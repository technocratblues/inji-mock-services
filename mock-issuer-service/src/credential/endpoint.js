import {
  STATIC_LDP_VC,
  STATIC_JWT_VC,
  STATIC_SD_JWT_VC,
  STATIC_MDL_MDOC,
  STATIC_MDL_MDOC_SAMPLE_B64URL,
} from "./static-vc.js";
import { SignJWT, generateKeyPair, exportJWK, decodeProtectedHeader, decodeJwt } from 'jose';
import { randomUUID, createHash } from 'node:crypto';
import { ISSUER } from "../issuer-metadata.js";
import { accessTokenStore, stageTestErrorStore } from "../as/authz-store.js";
import { verifyDPoPProof, buildHtu, DPoPError } from "../as/dpop.js";
import { hasExplicitVersion, issuerBaseUrl, resolveRequestVersion } from "../issuer-profile.js";
import { createSdJwt } from "./sd-jwt.js";
import { createMdoc } from "./mdoc.js";
import { signLdpVc } from "./ldp-vc.js";
import { envTestError, sendTestError } from "../test-errors.js";

const SUPPORTED_FORMATS = ["ldp_vc", "jwt_vc_json", "vc+sd-jwt","dc+sd-jwt", "mso_mdoc"];

// Minimal config-id → format map for the v1 flow where the client sends
// credential_configuration_id instead of format.
const CONFIG_TO_FORMAT = {
  FarmerCredential: "ldp_vc",
  JwtVerifiableCredential: "jwt_vc_json",
  SdJwtVerifiableCredential: "vc+sd-jwt",
  MdocVerifiableCredential: "mso_mdoc",
};

export default async function credentialEndpoint(req, res) {
  const body = req.body || {};

  // Accept both Bearer and DPoP tokens
  const authHeader = req.headers.authorization || "";
  const bearerMatch = authHeader.match(/^Bearer\s+(.+)$/i);
  const dpopMatch   = authHeader.match(/^DPoP\s+(.+)$/i);
  const accessToken = (dpopMatch?.[1] || bearerMatch?.[1]) ?? null;
  const isDpopToken = Boolean(dpopMatch);

  const tokenEntry = accessToken ? accessTokenStore.get(accessToken) : null;

  // ── DPoP binding check ────────────────────────────────────────────────────
  if (isDpopToken) {
    const dpopProof = req.headers["dpop"];
    if (!dpopProof) {
      return res.status(401).json({
        error: "invalid_token",
        error_description: "DPoP proof required for DPoP-bound token",
      });
    }
    if (!tokenEntry) {
      return res.status(401).json({ error: "invalid_token", error_description: "Access token not found" });
    }
    if (tokenEntry.tokenType !== "DPoP") {
      return res.status(401).json({
        error: "invalid_token",
        error_description: "Token type mismatch: token was issued as Bearer",
      });
    }
    try {
      const htu = buildHtu(req);
      console.log("[DPoP Credential Proof]");
      console.log("  header :", JSON.stringify(decodeProtectedHeader(dpopProof)));
      console.log("  payload:", JSON.stringify(decodeJwt(dpopProof)));
      await verifyDPoPProof(dpopProof, "POST", htu, { accessToken });
    } catch (err) {
      console.warn("Credential endpoint DPoP validation failed:", err.message);
      return res.status(401)
        .set("WWW-Authenticate", `DPoP error="${err.code}", error_description="${err.description}"`)
        .json({ error: err.code, error_description: err.description });
    }
    console.log("DPoP-bound credential request validated ✓");
  }
  // ── End DPoP binding check ─────────────────────────────────────────────────
  else if (accessToken) {
    // A DPoP-bound token must be presented with the DPoP scheme + proof. Accepting it as a
    // plain Bearer token would defeat sender-constraining (RFC 9449 §7.1), so reject it.
    if (tokenEntry?.tokenType === "DPoP") {
      return res.status(401)
        .set("WWW-Authenticate", 'DPoP error="invalid_token", error_description="DPoP-bound access token presented as Bearer"')
        .json({
          error: "invalid_token",
          error_description: "DPoP-bound access token must be presented with a DPoP proof",
        });
    }
    console.log(
      `Bearer credential request (no DPoP) — token_type on record: ${tokenEntry?.tokenType ?? "unknown"}`,
    );
  }

  const testError =
    envTestError("credential") || tokenEntry?.testError || stageTestErrorStore.get("credential") || null;
  if (testError) stageTestErrorStore.delete("credential");
  if (sendTestError(res, testError)) return;

  const explicitVersion = hasExplicitVersion(req);
  const version = resolveRequestVersion(req);
  const isV1 = explicitVersion
    ? version === "v1"
    : Boolean(body.credential_configuration_id || body.proofs);
  const issuerUrl = explicitVersion ? issuerBaseUrl(version) : ISSUER;

  let format;
  let proofJwt;

  if (isV1) {
    const configId = body.credential_configuration_id;
    format = CONFIG_TO_FORMAT[configId];
    if (!format) {
      return res.status(400).json({
        error: "unsupported_credential_type",
        error_description: `Unknown credential_configuration_id: ${configId}`,
      });
    }

    const jwtProofs = body.proofs && body.proofs.jwt;
    const mdocProofs = body.proofs && body.proofs.mso_mdoc;
    
    if (format === "mso_mdoc") {
        if (!mdocProofs || !Array.isArray(mdocProofs) || mdocProofs.length === 0) {
          // Fallback to jwt if mdoc proofs missing but jwt present (some wallets might still use jwt proof for mdoc)
          if (!jwtProofs || !Array.isArray(jwtProofs) || jwtProofs.length === 0) {
            return res.status(400).json({
                error: "invalid_proof",
                error_description: "proofs.mso_mdoc missing or empty",
            });
          }
          proofJwt = jwtProofs[0];
        } else {
            proofJwt = mdocProofs[0];
        }
    } else {
        if (!jwtProofs || !Array.isArray(jwtProofs) || jwtProofs.length === 0) {
            return res.status(400).json({
                error: "invalid_proof",
                error_description: "proofs.jwt missing or empty",
            });
        }
        proofJwt = jwtProofs[0];
    }
  } else {
    format = body.format;
    if (!SUPPORTED_FORMATS.includes(format)) {
      return res.status(400).json({ error: "unsupported_credential_format" });
    }
    if (!body.proof || !body.proof.jwt) {
      return res.status(400).json({
        error: "invalid_proof",
        error_description: "proof.jwt missing",
      });
    }
    proofJwt = body.proof.jwt;
  }

  // Get the holder key from the proof JWT protected header "kid".
  const holderKey = decodeProtectedHeader(proofJwt)?.kid;

  let credential;

  try {
    if (format === "ldp_vc") {
        let host;
        try {
            host = new URL(issuerUrl).host;
        } catch (e) {
            host = "mock-issuer.local";
        }
        const issuerDid = `did:web:${host}`;
        
        const { proof, ...unsignedVc } = STATIC_LDP_VC;
        unsignedVc.issuer = issuerDid;
        unsignedVc.issuanceDate = new Date().toISOString();

        credential = await signLdpVc(unsignedVc, issuerDid);
    } else {
        const { privateKey, publicKey } = await generateKeyPair('ES256');
        const privateKeyJwk = await exportJWK(privateKey);
        const publicKeyJwk = await exportJWK(publicKey);
        privateKeyJwk.kid = randomUUID();
        publicKeyJwk.kid = privateKeyJwk.kid;
        const didJwk = `did:jwk:${Buffer.from(JSON.stringify(publicKeyJwk)).toString('base64url')}`;

        if (format === "jwt_vc_json") {
          const { iat, nbf, exp, ...cleanStaticVc } = STATIC_JWT_VC;

          const vcPayload = {
            ...cleanStaticVc,
            iss: didJwk,
            sub: didJwk,
            jti: `urn:uuid:${randomUUID()}`,
            vc: {
              ...STATIC_JWT_VC.vc,
              credentialSubject: {
                ...STATIC_JWT_VC.vc.credentialSubject,
                id: didJwk,
              },
            },
          };

          credential = await new SignJWT(vcPayload)
            .setProtectedHeader({ alg: 'ES256', typ: 'JWT', kid: didJwk })
            .setIssuedAt()
            .setNotBefore('0s')
            .setExpirationTime('1y')
            .sign(privateKey);
        } else if (format === "vc+sd-jwt" || format === "dc+sd-jwt") {
          let holderCnfInfo = {};
          if (holderKey?.startsWith("did:jwk:")) {
            const encodedJwk = holderKey.slice("did:jwk:".length);
            try {
              const jwkString = Buffer.from(encodedJwk, "base64url").toString("utf8");
              const parsedJwk = JSON.parse(jwkString);
              holderCnfInfo = {
                "cnf": {
                  "jwk": parsedJwk
                }
              }
            } catch (error) {
              console.error("data in did:jwk not right ",error)
              holderCnfInfo = {
                "cnf": {
                  "kid": holderKey
                }
              }
            }
          }
            credential = await createSdJwt({...STATIC_SD_JWT_VC, ...holderCnfInfo}, privateKey, didJwk, didJwk);
        } else if (format === "mso_mdoc") {
            credential = STATIC_MDL_MDOC_SAMPLE_B64URL;
        }
    }
  } catch (error) {
  return res.status(500).json({ error: "signing_error" });
}
  if (isV1) {
    return res.json({
      credentials: [ { credential } ],
      credential_issuer: issuerUrl,
    });
  }

  return res.json({
    format,
    credential,
    c_nonce: "mock_nonce_123",
    c_nonce_expires_in: 86400,
  });
}
