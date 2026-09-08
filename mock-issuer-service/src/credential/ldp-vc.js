import jsonld from 'jsonld';
import jsigs from 'jsonld-signatures';
import { Ed25519Signature2018 } from '@digitalbazaar/ed25519-signature-2018';
import { Ed25519VerificationKey2018 } from '@digitalbazaar/ed25519-verification-key-2018';
import crypto from 'node:crypto';

const { AssertionProofPurpose } = jsigs.purposes;
const { LinkedDataSignature } = jsigs.suites;

// Configurable via env: "rsa" or "ed25519" (default)
const LDP_SIGNATURE_SUITE = (process.env.LDP_SIGNATURE_SUITE || 'ed25519').toLowerCase();

// Cached RSA key pair (persisted for the lifetime of the process so that
// the /.well-known/did.json endpoint can serve the matching public key)
let _rsaKeyCache = null;

let _ed25519KeyCache = null;

async function getEd25519Key(issuerDid) {
  if (_ed25519KeyCache &&
      _ed25519KeyCache.controller === issuerDid) {
    return _ed25519KeyCache;
  }

  _ed25519KeyCache = await Ed25519VerificationKey2018.generate({
    id: `${issuerDid}#key-0`,
    controller: issuerDid
  });

  return _ed25519KeyCache;
}

function getRsaKey(issuerDid) {
  if (_rsaKeyCache && _rsaKeyCache.controller === issuerDid) {
    return _rsaKeyCache;
  }

  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
  });

  const publicKeyObj = crypto.createPublicKey(publicKey);
  const publicKeyJwk = publicKeyObj.export({ format: 'jwk' });

 _rsaKeyCache = {
  id: `${issuerDid}#key-0`,
  controller: issuerDid,
  privateKeyPem: privateKey,
  publicKeyPem: publicKey,
  publicKeyJwk,
};
  return _rsaKeyCache;
}

/**
 * Returns the DID Document for the current RSA key.
 * Used by the /.well-known/did.json Express route.
 */
export async function getDidDocument(issuerDid) {

  if (LDP_SIGNATURE_SUITE === "ed25519") {

    const key = await getEd25519Key(issuerDid);

    return {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/v2"
      ],
      id: issuerDid,
      verificationMethod: [{
        id: key.id,
        type: "Ed25519VerificationKey2018",
        controller: issuerDid,
        publicKeyBase58: key.publicKeyBase58
      }],
      assertionMethod: [key.id],
      authentication: [key.id]
    };
  }

  // Existing RSA code
  const key = getRsaKey(issuerDid);

  return {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/v2"
    ],
    id: issuerDid,
    verificationMethod: [{
      id: key.id,
      type: "RsaVerificationKey2018",
      controller: issuerDid,
      publicKeyJwk: key.publicKeyJwk,
      publicKeyPem: key.publicKeyPem,
    }],
    assertionMethod: [key.id],
    authentication: [key.id],
  };
}

/**
 * RsaSignature2018 implementation using Node crypto.
 * Produces a detached JWS (RS256) per the W3C Linked Data Proofs spec.
 */
class RsaSignature2018 extends LinkedDataSignature {
  constructor({ key, date } = {}) {
    const signer = {
  id: key.id,
  sign: async ({ data }) => {
    return crypto.sign('sha256', data, {
      key: key.privateKeyPem,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
    });
  }
};
    super({
      type: 'RsaSignature2018',
      algorithm: 'PS256',
      date,
      signer,
      // credentials/v1 already defines RsaSignature2018; point contextUrl there
      // so ensureSuiteContext() sees it's already included and won't inject another
      contextUrl: 'https://www.w3.org/2018/credentials/v1',
    });
    this.rsaKey = key;
  }

  async sign({ verifyData, proof }) {
  const header = Buffer.from(
    JSON.stringify({ alg: 'PS256' })
  ).toString('base64url');
  const signingInput = Buffer.concat([
    Buffer.from(header + '.', 'ascii'),
    verifyData
  ]);
  const signature = crypto.sign(
    'sha256',
    signingInput,
    {
      key: this.rsaKey.privateKeyPem,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
    }
  );
  proof.jws = `${header}..${signature.toString('base64url')}`;
  return proof;
}

  async getVerificationMethod() {
    return {
      id: this.rsaKey.id,
      type: 'RsaVerificationKey2018',
      controller: this.rsaKey.controller,
      publicKeyJwk: this.rsaKey.publicKeyJwk,
    };
  }

async canonizeProof(proof, {document, documentLoader}) {
  proof = {
    '@context': 'https://w3id.org/security/v2',
    ...proof
  };

  delete proof.jws;
  delete proof.signatureValue;
  delete proof.proofValue;

  return this.canonize(proof, {documentLoader, skipExpansion: false});
}

  async canonize(input, { documentLoader, skipExpansion }) {
    const jsonld = (await import('jsonld')).default;
    const rdfCanonize = (await import('rdf-canonize')).default;
    const opts = {
      algorithm: 'RDFC-1.0',
      base: null,
      format: 'application/n-quads',
      documentLoader,
      safe: false,
      skipExpansion,
      produceGeneralizedRdf: false,
      rdfDirection: 'i18n-datatype',
    };
    delete opts.format;
    const dataset = await jsonld.toRDF(input, opts);
   const canonized = await rdfCanonize.canonize(dataset, {
  algorithm: 'RDFC-1.0',
  format: 'application/n-quads',
});
return canonized;
  }

  async assertVerificationMethod({ verificationMethod }) {
    if (!verificationMethod || !verificationMethod.id) {
      throw new Error('Missing verificationMethod id');
    }
  }
}

// Predefined contexts to avoid network calls
const CONTEXTS = {
  "https://www.w3.org/2018/credentials/v1": {
    "@context": {
      "@version": 1.1,
      "@protected": true,
      "id": "@id",
      "type": "@type",
      "VerifiableCredential": {
        "@id": "https://www.w3.org/2018/credentials#VerifiableCredential",
        "@context": {
          "@version": 1.1,
          "@protected": true,
          "id": "@id",
          "type": "@type",
          "cred": "https://www.w3.org/2018/credentials#",
          "sec": "https://w3id.org/security#",
          "issuer": {
            "@id": "cred:issuer",
            "@type": "@id"
          },
          "issuanceDate": {
            "@id": "cred:issuanceDate",
            "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
          },
          "expirationDate": {
            "@id": "cred:expirationDate",
            "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
          },
          "credentialStatus": {
            "@id": "cred:credentialStatus",
            "@type": "@id"
          },
          "credentialSubject": {
            "@id": "cred:credentialSubject"
          },
          "proof": {
            "@id": "sec:proof",
            "@type": "@id",
            "@container": "@set"
          }
        }
      },
      "VerifiablePresentation": {
        "@id": "https://www.w3.org/2018/credentials#VerifiablePresentation",
        "@context": {
          "@version": 1.1,
          "@protected": true,
          "id": "@id",
          "type": "@type",
          "cred": "https://www.w3.org/2018/credentials#",
          "sec": "https://w3id.org/security#",
          "verifiableCredential": {
            "@id": "cred:verifiableCredential",
            "@type": "@id",
            "@container": "@set"
          },
          "proof": {
            "@id": "sec:proof",
            "@type": "@id",
            "@container": "@set"
          }
        }
      },
      "EcdsaSecp256k1Signature2019": "https://w3id.org/security#EcdsaSecp256k1Signature2019",
      "EcdsaSecp256r1Signature2019": "https://w3id.org/security#EcdsaSecp256r1Signature2019",
      "Ed25519Signature2018": "https://w3id.org/security#Ed25519Signature2018",
      "RsaSignature2018": "https://w3id.org/security#RsaSignature2018",
      "proof": {
        "@id": "https://w3id.org/security#proof",
        "@type": "@id",
        "@container": "@set"
      }
    }
  },
  "https://w3id.org/security/v2": {
    "@context": {
      "id": "@id",
      "type": "@type",
      "sec": "https://w3id.org/security#",
      "proof": "sec:proof",
      "verificationMethod": { "@id": "sec:verificationMethod", "@type": "@id" },
      "created": { "@id": "http://purl.org/dc/terms/created", "@type": "http://www.w3.org/2001/XMLSchema#dateTime" },
      "proofPurpose": { "@id": "sec:proofPurpose", "@type": "@id" },
      "jws": "sec:jws"
    }
  },
  "https://w3id.org/security/v1": {
    "@context": {
      "id": "@id",
      "type": "@type",
      "sec": "https://w3id.org/security#",
      "proof": "sec:proof",
      "jws": "sec:jws",
      "created": { "@id": "http://purl.org/dc/terms/created", "@type": "http://www.w3.org/2001/XMLSchema#dateTime" },
      "verificationMethod": { "@id": "sec:verificationMethod", "@type": "@id" }
    }
  },
  "https://piyush7034.github.io/my-files/farmer.json": {
    "@context": {
      "@version": 1.1,
      "type": "@type",
      "schema": "https://schema.org/",
      "FarmerCredential": {
        "@id": "https://piyush7034.github.io/my-files/farmer.json#FarmerCredential"
      },
      "fullName": "schema:name",
      "mobileNumber": "schema:telephone",
      "dateOfBirth": "schema:birthDate",
      "gender": "schema:gender",
      "state": "schema:addressRegion",
      "district": "schema:addressLocality",
      "villageOrTown": "schema:addressLocality",
      "postalCode": "schema:postalCode",
      "landArea": "schema:Number",
      "landOwnershipType": "schema:Text",
      "primaryCropType": "schema:Text",
      "secondaryCropType": "schema:Text",
      "face": "schema:Text",
      "farmerID": "schema:Text"
    }
  }
};

export const documentLoader = async (url) => {
  const context = CONTEXTS[url];

  if (context) {
    return {
      contextUrl: null,
      documentUrl: url,
      document: context,
    };
  }

  throw new Error(`Unknown context requested: ${url}`);
};

async function signWithRsa(credential, issuerDid) {
  const rsaKey = getRsaKey(issuerDid);

  const suite = new RsaSignature2018({
    key: rsaKey,
    date: new Date().toISOString(),
  });

  const signedVc = await jsigs.sign(credential, {
    suite,
    purpose: new AssertionProofPurpose(),
    documentLoader,
  });

  return signedVc;
}

async function signWithEd25519(credential, issuerDid) {
 const key = await getEd25519Key(issuerDid);

  class FixedEd25519Signature2018 extends Ed25519Signature2018 {
    async canonizeProof(proof, { document, documentLoader }) {
      proof = {
        '@context': 'https://w3id.org/security/v2',
        ...proof,
      };
      delete proof.jws;
      delete proof.signatureValue;
      delete proof.proofValue;
      return this.canonize(proof, { documentLoader, skipExpansion: false });
    }
  }

  const suite = new FixedEd25519Signature2018({   
    key,
    date: new Date().toISOString()
  });

  const signedVc = await jsigs.sign(credential, {
    suite,
    purpose: new AssertionProofPurpose(),
    documentLoader
  });

  return signedVc;
}
export async function signLdpVc(credential, issuerDid) {
  if (LDP_SIGNATURE_SUITE === "rsa") {
    return signWithRsa(credential, issuerDid);
  }

  return signWithEd25519(credential, issuerDid);
}