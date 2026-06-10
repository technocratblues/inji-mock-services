import {
  ISSUER,
  authServerBaseUrl,
  hasExplicitVersion,
  issuerBaseUrl,
  resolveRequestVersion,
} from "./issuer-profile.js";

const BASE_CREDENTIAL_CONFIGURATIONS = {
  UniversityDegreeCredential: {
    format: "ldp_vc",
    scope: "degree.read",
    cryptographic_binding_methods_supported: ["jwk"],
    proof_types_supported: {
      jwt: {
        proof_signing_alg_values_supported: ["RS256"],
      },
    },
    credential_definition: {
      type: ["VerifiableCredential", "FarmerCredential"],
      "@context": ["https://www.w3.org/2018/credentials/v1"],
    },
    credential_metadata: {
      display: [
        { name: "Farmer Credential", locale: "en" ,logo: {
          uri: "https://inji.github.io/inji-config/logos/mosipid-logo.png",
          alt_text: "a square logo of a MOSIP"
        }},
        { name: "किसान क्रेडेंशियल", locale: "hi",logo: {
          uri: "https://inji.github.io/inji-config/logos/mosipid-logo.png",
          alt_text: "a square logo of a MOSIP"
        } },
      ],
      claims: [
        {
          path: ["credentialSubject", "fullName"],
          display: [
            { name: "Full Name", locale: "en" },
            { name: "पूरा नाम", locale: "hi" },
          ],
        },
        {
          path: ["credentialSubject", "mobileNumber"],
          display: [{ name: "Mobile Number", locale: "en" }],
        },
        {
          path: ["credentialSubject", "dateOfBirth"],
          display: [{ name: "Date of Birth", locale: "en" }],
        },
        {
          path: ["credentialSubject", "landArea"],
          display: [{ name: "Land Area (acres)", locale: "en" }],
        },
        {
          path: ["credentialSubject", "landOwnershipType"],
          display: [{ name: "Land Ownership", locale: "en" }],
        },
        {
          path: ["credentialSubject", "address", "village"],
          display: [{ name: "Village", locale: "en" }],
        },
        {
          path: ["credentialSubject", "farmProfile", "landRecord", "surveyNumber"],
          display: [{ name: "Survey Number", locale: "en" }],
        },
        {
          path: ["credentialSubject", "farmProfile", "landRecord", "registry", "office"],
          display: [{ name: "Registry Office", locale: "en" }],
        },
        {
          path: ["credentialSubject", "farmProfile", "irrigation", "source", "type"],
          display: [{ name: "Irrigation Source Type", locale: "en" }],
        },
        {
          path: ["credentialSubject", "cooperative", "membership", "membershipNumber"],
          display: [{ name: "Cooperative Membership Number", locale: "en" }],
        },
        {
          path: ["credentialSubject", "crops", null],
          display: [{ name: "Crops", locale: "en" }],
        },
        {
          path: ["credentialSubject", "plots", 0, "soilType"],
          display: [{ name: "Primary Plot Soil", locale: "en" }],
        },
      ],
    },
  },
  JwtVerifiableCredential: {
    format: "jwt_vc_json",
    scope: "jwt_vc_json.read",
    cryptographic_binding_methods_supported: ["did:jwk"],
    credential_signing_alg_values_supported: ["ES256"],
    proof_types_supported: {
      jwt: {
        proof_signing_alg_values_supported: ["ES256", "RS256"],
      },
    },
    credential_definition: {
      type: ["VerifiableCredential", "EmployeeCredential"],
    },
    credential_metadata: {
      display: [
        { name: "Employee Credential", locale: "en",logo: {
          uri: "https://inji.github.io/inji-config/logos/mosipid-logo.png",
          alt_text: "a square logo of a MOSIP"
        } },
        { name: "Kredensyal ng Empleyado", locale: "fil" ,logo: {
          uri: "https://inji.github.io/inji-config/logos/mosipid-logo.png",
          alt_text: "a square logo of a MOSIP"
        }},
        { name: "कर्मचारी क्रेडेंशियल", locale: "hi" ,logo: {
          uri: "https://inji.github.io/inji-config/logos/mosipid-logo.png",
          alt_text: "a square logo of a MOSIP"
        }},
        { name: "ಉದ್ಯೋಗಿ ರುಜುವಾತು", locale: "kn",logo: {
          uri: "https://inji.github.io/inji-config/logos/mosipid-logo.png",
          alt_text: "a square logo of a MOSIP"
        } },
        { name: "பணியாளர் நற்சான்றிதழ்", locale: "ta" ,logo: {
          uri: "https://inji.github.io/inji-config/logos/mosipid-logo.png",
          alt_text: "a square logo of a MOSIP"
        }},
        { name: "اعتماد الموظف", locale: "ar",logo: {
          uri: "https://inji.github.io/inji-config/logos/mosipid-logo.png",
          alt_text: "a square logo of a MOSIP"
        } },
      ],

      claims: [
        {
          path: ["credentialSubject", "employeeId"],
          display: [
            { name: "कर्मचारी पहचान", locale: "hi" },
            { name: "Employee ID", locale: "en" },
            { name: "ID ng Empleyado", locale: "fil" },
            { name: "ಉದ್ಯೋಗಿ ಗುರುತು", locale: "kn" },
            { name: "பணியாளர் அடையாளம்", locale: "ta" },
            { name: "معرف الموظف", locale: "ar" },
          ],
        },
        {
          path: ["credentialSubject", "name"],
          display: [
            { name: "पूरा नाम", locale: "hi" },
            { name: "Name", locale: "en" },
            { name: "Buong Pangalan", locale: "fil" },
            { name: "ಪೂರ್ಣ ಹೆಸರು", locale: "kn" },
            { name: "முழு பெயர்", locale: "ta" },
            { name: "الاسم الكامل", locale: "ar" },
          ],
        },
        {
          path: ["credentialSubject", "role"],
          display: [
            { name: "भूमिका", locale: "hi" },
            { name: "Role", locale: "en" },
            { name: "Tungkulin", locale: "fil" },
            { name: "ಪಾತ್ರ", locale: "kn" },
            { name: "பணிப்பொறுப்பு", locale: "ta" },
            { name: "الدور الوظيفي", locale: "ar" },
          ],
        },
        {
          path: ["credentialSubject", "address", "city"],
          display: [{ name: "City", locale: "en" }],
        },
        {
          path: ["credentialSubject", "nationalities", null],
          display: [{ name: "Nationalities", locale: "en" }],
        },
        {
          path: ["credentialSubject", "degrees", 0, "type"],
          display: [{ name: "Primary Degree", locale: "en" }],
        },
      ],
    },
  },
  SdJwtVerifiableCredential: {
    format: "vc+sd-jwt",
    scope: "sd_jwt_vc.read",
    cryptographic_binding_methods_supported: ["did:jwk"],
    credential_signing_alg_values_supported: ["ES256"],
    proof_types_supported: {
      jwt: {
        proof_signing_alg_values_supported: ["ES256", "RS256"],
      },
    },
    vct: "EmployeeCredential",
    credential_metadata: {
      display: [
        { name: "SD-JWT Employee Credential", locale: "en",logo: {
          uri: "https://inji.github.io/inji-config/logos/mosipid-logo.png",
          alt_text: "a square logo of a MOSIP"
        } },
      ],
      claims: [
        {
          path: ["employeeId"],
          display: [{ name: "Employee ID", locale: "en" }],
        },
        {
          path: ["name"],
          display: [{ name: "Name", locale: "en" }],
        },
      ],
    },
  },
  MdocVerifiableCredential: {
    format: "mso_mdoc",
    scope: "mdoc.read",
    cryptographic_binding_methods_supported: ["jwk"],
    credential_signing_alg_values_supported: ["ES256"],
    doctype: "org.iso.18013.5.1.mDL",
    credential_metadata: {
      display: [
        { name: "Mobile Driving License", locale: "en" ,logo: {
          uri: "https://inji.github.io/inji-config/logos/mosipid-logo.png",
          alt_text: "a square logo of a MOSIP"
        }},
      ],

      claims: [
        {
          path: ["org.iso.18013.5.1", "given_name"],
          display: [{ name: "Given Name", locale: "en" }],
        },
        {
          path: ["org.iso.18013.5.1", "family_name"],
          display: [{ name: "Family Name", locale: "en" }],
        },
      ],
    },
  },
};

function toDraft13Configuration(configuration) {
  const { credential_metadata, ...rest } = configuration;

  return {
    ...rest,
    display: credential_metadata?.display || [],
    claims: credential_metadata?.claims || [],
  };
}

function buildCredentialConfigurations(version) {

  const isV1 = version === "v1";
  
  return Object.fromEntries(
    Object.entries(BASE_CREDENTIAL_CONFIGURATIONS).map(([id, configuration]) => [
      id,
      isV1 ? configuration : toDraft13Configuration(configuration),
    ]),
  );
}

export { ISSUER };

export default function issuerMetadata(req, res) {
  const version = resolveRequestVersion(req);
  const explicitVersion = hasExplicitVersion(req);
  const flow = req.params?.flow === "pdi" ? "pdi" : null;
  const credentialIssuer = issuerBaseUrl(version, explicitVersion, flow);
  const authorizationServer = authServerBaseUrl(version, explicitVersion, flow);
  const isV1 = version === "v1";

  const response = {
    credential_issuer: credentialIssuer,
    authorization_servers: [authorizationServer],
    credential_endpoint: `${credentialIssuer}/credential`,
    credential_configurations_supported: buildCredentialConfigurations(version),
    grants: {
      authorization_code: {
        issuer_state: true,
      },
      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {},
    },
  };

  if (isV1) {
    response.nonce_endpoint = `${credentialIssuer}/nonce`;
  }

  res.json(response);
}
