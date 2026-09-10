export const STATIC_LDP_VC = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://piyush7034.github.io/my-files/farmer.json",
  ],
  issuer: "did:web:vharsh.github.io:DID:local",
  type: ["VerifiableCredential", "FarmerCredential"],
  issuanceDate: "2025-01-02T05:16:46.176Z",
  expirationDate: "2027-01-02T05:16:46.176Z",
  credentialSubject: {
    fullName: "Mary Smith",
    mobileNumber: "8765432109",
    dateOfBirth: "1975-08-22",
    landArea: "25.75",
    landOwnershipType: "Leased",
    primaryCropType: "Rice",
    secondaryCropType: "Pulses",
  },
  proof: {
    type: "Ed25519Signature2018",
    created: "2025-01-01T23:46:46Z",
    proofPurpose: "assertionMethod",
    verificationMethod: "did:web:vharsh.github.io:DID:local#key-0",
    jws: "eyJ4NXQjUzI1NiI6IkhkakdicHlseVY0ZGZPZS01dDRhWGJOc3F2d1JDaExOeUxWczl2MEhqSjQiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJraWQiOiIxSTZ1bVNrRDRNeWxXUmMtYWJCejIwY3hMcUVGTUp3aG9KdmhNM1ZGZ21jIiwiYWxnIjoiRWREU0EifQ..VAqXjgwvMZ-3TAUR6kW0snxqGdlycyP3cQCzdsl61CFulGlOrCpCV_KiqMrEsQ3-23Cmn-pdtnF8m4V-qwkKAg",
  },
};

export const STATIC_JWT_VC = {
  "iss": "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2Iiwia2lkIjoiMSIsIngiOiI0eE9mS3pXNl96S018M04xOVM1eE1hVldreDVSR3A1YURSVmJXcHBiRzF1VG5reFYiLCJ5IjoiaVpXVk5qWmxWdlZWVmJlRWRxV0hWemVIaFNVVkpYVzFsd01XMXdjM0J2YlZSIn0",
  "jti": "urn:uuid:3c67f42e-dd3c-4d9b-898a-debff416ccca",
  "iat": 1767225600,
  "nbf": 1767225600,
  "exp": 1893456000,
  "vc": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1"
    ],
    "type": ["VerifiableCredential", "EmployeeCredential"],
    "credentialSubject": {
      "employeeId": "E12345",
      "name": "Anup Kumar",
      "role": "Software Engineer",
      "address": {
        "city": "Bengaluru",
        "country": "India"
      },
      "nationalities": ["Indian", "Singaporean"],
      "degrees": [
        { "type": "B.Tech", "university": "IIT" },
        { "type": "M.S.", "university": "NUS" }
      ]
    }
  }
};

export const STATIC_SD_JWT_VC = {
  vct: "EmployeeCredential",
  employeeId: "E12345",
  name: "Simon Kelleher",
  role: "Software Engineer",
  department: "R&D",
  location: "Bangalore",
  address: {
    city: "Bengaluru",
    country: {
      name: "India",
      postalCode: "560001"
    }
  },
  degrees: [
    { type: "B.Tech", university: "IIT" },
    { type: "M.S.", university: "NUS" }
  ]
};

export const STATIC_MDL_MDOC = {
  "org.iso.18013.5.1": {
    "given_name": "Anup",
    "family_name": "Kumar",
    "birth_date": "1990-01-01",
    "issue_date": "2023-01-01",
    "expiry_date": "2033-01-01",
    "issuing_country": "IN",
    "issuing_authority": "Ministry of Transport",
    "document_number": "ABC123456"
  }
};

export const STATIC_MDL_MDOC_SAMPLE_B64URL = "omdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiamlzc3VlckF1dGiEQ6EBJqEYIVkB2TCCAdUwggF7oAMCAQICFBRDWWSBLltTWt65yytaZ01baoM9MAoGCCqGSM49BAMCMFkxCzAJBgNVBAYTAk1LMQ4wDAYDVQQIDAVNSy1LQTENMAsGA1UEBwwETW9jazENMAsGA1UECgwETW9jazENMAsGA1UECwwETU9jazENMAsGA1UEAwwETW9jazAeFw0yNDEwMjEwNzU2MTBaFw0yNTEwMjEwNzU2MTBaMFkxCzAJBgNVBAYTAk1LMQ4wDAYDVQQIDAVNSy1LQTENMAsGA1UEBwwETW9jazENMAsGA1UECgwETW9jazENMAsGA1UECwwETU9jazENMAsGA1UEAwwETW9jazBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABA8PMic1jzZYunhb2Ymq3eH2qEudb5rBnGMk1RAmFuLbPYBgFhDjdhK7j3ciE16-XfCFHnVEX8cANHw1_XjU2nejITAfMB0GA1UdDgQWBBQmaVJHKU-6Y7m6g6qolUJ3p94yhjAKBggqhkjOPQQDAgNIADBFAiEAwXQgNSUrhHIlPE1N24u5UCRwBTqYKKpJqBlC0niZRHgCIFryTL85LV-hab5RL4YiDpDeNOL6_YyiS-STfjrv-OL4WQJR2BhZAkymZ3ZlcnNpb25jMS4wb2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2Z2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMbHZhbHVlRGlnZXN0c6Fxb3JnLmlzby4xODAxMy41LjGoAlggahyUDZzWwyVz1oYQSOSTOl3XfzVAAVi-ILLpwP3DMtUGWCBJiBVoqzuOj8ZRrOsV7DNFe0QBWplIKWMU3aILs8y6lwNYILzO8fswbC_wn7rQYO8eq91XotAltVllVzYTwyYHHWYIAVggHp8Y6cV73O670tvfMiyCZoxGczcYyfOh43Q8ahKpxxcEWCC75BhZBjDE1I4S5NLZAsaUmBERMZM9rMgZPkAzl45VeABYIIlDF4uT1D3MLGPsLL-kVBP0SHyxAYcAVf9SLYLUJUUgB1ggFuI0cmV1WwSJGv5VxI5a7Dsm6fIqr2MeIDBmYjIlZ0oFWCA88kOo8KNGtCpl2XH5CXMcgoE6D_fag9xjmPoLUcpgpG1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmkAQIgASFYIOMdpjABg7S1sJBCgdC4D6V237Jk_oGhMl_LInX0CFnGIlggPdyNKVXrSZb4CYQmoK6lX7Zux0DIBcnhJ9-_a7ZlYtdsdmFsaWRpdHlJbmZvo2ZzaWduZWTAdDIwMjQtMTAtMjFUMDg6MTE6MTNaaXZhbGlkRnJvbcB0MjAyNC0xMC0yMVQwODoxMToxM1pqdmFsaWRVbnRpbMB0MjAyNS0xMC0yMVQwODoxMToxM1pYQBZJtQ6yPA--sITjOK29mGLGKeG2DEx3qDHQEw99esCHwUnPJtobUfLGHhfmM0nawMZai21LXq5ZEdInOkEDSNRqbmFtZVNwYWNlc6Fxb3JnLmlzby4xODAxMy41LjGI2BhYaqRoZGlnZXN0SUQCZnJhbmRvbVBthSy1vmphqpoMYRe9Z0PncWVsZW1lbnRJZGVudGlmaWVyamlzc3VlX2RhdGVsZWxlbWVudFZhbHVleBsyMDI0LTEwLTIxVDA4OjExOjEzLjQ5NTQ3OFrYGFhrpGhkaWdlc3RJRAZmcmFuZG9tUNyXhXOZjmheiFyzYfhsl0ZxZWxlbWVudElkZW50aWZpZXJrZXhwaXJ5X2RhdGVsZWxlbWVudFZhbHVleBsyMDI1LTEwLTIxVDA4OjExOjEzLjQ5NTQ3OFrYGFjBpGhkaWdlc3RJRANmcmFuZG9tUCC-v7ARALJ2VFcYww9AbMhxZWxlbWVudElkZW50aWZpZXJyZHJpdmluZ19wcml2aWxlZ2VzbGVsZW1lbnRWYWx1ZXhqe2lzc3VlX2RhdGU9MjAyNC0xMC0yMVQwODoxMToxMy40OTU0NzhaLCB2ZWhpY2xlX2NhdGVnb3J5X2NvZGU9QSwgZXhwaXJ5X2RhdGU9MjAyNS0xMC0yMVQwODoxMToxMy40OTU0NzhafdgYWFekaGRpZ2VzdElEAWZyYW5kb21Q46GI__EQWetvvOYmVd-9b3FlbGVtZW50SWRlbnRpZmllcm9kb2N1bWVudF9udW1iZXJsZWxlbWVudFZhbHVlZDEyMzPYGFhVpGhkaWdlc3RJRARmcmFuZG9tUIO4lnDW2fm_Utg97twL9mJxZWxlbWVudElkZW50aWZpZXJvaXNzdWluZ19jb3VudHJ5bGVsZW1lbnRWYWx1ZWJNS9gYWFikaGRpZ2VzdElEAGZyYW5kb21QBYNczBataC2MR4om9FAnmHFlbGVtZW50SWRlbnRpZmllcmpiaXJ0aF9kYXRlbGVsZW1lbnRWYWx1ZWoxOTk0LTExLTA22BhYVKRoZGlnZXN0SUQHZnJhbmRvbVBJWZtW3VOzNRpXK0Dyf3LTcWVsZW1lbnRJZGVudGlmaWVyamdpdmVuX25hbWVsZWxlbWVudFZhbHVlZkpvc2VwaNgYWFWkaGRpZ2VzdElEBWZyYW5kb21QfzR7XZl5Fiz6lZ0oMqRhlnFlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZWxlbGVtZW50VmFsdWVmQWdhdGhh";
