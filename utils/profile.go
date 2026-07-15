package utils

import (
	"strings"

	"github.com/ProtonMail/gopenpgp/v3/constants"
	"github.com/ProtonMail/gopenpgp/v3/profile"
)

const DefaultProfileName string = "default"

var EncryptionProfiles = createEncryptionProfiles()
var KeyGenerationProfiles = createKeyGenerationProfiles()

type SopProfile struct {
	Names         []string
	Description   string
	PgpProfile    *profile.Custom
	SecurityLevel int8 // Only applies to key generation.
}

func SelectKeyGenerationProfile(name string) (selectedProfile *SopProfile) {
	lowercase := strings.ToLower(name)
	for _, keyGenProfile := range KeyGenerationProfiles {
		for _, name := range keyGenProfile.Names {
			if name == lowercase {
				selectedProfile = keyGenProfile
			}
		}
	}
	return
}

func SelectEncryptionProfile(name string) (selectedProfile *SopProfile) {
	lowercase := strings.ToLower(name)
	for _, encProfile := range EncryptionProfiles {
		for _, name := range encProfile.Names {
			if name == lowercase {
				selectedProfile = encProfile
			}
		}
	}
	return
}

func createEncryptionProfiles() []*SopProfile {
	return []*SopProfile{
		{
			Names:         []string{"default", "compatibility", "rfc4880"},
			Description:   "Use CFB encryption (SEIPDv1)",
			PgpProfile:    profile.Default(),
			SecurityLevel: constants.StandardSecurity,
		},
		{
			Names:         []string{"performance", "security", "rfc9580"},
			Description:   "Use AEAD encryption (SEIPDv2)",
			PgpProfile:    profile.RFC9580(),
			SecurityLevel: constants.StandardSecurity,
		},
	}
}

func createKeyGenerationProfiles() []*SopProfile {
	return []*SopProfile{
		{
			Names:         []string{"default"},
			Description:   "Generate v4 keys using Curve25519",
			PgpProfile:    profile.Default(),
			SecurityLevel: constants.StandardSecurity,
		},
		{
			Names:         []string{"compatibility", "rfc4880"},
			Description:   "Generate v4 keys using 3072-bit RSA",
			PgpProfile:    profile.RFC4880(),
			SecurityLevel: constants.StandardSecurity,
		},
		{
			Names:         []string{"performance", "rfc9580"},
			Description:   "Generate v6 keys using Ed25519/X25519",
			PgpProfile:    profile.RFC9580(),
			SecurityLevel: constants.StandardSecurity,
		},
		{
			Names:         []string{"security"},
			Description:   "Generate v6 keys using Ed448/X448",
			PgpProfile:    profile.RFC9580(),
			SecurityLevel: constants.HighSecurity,
		},
		{
			Names:         []string{"rfc9980"},
			Description:   "Generate v6 keys using ML-DSA-65+Ed25519/ML-KEM-768+X25519",
			PgpProfile:    profile.PQC(),
			SecurityLevel: constants.StandardSecurity,
		},
		{
			Names:         []string{"rfc9980-high-security"},
			Description:   "Generate v6 keys using ML-DSA-87+Ed448/ML-KEM-1024+X448",
			PgpProfile:    profile.PQC(),
			SecurityLevel: constants.HighSecurity,
		},
		{
			Names:         []string{"draft-ietf-openpgp-persistent-symmetric-keys-03"},
			Description:   "Generate a persistent symmetric key using AEAD",
			PgpProfile:    profile.Symmetric(),
			SecurityLevel: constants.StandardSecurity,
		},
	}
}
