package utils

import (
	"strings"

	"github.com/ProtonMail/gopenpgp/v3/profile"
)

const DefaultProfileName string = "default"

var EncryptionProfiles = createEncryptionProfiles()
var KeyGenerationProfiles = createKeyGenerationProfiles()

type SopProfile struct {
	Name        string
	Description string
	pgpProfile  *profile.Custom
}

func SelectKeyGenerationProfile(name string) *profile.Custom {
	lowercase := strings.ToLower(name)
	selectedProfile := KeyGenerationProfiles[0].pgpProfile
	for _, keyGenProfile := range KeyGenerationProfiles {
		if keyGenProfile.Name == lowercase {
			selectedProfile = keyGenProfile.pgpProfile
		}
	}
	return selectedProfile
}

func SelectEncryptionProfile(name string) *profile.Custom {
	lowercase := strings.ToLower(name)
	selectedProfile := EncryptionProfiles[0].pgpProfile
	for _, encProfile := range EncryptionProfiles {
		if encProfile.Name == lowercase {
			selectedProfile = encProfile.pgpProfile
		}
	}
	return selectedProfile
}

func createEncryptionProfiles() []*SopProfile {
	return []*SopProfile{
		{
			Name:        "rfc4880",
			Description: "(default) CFB (SEIPDv1) only",
			pgpProfile:  defaultProfile(),
		},
		{
			Name:        "rfc9580",
			Description: "AEAD (SEIPDv2) enabled",
			pgpProfile:  rfc9580(),
		},
	}
}

func createKeyGenerationProfiles() []*SopProfile {
	return []*SopProfile{
		{
			Name:        "default",
			Description: "Generates EdDSA/ECDH v4 keys with Curve25519",
			pgpProfile:  defaultProfile(),
		},
		{
			Name:        "rfc4880",
			Description: "Generates 3072-bit RSA keys",
			pgpProfile:  rfc4880(),
		},
		{
			Name:        "rfc9580",
			Description: "Generates Ed25519/X25519 v6 keys with Curve25519",
			pgpProfile:  rfc9580(),
		},
		{
			Name:        "pqc",
			Description: "ML-KEM and ML-DSA",
			pgpProfile:  pqc(),
		},
		{
			Name:        "draft-ietf-openpgp-persistent-symmetric-keys-00",
			Description: "AEAD and HMAC",
			pgpProfile:  symmetric(),
		},
	}
}

func defaultProfile() *profile.Custom {
	return profile.Default()
}

func rfc4880() *profile.Custom {
	return profile.RFC4880()
}

func rfc9580() *profile.Custom {
	return profile.RFC9580()
}

func pqc() *profile.Custom {
	return profile.PQC()
}

func symmetric() *profile.Custom {
	return profile.Symmetric()
}
