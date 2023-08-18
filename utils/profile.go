package utils

import "github.com/ProtonMail/gopenpgp/v3/profile"

const DefaultProfileName string = "default"

var EncryptionProfiles = []string{"rfc4880", "draft-ietf-openpgp-crypto-refresh-10"}
var KeyGenerationProfiles = []string{"draft-koch-eddsa-for-openpgp-00", "draft-ietf-openpgp-crypto-refresh-10", "rfc4880"}

var descriptions = map[string]string{
	"generate-key rfc4880":                              "Generates 3072-bit RSA keys",
	"generate-key draft-koch-eddsa-for-openpgp-00":      "(default) Generates EdDSA/ECDH v4 keys with Curve25519",
	"generate-key draft-ietf-openpgp-crypto-refresh-10": "Generates Ed25519/X25519 v6 keys with Curve25519",
	"encrypt rfc4880":                                   "(default) CFB (SEIPDv1)",
	"encrypt draft-ietf-openpgp-crypto-refresh-10":      "AEAD (SEIPDv2) enabled",
}

func SelectKeyGenerationProfile(name string) *profile.Custom {
	if name == DefaultProfileName {
		name = KeyGenerationProfiles[0]
	}
	return profile.WithName(name)
}

func SelectEncryptionProfile(name string) *profile.Custom {
	if name == DefaultProfileName {
		name = EncryptionProfiles[0]
	}
	return profile.WithName(name)
}

func GetProfileDescription(cmd, profile string) string {
	description, ok := descriptions[cmd+" "+profile]
	if !ok {
		return ""
	}
	return description
}
