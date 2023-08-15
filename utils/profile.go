package utils

import "github.com/ProtonMail/gopenpgp/v3/profile"

var descriptions = map[string]string{
	"generate-key rfc4880":                              "generates 3072-bit rsa keys",
	"generate-key draft-koch-eddsa-for-openpgp-00":      "generates EdDSA/ECDH v4 keys with Curve25519",
	"generate-key draft-ietf-openpgp-crypto-refresh-10": "generates Ed25519/X25519 v6 keys with Curve25519",
	"encrypt rfc4880":                                   "CFB (SEIPDv1)",
	"encrypt draft-koch-eddsa-for-openpgp-00":           "AEAD (SEIPDv2) enabled",
	"encrypt draft-ietf-openpgp-crypto-refresh-10":      "AEAD (SEIPDv2) enabled",
}

func SelectProfile(name string) *profile.Custom {
	return profile.WithName(name)
}

func GetProfileDescription(cmd, profile string) string {
	description, ok := descriptions[cmd+" "+profile]
	if !ok {
		return ""
	}
	return description
}
