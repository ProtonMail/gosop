package utils

import "github.com/ProtonMail/gopenpgp/v3/profile"

var descriptions = map[string]string{
	"generate-key rfc4880":                           "generates rsa keys with RFC 4880 algorithms",
	"generate-key draft-koch-openpgp":                "generates x25519 keys with draft-koch algorithms",
	"generate-key draft-ietf-openpgp-crypto-refresh": "generates x25519 keys with draft-ietf-openpgp-crypto-refresh algorithms",
	"encrypt rfc4880":                                "no aead",
	"encrypt draft-koch-openpgp":                     "aead enabled according to draft-koch",
	"encrypt draft-ietf-openpgp-crypto-refresh":      "aead enabled according to draft-ietf-openpgp-crypto-refresh",
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
