package utils

import (
	"crypto"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/go-crypto/openpgp/s2k"
	"github.com/ProtonMail/gopenpgp/v3/constants"
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
	}
}

func defaultProfile() *profile.Custom {
	setKeyAlgorithm := func(cfg *packet.Config, securityLevel int8) {
		cfg.Algorithm = packet.PubKeyAlgoEdDSA
		switch securityLevel {
		case constants.HighSecurity:
			cfg.Curve = packet.Curve25519
		default:
			cfg.Curve = packet.Curve25519
		}
	}
	return &profile.Custom{
		SetKeyAlgorithm:      setKeyAlgorithm,
		Hash:                 crypto.SHA256,
		CipherEncryption:     packet.CipherAES256,
		CompressionAlgorithm: packet.CompressionZLIB,
		CompressionConfiguration: &packet.CompressionConfig{
			Level: 6,
		},
	}
}

func rfc4880() *profile.Custom {
	setKeyAlgorithm := func(cfg *packet.Config, securityLevel int8) {
		cfg.Algorithm = packet.PubKeyAlgoRSA
		switch securityLevel {
		case constants.HighSecurity:
			cfg.RSABits = 4096
		default:
			cfg.RSABits = 3072
		}
	}
	return &profile.Custom{
		SetKeyAlgorithm:      setKeyAlgorithm,
		Hash:                 crypto.SHA256,
		CipherEncryption:     packet.CipherAES256,
		CompressionAlgorithm: packet.CompressionZLIB,
	}
}

func rfc9580() *profile.Custom {
	setKeyAlgorithm := func(cfg *packet.Config, securityLevel int8) {
		switch securityLevel {
		case constants.HighSecurity:
			cfg.Algorithm = packet.PubKeyAlgoEd448
		default:
			cfg.Algorithm = packet.PubKeyAlgoEd25519
		}
	}
	return &profile.Custom{
		SetKeyAlgorithm:      setKeyAlgorithm,
		Hash:                 crypto.SHA512,
		CipherEncryption:     packet.CipherAES256,
		CompressionAlgorithm: packet.CompressionZLIB,
		AeadKeyEncryption:    &packet.AEADConfig{},
		AeadEncryption:       &packet.AEADConfig{},
		S2kKeyEncryption: &s2k.Config{
			S2KMode:      s2k.Argon2S2K,
			Argon2Config: &s2k.Argon2Config{},
		},
		S2kEncryption: &s2k.Config{
			S2KMode:      s2k.Argon2S2K,
			Argon2Config: &s2k.Argon2Config{},
		},
		V6: true,
	}
}
