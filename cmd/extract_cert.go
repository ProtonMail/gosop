package cmd

import (
	"io"
	"os"

	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	"github.com/ProtonMail/gopenpgp/v3/armor"
	"github.com/ProtonMail/gopenpgp/v3/constants"
)

// ExtractCert - Extract a Certificate from a Secret Key
func ExtractCert() error {
	var entities openpgp.EntityList
	var err error
	r, armored := armor.IsPGPArmored(os.Stdin)
	if armored {
		entities, err = openpgp.ReadArmoredKeyRing(r)
	} else {
		entities, err = openpgp.ReadKeyRing(r)
	}
	if err != nil {
		return certErr(err)
	}

	var w io.WriteCloser
	w = os.Stdout
	if !noArmor {
		v6 := true
		for _, entity := range entities {
			if entity.PrimaryKey.Version != 6 {
				v6 = false
			}
		}
		w, err = armor.ArmorWriterWithTypeChecksum(w, constants.PublicKeyHeader, !v6)
		if err != nil {
			return certErr(err)
		}
	}

	for _, entity := range entities {
		err = entity.Serialize(w)
		if err != nil {
			return certErr(err)
		}
	}

	if !noArmor {
		err = w.Close()
		if err != nil {
			return certErr(err)
		}
	}
	_, err = os.Stdout.WriteString("\n")
	if err != nil {
		return certErr(err)
	}
	return nil
}

func certErr(err error) error {
	return Err99("extract-cert", err)
}
