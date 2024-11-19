package cmd

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"

	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v3/armor"
	"github.com/ProtonMail/gopenpgp/v3/constants"
)

// ArmorComm takes unarmored OpenPGP material from Std input and outputs the
// same material with ASCII-armoring added.
func ArmorComm(keyFilenames ...string) error {
	inputReader, isArmored := armor.IsPGPArmored(os.Stdin)
	if isArmored {
		// If already armored, output directly and return
		_, err := io.Copy(os.Stdout, inputReader)
		if err != nil {
			return armErr(err)
		}
		return nil
	}

	input, err := ioutil.ReadAll(inputReader)
	if err != nil {
		return armErr(err)
	}

	armored, err := armorDecidingType(input)
	if err != nil {
		return armErr(err)
	}

	_, err = os.Stdout.WriteString(armored + "\n")
	return err
}

func armErr(err error) error {
	return Err99("armor", err)
}

func armorDecidingType(input []byte) (armored string, err error) {
	packets := packet.NewReader(bytes.NewReader(input))
	var p packet.Packet
	if p, err = packets.Next(); err != io.EOF && err != nil {
		armored, err = armor.ArmorPGPMessage(input)
		if err != nil {
			return armored, err
		}
	}
	if _, ok := p.(*packet.PublicKey); ok {
		return armorKeys(input, constants.PublicKeyHeader)
	}
	if _, ok := p.(*packet.PrivateKey); ok {
		return armorKeys(input, constants.PrivateKeyHeader)
	}
	if _, ok := p.(*packet.Signature); ok {
		armored, err = armor.ArmorPGPSignature(input)
		if err != nil {
			return armored, err
		}
	}
	armored, err = armor.ArmorPGPMessage(input)
	return armored, err
}

func armorKeys(input []byte, armorType string) (armored string, err error) {
	entities, err := openpgp.ReadKeyRing(bytes.NewReader(input))
	if err != nil {
		return armored, err
	}

	var output bytes.Buffer

	v6 := true
	for _, entity := range entities {
		if entity.PrimaryKey.Version != 6 {
			v6 = false
		}
	}

	w, err := armor.ArmorWriterWithTypeChecksum(&output, armorType, !v6)
	if err != nil {
		return armored, err
	}

	for _, entity := range entities {
		err = entity.Serialize(w)
		if err != nil {
			return armored, err
		}
	}

	err = w.Close()
	if err != nil {
		return armored, err
	}

	armored = output.String()
	return armored, err
}
