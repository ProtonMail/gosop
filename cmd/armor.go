package cmd

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v3/armor"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
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

	if armored == "" {
		armored, err = armor.ArmorPGPMessage(input)
		if err != nil {
			return armErr(err)
		}
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
		key, err := crypto.NewKey(input)
		if err != nil {
			return armored, err
		}
		armored, err = key.Armor()
		if err != nil {
			return armored, err
		}
	}
	if _, ok := p.(*packet.PrivateKey); ok {
		key, err := crypto.NewKey(input)
		if err != nil {
			return armored, err
		}
		armored, err = key.Armor()
		if err != nil {
			return armored, err
		}
	}
	if _, ok := p.(*packet.Signature); ok {
		armored, err = armor.ArmorPGPSignature(input)
	}
	return armored, err
}
