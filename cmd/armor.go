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
	input, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return armErr(err)
	}

	// If already armored, output directly and return
	if string(input[:14]) == "-----BEGIN PGP" {
		if _, err := os.Stdout.Write(input); err != nil {
			return armErr(err)
		}
		return nil
	}

	armored, err := armorDecidingType(input)
	if err != nil {
		return armErr(err)
	}

	if armored == "" {
		message := crypto.NewPGPMessage(input)
		armored, err = message.GetArmored()
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
		message := crypto.NewPGPMessage(input)
		armored, err = message.GetArmored()
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
