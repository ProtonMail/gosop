package cmd

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/gosop/utils"

	"github.com/ProtonMail/gopenpgp/v2/constants"
	"github.com/ProtonMail/gopenpgp/v2/crypto"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

var symKeyAlgos = map[packet.CipherFunction]string{
	packet.Cipher3DES:   constants.ThreeDES,
	packet.CipherCAST5:  constants.CAST5,
	packet.CipherAES128: constants.AES128,
	packet.CipherAES192: constants.AES192,
	packet.CipherAES256: constants.AES256,
}

// Decrypt takes the data from stdin and decrypts it with the key file passed as
// argument, or a passphrase in a file passed with the --with-password flag.
// Note: Can't encrypt both symmetrically (passphrase) and keys.
// TODO: Multiple signers?
//
// --session-key-out=file flag: Outputs session key byte stream to given file.
// About --with-session-key flag: This is not currently supported and could be
// achieved with openpgp.packet, taking the first packet.EncryptedDataPacket
// (be it Sym. Encrypted or AEAD Encrypted) and then decrypt directly.
func Decrypt(keyFilenames ...string) error {
	if len(keyFilenames) == 0 && password == "" && sessionKey == "" {
		println("Please provide decryption keys, session key, or passphrase")
		return Err69
	}

	ciphertextBytes, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return decErr(err)
	}
	ciphertext, err := crypto.NewPGPMessageFromArmored(string(ciphertextBytes))
	if err != nil {
		// If that fails, try binary
		ciphertext = crypto.NewPGPMessage(ciphertextBytes)
	}
	var pubKeyRing *crypto.KeyRing
	if verifyWith != "" {
		pubKeyRing, err = utils.CollectKeys([]string{verifyWith}...)
		if err != nil {
			return decErr(err)
		}
	}
	var sk *crypto.SessionKey
	if sessionKey != "" {
		sk, err = parseSessionKey()
	} else if password != "" {
		sk, err = passwordDecrypt(ciphertext)
	} else {
		sk, err = publicKeyDecrypt(ciphertext, keyFilenames)
	}
	if err != nil {
		return decErr(err)
	}
	if sessionKeyOut != "" {
		err := writeSessionKeyToFile(sk)
		if err != nil {
			return decErr(err)
		}
	}
	plaintext, err := sk.DecryptAndVerify(getEncryptedDataPacket(ciphertext), pubKeyRing, crypto.GetUnixTime())
	if err != nil {
		return decErr(err)
	}
	_, err = os.Stdout.WriteString(plaintext.GetString())
	if err != nil {
		return decErr(err)
	}
	if verificationsOut != "" {
		// TODO: This is fake
		if err := writeVerificationToFile(pubKeyRing); err != nil {
			return err
		}
	}
	return nil
}

func decErr(err error) error {
	return Err99("decrypt", err)
}

func parseSessionKey() (*crypto.SessionKey, error) {
	formattedSessionKey, err := utils.ReadFileOrEnv(sessionKey)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimSpace(string(formattedSessionKey)), ":")
	skAlgo, err := strconv.ParseUint(parts[0], 10, 8)
	if err != nil {
		return nil, err
	}
	skAlgoName := ""
	if skAlgo != 0 {
		var ok bool
		skAlgoName, ok = symKeyAlgos[packet.CipherFunction(skAlgo)]
		if !ok {
			return nil, errors.New("unsupported session key algorithm")
		}
	}

	skBytes, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	sk := crypto.NewSessionKeyFromToken(skBytes, skAlgoName)
	return sk, nil
}

func passwordDecrypt(message *crypto.PGPMessage) (*crypto.SessionKey, error) {
	pw, err := utils.ReadFileOrEnv(password)
	if err != nil {
		return nil, err
	}
	pw = []byte(strings.TrimSpace(string(pw)))
	sk, err := crypto.DecryptSessionKeyWithPassword(message.GetBinary(), pw)
	if err != nil {
		return nil, err
	}
	return sk, err
}

func publicKeyDecrypt(message *crypto.PGPMessage, keyFilenames []string) (*crypto.SessionKey, error) {
	privKeyRing, err := utils.CollectKeys(keyFilenames...)
	if err != nil {
		return nil, err
	}

	sk, err := privKeyRing.DecryptSessionKey(message.GetBinary())
	if err != nil {
		return nil, err
	}
	return sk, nil
}

func getEncryptedDataPacket(message *crypto.PGPMessage) []byte {
	bytesReader := bytes.NewReader(message.Data)
	packets := packet.NewReader(bytesReader)
	start := int64(0)
	for {
		p, err := packets.Next()
		if err != nil {
			break
		}
		switch p.(type) {
		case *packet.SymmetricKeyEncrypted, *packet.EncryptedKey:
			start = bytesReader.Size() - int64(bytesReader.Len())
		case *packet.SymmetricallyEncrypted, *packet.AEADEncrypted:
			break
		}
	}
	return message.Data[start:]
}

func writeSessionKeyToFile(sk *crypto.SessionKey) error {
	var sessionKeyFile *os.File
	if sessionKeyOut[0:4] == "@FD:" {
		fd, err := strconv.ParseUint(sessionKeyOut[4:], 10, strconv.IntSize)
		if err != nil {
			return err
		}
		sessionKeyFile = os.NewFile(uintptr(fd), sessionKeyOut)
	} else {
		var err error
		sessionKeyFile, err = os.Create(sessionKeyOut)
		if err != nil {
			return err
		}
	}
	cipherFunc, err := sk.GetCipherFunc()
	if err != nil {
		return decErr(err)
	}
	formattedSessionKey := strconv.FormatUint(uint64(cipherFunc), 10) + ":" +
		strings.ToUpper(hex.EncodeToString(sk.Key))
	if _, err = sessionKeyFile.Write([]byte(formattedSessionKey)); err != nil {
		return decErr(err)
	}
	if err = sessionKeyFile.Close(); err != nil {
		return decErr(err)
	}
	return nil
}

func writeVerificationToFile(pubKeyRing *crypto.KeyRing) error {
	fgp, err := hex.DecodeString(pubKeyRing.GetKeys()[0].GetFingerprint())
	if err != nil {
		return decErr(err)
	}
	ver := utils.VerificationString(time.Now(), fgp, fgp)
	outputVerFile, err := os.Create(verificationsOut)
	if err != nil {
		return decErr(err)
	}
	if _, err = outputVerFile.WriteString(ver + "\n"); err != nil {
		return decErr(err)
	}
	if err = outputVerFile.Close(); err != nil {
		return decErr(err)
	}
	return nil
}
