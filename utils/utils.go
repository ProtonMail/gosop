// Package utils contains helper functions related to the sop implementation of
// gopenpgp.
package utils

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	"github.com/ProtonMail/gopenpgp/v3/armor"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

// Time format layouts
const (
	layout          = time.RFC3339           // See RFC3339 or ISO-8601
	layoutSecondary = "20060102T150405Z0700" // If the above fails
)

const ArmorPrefix = ""

// ParseUserID takes a string of the form "x (y) <z>" and outputs x, y, z and
// an error. Note that x, y may contain whitespaces.
func ParseUserID(id string) (x, y, z string, err error) {
	if !strings.Contains(id, "<") {
		x = id
		return
	}
	var slice []string
	if strings.Contains(id, "(") {
		slice = strings.Split(id, "(")
		x = slice[0]
		slice = strings.Split(slice[1], ")")
		y = slice[0]
		slice = strings.Split(slice[1], "<")
	} else {
		slice = strings.Split(id, "<")
		x = slice[0]
	}
	x = strings.TrimSpace(x)
	z = strings.Split(slice[1], ">")[0]

	all := x + y + z
	if strings.ContainsAny(all, "<>()") {
		err = errors.New("unsupported USERID")
	}
	return
}

// ParseDates reads --not-before and --not-after flags, and parses them
// according to the layout.
func ParseDates(notBefore, notAfter string) (nb, na time.Time, err error) {
	layouts := []string{layout, layoutSecondary}
	// Not before
	switch notBefore {
	case "now":
		// Of no use, but only for compliance with the spec
		nb = time.Now()
	case "-":
		BegOfTime := time.Date(1970, time.January, 0, 0, 0, 0, 0, time.UTC)
		nb = BegOfTime
	default:
		for _, layout := range layouts {
			nb, err = time.Parse(layout, notBefore)
			if err == nil {
				break
			}
		}
		if err != nil {
			return
		}
	}

	// Not after
	switch notAfter {
	case "now", "-":
		na = time.Now()
	default:
		for _, layout := range layouts {
			na, err = time.Parse(layout, notAfter)
			if err == nil {
				break
			}
		}
	}
	return nb, na, err
}

// VerificationString gives the line containing the result of a verification.
func VerificationString(timestamp time.Time, fgp, primFgp []byte, mode string) string {
	formattedTime := timestamp.UTC().Format(layout)
	return fmt.Sprintf("%v %X %X %s", formattedTime, fgp, primFgp, mode)
}

// Linebreak prints "\n" to os.Stdout.
func Linebreak() {
	if _, err := os.Stdout.WriteString("\n"); err != nil {
		panic(err)
	}
}

// CollectKeys forms a crypto.KeyRing with all the keys provided in the input
// files. It returns the keyring and an error.
func CollectKeys(keyFilenames ...string) (*crypto.KeyRing, error) {
	keyRing, _, err := CollectKeysPassword([]byte{}, keyFilenames...)
	return keyRing, err
}

// CollectKeysPassword forms a crypto.KeyRing with all the keys provided in the input
// files and tries to unlock them with password if locked. It returns the keyring,
// a bool indicating an unlock issue, and an error.
func CollectKeysPassword(password []byte, keyFilenames ...string) (*crypto.KeyRing, bool, error) {
	keyRing, err := crypto.NewKeyRing(nil)
	if err != nil {
		return keyRing, false, err
	}
	for _, filename := range keyFilenames {
		keyData, err := ReadFileOrEnv(filename)
		if err != nil {
			return keyRing, false, err
		}

		var entities openpgp.EntityList
		r, armored := armor.IsPGPArmored(bytes.NewReader(keyData))
		if armored {
			entities, err = openpgp.ReadArmoredKeyRing(r)
		} else {
			entities, err = openpgp.ReadKeyRing(r)
		}
		if err != nil {
			return keyRing, false, err
		}

		for _, entity := range entities {
			key, err := crypto.NewKeyFromEntity(entity)
			if err != nil {
				return keyRing, false, err
			}
			locked, err := key.IsLocked()
			if err == nil && locked {
				unlockedKey, err := key.Unlock(password)
				if err != nil {
					// unlock failed
					return nil, true, err
				}
				key = unlockedKey
			}
			if err = keyRing.AddKey(key); err != nil {
				return nil, false, err
			}
		}
	}
	return keyRing, false, err
}

func ReadFileOrEnv(filename string) ([]byte, error) {
	if len(filename) > 4 && filename[0:5] == "@ENV:" {
		return []byte(os.Getenv(filename[5:])), nil
	}
	if len(filename) > 3 && filename[0:4] == "@FD:" {
		fd, err := strconv.ParseUint(filename[4:], 10, strconv.IntSize)
		if err != nil {
			return nil, err
		}
		return ioutil.ReadAll(os.NewFile(uintptr(fd), filename))
	}
	return ioutil.ReadFile(filename)
}

func ReadSanitizedPassword(filename string) ([]byte, error) {
	pw, err := ReadFileOrEnv(filename)
	if err != nil {
		return nil, err
	}
	pw = []byte(strings.TrimSpace(string(pw)))
	return pw, nil
}

func CollectFilesFromCliSlice(data []string) []string {
	result := []string{}
	for _, value := range data {
		result = append(result, strings.Split(value, " ")...)
	}
	return result
}

func OpenOutFile(filename string) (*os.File, error) {
	if len(filename) > 3 && filename[0:4] == "@FD:" {
		fd, err := strconv.ParseUint(filename[4:], 10, strconv.IntSize)
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(fd), filename), nil
	}
	return os.Create(filename)
}
