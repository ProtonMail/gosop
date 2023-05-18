// Package utils contains helper functions related to the sop implementation of
// gopenpgp.
package utils

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// Time format layouts
const (
	layout          = time.RFC3339           // See RFC3339 or ISO-8601
	layoutSecondary = "20060102T150405Z0700" // If the above fails
)

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
func VerificationString(timestamp time.Time, fgp, primFgp []byte) string {
	formattedTime := timestamp.UTC().Format(layout)
	return fmt.Sprintf("%v %X %X", formattedTime, fgp, primFgp)
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
	keyRing, err := crypto.NewKeyRing(nil)
	if err != nil {
		return keyRing, err
	}
	for _, filename := range keyFilenames {
		keyData, err := ReadFileOrEnv(filename)
		if err != nil {
			return keyRing, err
		}
		var key *crypto.Key
		if strings.Contains(string(keyData), "-----BEGIN PGP") {
			key, err = crypto.NewKeyFromArmored(string(keyData))
		} else {
			key, err = crypto.NewKey(keyData)
		}
		if err != nil {
			return nil, err
		}
		if err = keyRing.AddKey(key); err != nil {
			return nil, err
		}
	}
	return keyRing, err
}

func ReadFileOrEnv(filename string) ([]byte, error) {
	if filename[0:5] == "@ENV:" {
		return []byte(os.Getenv(filename[5:])), nil
	}
	if filename[0:4] == "@FD:" {
		fd, err := strconv.ParseUint(filename[4:], 10, strconv.IntSize)
		if err != nil {
			return nil, err
		}
		return ioutil.ReadAll(os.NewFile(uintptr(fd), filename))
	}
	return ioutil.ReadFile(filename)
}
