package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"regexp"
	"strings"
)

const alphabet string = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

type Decoder struct {
	Key     string
	Encoded string
}

func (d *Decoder) checkString(decoded string) (err error) {
	var match []byte
	const pat string = "^THM{[a-zA-Z0-9]+}$"
	var re *regexp.Regexp

	re, err = regexp.Compile(pat)
	if err != nil {
		return err
	}

	match = re.Find([]byte(decoded))
	if match == nil {
		return fmt.Errorf("not the flag")
	}

	return nil
}

func (d *Decoder) decrypt() (decrypted string, err error) {
	var calculated byte
	var keybytes []byte
	var i int = 0
	var raw []byte
	var rawdec []byte = make([]byte, 0)

	keybytes, err = hex.DecodeString(d.Key)
	if err != nil {
		return "", err
	}

	raw, err = hex.DecodeString(d.Encoded)
	if err != nil {
		return "", err
	}

	for i = 0; i < len(raw); i++ {
		calculated = raw[i] ^ keybytes[i%len(keybytes)]
		rawdec = append(rawdec, calculated)
	}

	decrypted = string(rawdec)

	return decrypted, nil
}

func (d *Decoder) leakInfo() (keyinfo string, err error) {
	var calc byte
	var dec []byte
	var i int
	var pat []byte = []byte("THM{")
	var raw []byte = make([]byte, 0)

	dec, err = hex.DecodeString(d.Encoded)
	if err != nil {
		return "", err
	}

	dec = dec[:len(pat)]

	for i = 0; i < len(dec); i++ {
		calc = pat[i] ^ dec[i]
		raw = append(raw, calc)
	}

	keyinfo = string(raw)

	return keyinfo, nil
}

func (d *Decoder) BruteKey() (flag string, err error) {
	var bytekey []byte = make([]byte, 10)
	var decrypted string
	var found bool = false
	var i int
	var keyinfo string

	keyinfo, err = d.leakInfo()
	if err != nil {
		return "", err
	}

	for i = 0; i < len(alphabet); i++ {
		_ = hex.Encode(bytekey, []byte(fmt.Sprintf("%s%c", keyinfo, alphabet[i])))
		d.Key = string(bytekey)

		decrypted, err = d.decrypt()
		if err != nil {
			continue
		}

		if err = d.checkString(decrypted); err == nil {
			found = true
			break
		}
	}

	if !found {
		d.Key = ""
		return "", fmt.Errorf("flag not found")
	}

	return decrypted, nil
}

func init() {}

func main() {
	var decoder Decoder = Decoder{}
	var err error
	var flagstr string
	var keydec []byte

	flag.StringVar(&decoder.Encoded, "e", "", "hex encoded string to decrypt")
	flag.Parse()

	decoder.Encoded = strings.TrimSpace(decoder.Encoded)
	if len(decoder.Encoded) < 1 {
		log.Fatalf("no encoded string specified...")
	}

	flagstr, err = decoder.BruteKey()
	if err != nil {
		log.Fatalf(err.Error())
	}

	keydec, err = hex.DecodeString(decoder.Key)
	if err != nil {
		log.Fatalf(err.Error())
	}

	log.Printf("Key: %s\n", string(keydec))
	log.Printf("Flag: %s\n", flagstr)
}

