package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"regexp"
	"strings"
)

const alphabet string = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

type Decoder struct {
	conn    net.Conn
	encoded string
	Key     string
	Target  string
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

func (d *Decoder) connect() (err error) {
	d.conn, err = net.Dial("tcp", d.Target)
	return err
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

	raw, err = hex.DecodeString(d.encoded)
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

// reference:
//
// https://www.developer.com/languages/intro-socket-programming-go/
func (d *Decoder) getEncrypted() (err error) {
	var mBuff []byte = make([]byte, 4096)
	var nRead int = 0

	nRead, err = d.conn.Read(mBuff)
	if err != nil {
		return err
	}

	d.encoded = string(bytes.TrimSpace(bytes.Split(mBuff[:nRead], []byte(":"))[1]))

	return nil
}

func (d *Decoder) getFlag2() (flag2 string, err error) {
	var keydec []byte
	var mBuff []byte = make([]byte, 1024)
	var nRead int = 0

	keydec, err = hex.DecodeString(d.Key)
	if err != nil {
		return "", err
	}
	keydec = append(keydec, '\n')

	// read the server prompt asking for the key.
	_, err = d.conn.Read(mBuff)
	if err != nil {
		return "", err
	}

	// send the key to the server.
	nRead, err = d.conn.Write(keydec)
	if err != nil {
		return "", err
	}

	// read the server response.
	nRead, err = d.conn.Read(mBuff)
	if err != nil {
		return "", err
	}

	flag2 = string(bytes.TrimSpace(bytes.Split(mBuff[:nRead], []byte(":"))[1]))

	return flag2, nil
}

func (d *Decoder) leakInfo() (keyinfo string, err error) {
	var calc byte
	var dec []byte
	var i int
	var pat []byte = []byte("THM{")
	var raw []byte = make([]byte, 0)

	dec, err = hex.DecodeString(d.encoded)
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

func (d *Decoder) BruteKey() (flag string, flag2 string, err error) {
	var bytekey []byte = make([]byte, 10)
	var decrypted string
	var found bool = false
	var i int
	var keyinfo string

	err = d.connect()
	if err != nil {
		return "", "", err
	}
	defer d.conn.Close()

	err = d.getEncrypted()
	if err != nil {
		return "", "", err
	}

	keyinfo, err = d.leakInfo()
	if err != nil {
		return "", "", err
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
		return "", "", fmt.Errorf("flag not found")
	}

	flag2, err = d.getFlag2()
	if err != nil {
		return "", "", err
	}

	return decrypted, flag2, nil
}

func init() {}

func main() {
	var decoder Decoder = Decoder{}
	var err error
	var flagstr string
	var flag2str string
	var keydec []byte
	var target string

	flag.StringVar(&target, "t", "", "address (ip:port) of target server")
	flag.Parse()

	target = strings.TrimSpace(target)
	if len(target) < 1 {
		log.Fatalf("no target specified...")
	}

	decoder.Target = target

	flagstr, flag2str, err = decoder.BruteKey()
	if err != nil {
		log.Fatalf(err.Error())
	}

	keydec, err = hex.DecodeString(decoder.Key)
	if err != nil {
		log.Fatalf(err.Error())
	}

	log.Printf("Key: %s\n", string(keydec))
	log.Printf("Flag: %s\n", flagstr)
	log.Printf("Flag2: %s\n", flag2str)
}

