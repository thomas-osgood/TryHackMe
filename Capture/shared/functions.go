package shared

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// function designed to check for a fail message in an
// http response. if the fail message is found in the
// http response, an error is returned.
func CheckResponse(response *http.Response, message string, captchamsg string) (content []byte, err error) {

	if response.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("bad return code (%s)", response.Status)
	}

	content, err = io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	if len(content) < 1 {
		return nil, err
	}

	if bytes.Contains(content, []byte(message)) || bytes.Contains(content, []byte(captchamsg)) {
		return content, fmt.Errorf("fail message found in response")
	}

	return content, nil
}

// generic function designed to check if the value v
// is in slice s.
func Contains[T Checkable](s []T, v T) bool {
	var i int
	for i = range s {
		if s[i] == v {
			return true
		}
	}
	return false
}

// function designed to search for and return the flag
// from a website's contents. this is designed only for
// the Capture room, as it pulls out the first instance
// of <h3>([a-zA-Z0-9]+)</h3> in the content passed in.
func ReadFlag(content []byte) (flag string, err error) {
	var matches [][]byte
	const regpat string = `<h3>([a-zA-Z0-9]+)</h3>`
	var re *regexp.Regexp = regexp.MustCompile(regpat)

	matches = re.FindAll(content, -1)
	if (matches == nil) || (len(matches) < 1) {
		return "", fmt.Errorf("flag not found")
	}

	flag = string(matches[0])

	// remove the h3 tags from the extracted flag.
	flag = strings.ReplaceAll(flag, "<h3>", "")
	flag = strings.ReplaceAll(flag, "</h3>", "")

	return flag, nil
}

// function designed to pull out the captcha question from
// the response content, solve it and return the answer.
func SolveCaptcha(content []byte) (answer int, err error) {
	var matches [][]byte
	var n1 int
	var n1s string
	var n2 int
	var n2s string
	var op string
	var re *regexp.Regexp
	var regpat string = `[0-9]+\s(\+|-|\*|/)\s[0-9]+\s\=`
	var question string
	var qsplit []string

	re, err = regexp.Compile(regpat)
	if err != nil {
		return 0, err
	}

	matches = re.FindAll(content, -1)
	if matches == nil {
		return 0, fmt.Errorf("captcha not found")
	}
	question = strings.TrimSpace(string(matches[0]))

	qsplit = strings.Split(question, " ")

	n1s = qsplit[0]
	op = qsplit[1]
	n2s = qsplit[2]

	n1, err = strconv.Atoi(n1s)
	if err != nil {
		return 0, err
	}

	n2, err = strconv.Atoi(n2s)
	if err != nil {
		return 0, err
	}

	switch op {
	case "+":
		answer = n1 + n2
	case "-":
		answer = n1 - n2
	case "*":
		answer = n1 * n2
	case "/":
		answer = n1 / n2
	}

	return answer, nil
}
