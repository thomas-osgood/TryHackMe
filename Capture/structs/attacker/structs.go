package attacker

import (
	"net/http"

	"github.com/thomas-osgood/OGOR/output"
)

type Attacker struct {
	client    *http.Client
	commschan chan string
	failmsg   string
	printer   *output.Outputter

	Route    string
	Scheme   string
	TargetIP string
	Username string
	Wordlist string
}

type AttackerOpt struct {
	Client   *http.Client
	FailMsg  string
	Route    string
	Scheme   string
	TargetIP string
	Username string
	Wordlist string
}
