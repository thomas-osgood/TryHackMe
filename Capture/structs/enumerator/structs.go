package enumerator

import (
	"net/http"

	"github.com/thomas-osgood/OGOR/output"
)

type Enumerator struct {
	client    *http.Client
	commschan chan string
	failmsg   string
	onlyOne   bool
	printer   *output.Outputter

	Route    string
	Scheme   string
	TargetIP string
	Wordlist string
	Password string
}

type EnumeratorOpt struct {
	Client   *http.Client
	FailMsg  string
	OnlyOne  bool
	Route    string
	Scheme   string
	TargetIP string
	Wordlist string
	Password string
}
