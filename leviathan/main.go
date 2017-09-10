package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/MJKWoolnough/memio"
)

const (
	host     = "leviathan.labs.overthewire.org:2223"
	username = "leviathan%d"
)

var (
	commands = [...]string{}
)

func RunCommands(server, username, password, commands string, stdout, stderr io.Writer) error {
	s, err := ssh.Dial("tcp", server, &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		return err
	}
	session, err := s.NewSession()
	if err != nil {
		return err
	}

	session.Stdout = stdout
	session.Stderr = stderr

	err = session.Run(commands)
	session.Close()
	if err != nil {
		return err
	}
	return s.Close()
}

func main() {
	var (
		level    uint
		password string
	)

	flag.UintVar(&level, "l", 0, "level number. > 0 requires password")
	flag.StringVar(&password, "p", "leviathan0", "password for initial level")
	flag.Parse()

	stdout := make(memio.Buffer, 0, 41)

	// levels 0-24

	for n, cmds := range commands[level:] {
		n += int(level)
		log.Printf("Level %2d: Sending Commands...\n", n)

		if strings.Contains(cmds, "%q") {
			cmds = fmt.Sprintf(cmds, password)
		}

		err := RunCommands(host, fmt.Sprintf(username, n), password, cmds, &stdout, os.Stderr)
		if err != nil {
			log.Printf("Level %2d: error: %s\n", n, err)
			break
		}
		if string(stdout[:9]) != "Password:" || len(stdout) != 20 || stdout[19] != 10 {
			log.Printf("Level %2d: invalid password: %s\n", n, stdout[9:])
			return
		}
		password = string(stdout[9:19])
		log.Printf("Level %2d: Password: %s\n", n, password)
		stdout = stdout[:0]
	}
}
