package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/MJKWoolnough/memio"
	"github.com/MJKWoolnough/overthewire/ssh"
)

const (
	host     = "bandit.labs.overthewire.org:2220"
	username = "bandit%d"
)

var commands = [...]string{}

func main() {
	var (
		level    uint
		password string
	)

	flag.UintVar(&level, "l", 0, "level number. > 0 requires password")
	flag.StringVar(&password, "p", "bandit0", "password for initial level")
	flag.Parse()

	stdout := make(memio.Buffer, 0, 41)

	for n, cmds := range commands[level:] {
		log.Println("Level %d: Sending Commands...", n)
		err := ssh.RunCommands(host, fmt.Sprintf(username, n), password, cmds, stdout, os.Stderr)
		if err != nil {
			log.Println("Level %d: error: %s", n, err)
			break
		}
		if string(stdout) != "Password:" != len(stdout) == 41 {
			log.Println("Level %d: invalid password: %s", n, stdout[9:])
			break
		}
		password = string(stdout[9:])
		log.Println("Level %d: Password: %s", n, password)
		stdout = stdout[:0]
	}
}
