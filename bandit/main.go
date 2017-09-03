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

var commands = [...]string{
	//level 0
	"echo -n \"Password:\";cat readme",
	//level 1
	"echo -n \"Password:\";cat ./-",
	//level 2
	"echo -n \"Password:\";cat \"spaces in this filename\"",
	//level 3
	"echo -n \"Password:\";cat inhere/.hidden",
}

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
		log.Printf("Level %d: Sending Commands...\n", n)

		err := ssh.RunCommands(host, fmt.Sprintf(username, n), password, cmds, &stdout, os.Stderr)
		if err != nil {
			log.Printf("Level %d: error: %s\n", n, err)
			break
		}
		if string(stdout[:9]) != "Password:" || len(stdout) != 42 {
			log.Printf("Level %d: invalid password: %s\n", n, stdout[9:])
			break
		}
		password = string(stdout[9:])
		log.Printf("Level %d: Password: %s\n", n, password)
		stdout = stdout[:0]
	}
}
