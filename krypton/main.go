package main // import "vimagination.zapto.org/overthewire/krypton"

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"golang.org/x/crypto/ssh"

	"vimagination.zapto.org/memio"
)

const (
	host     = "krypton.labs.overthewire.org:2222"
	username = "krypton%d"
)

var (
	commands = [...][]string{
		//level 0
		[]string{},
		//level 1
		[]string{
			"echo -n \"Password:\";cat /krypton/krypton1/krypton2 | tr \"[N-ZA-M]\" \"[A-Z]\" | cut -d' ' -f4;exit\n",
		},
		//level 2

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

	flag.UintVar(&level, "l", 1, "level number. > 1 requires password")
	flag.StringVar(&password, "p", "KRYPTONISGREAT", "password for initial level")
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
