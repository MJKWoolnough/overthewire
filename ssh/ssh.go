package ssh

import (
	"log"
	"os"

	"golang.org/x/crypto/ssh"
)

func RunCommands(server, username, password, commands string) {
	logger := log.New(os.Stderr, username+": ", 0)
	logger.Println("Dialing...")
	s, err := ssh.Dial("tcp", server, &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		logger.Fatal(err)
	}
	logger.Println("...Connected")
	session, err := s.NewSession()
	if err != nil {
		logger.Fatal(err)
	}
	defer session.Close()
	session.Stdout = os.Stdout
	err = session.Run(commands)
	if err != nil {
		logger.Fatal(err)
	}
}
