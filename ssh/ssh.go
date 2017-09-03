package ssh

import (
	"io"

	"golang.org/x/crypto/ssh"
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
	return nil
}
