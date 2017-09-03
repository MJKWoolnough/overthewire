package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

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
		"mkdir /tmp/otw-123456789;" +
		"cd /tmp/otw-123456789;" +
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
		"               cat data.bin | sed -e 's/.* //';" +
		"               break;;" +
		"       esac;" +
		"done;" +
		"cd;" +
		"rm -rf /tmp/otw-123456789;",
	//level 13
	"echo -n \"Password:\";ssh -o StrictHostKeyChecking=no -i sshkey.private bandit14@127.0.0.1 cat /etc/bandit_pass/bandit14 2> /dev/null",
	//level 14
	"echo -n \"Password:\";echo %q | nc 127.0.0.1 30000 | grep -v \"Correct\" | tr -d '\\r\\n';echo",
	//level 15
	"echo -n \"Password:\";echo %q | openssl s_client -ign_eof -connect 127.0.0.1:30001 2> /dev/null | grep -A1 \"Correct\" | grep -v \"Correct\" | tr -d '\\r\\n';echo",
	//level 16
	"echo -n \"Password:\";" +
		"nmap -p 31000-32000 127.0.0.1 | grep \"/tcp\" | sed -e 's@^\\([0-9]*\\)/.*@\\1@' | while read port; do" +
		"       (echo %q;sleep 2s) | openssl s_client -connect 127.0.0.1:\"$port\";" +
		"done 2> /dev/null | grep -A 27 Correct | grep -v Correct > /tmp/private-123456789.key;" +
		"chmod 600 /tmp/private-123456789.key;" +
		"ssh -o StrictHostKeyChecking=no -i /tmp/private-123456789.key bandit17@127.0.0.1 cat /etc/bandit_pass/bandit17 2> /dev/null;" +
		"rm -f /tmp/private-123456789.key;",
	//level 17
	"echo -n \"Password:\";diff passwords.old passwords.new | tail -n1 | cut -d' ' -f2",
	//level 18
	"echo -n \"Password:\";cat readme",
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

		if strings.Contains(cmds, "%q") {
			cmds = fmt.Sprintf(cmds, password)
		}

		err := ssh.RunCommands(host, fmt.Sprintf(username, n), password, cmds, &stdout, os.Stderr)
		if err != nil {
			log.Printf("Level %d: error: %s\n", n, err)
			break
		}
		if string(stdout[:9]) != "Password:" || len(stdout) != 42 || stdout[41] != 10 {
			log.Printf("Level %d: invalid password: %s\n", n, stdout[9:])
			break
		}
		password = string(stdout[9:41])
		log.Printf("Level %d: Password: %s\n", n, password)
		stdout = stdout[:0]
	}
}
