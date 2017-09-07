package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MJKWoolnough/memio"
)

type Hex2Dec struct {
	Grabber
}

func (h Hex2Dec) Grab(r http.Request) string {
	hx := h.Grabber.Grab(r)
	dec := make([]byte, hex.DecodedLen(len(hx)))
	_, err := hex.Decode(dec, []byte(hx))
	e(err)
	return string(dec)
}

type Reverse struct {
	Grabber
}

func (rv Reverse) Grab(r http.Request) string {
	str := rv.Grabber.Grab(r)
	rts := make([]byte, len(str))
	for n, b := range []byte(str) {
		rts[len(rts)-n-1] = b
	}
	return string(rts)
}

type Base64Decode struct {
	Grabber
}

func (b Base64Decode) Grab(r http.Request) string {
	str := b.Grabber.Grab(r)
	res, err := base64.StdEncoding.DecodeString(strings.Replace(str, "%3D", "=", -1))
	e(err)
	return string(res)
}

type Base64Encode struct {
	Grabber
}

func (b Base64Encode) Grab(r http.Request) string {
	str := b.Grabber.Grab(r)
	return base64.StdEncoding.EncodeToString([]byte(str))
}

type XOR struct {
	Input, Key Grabber
}

func (x XOR) Grab(r http.Request) string {
	i := x.Input.Grab(r)
	k := x.Key.Grab(r)
	o := make([]byte, len(i))
	for n, c := range []byte(i) {
		o[n] = c ^ k[n%len(k)]
	}
	return string(o)
}

type Combine struct {
	Prefix, Suffix Grabber
}

func (c Combine) Grab(r http.Request) string {
	prefix := c.Prefix.Grab(r)
	suffix := c.Suffix.Grab(r)
	return prefix + suffix
}

type Cut struct {
	Grabber
	Seperator string
	Slice     int
}

func (c Cut) Grab(r http.Request) string {
	parts := strings.Split(c.Grabber.Grab(r), c.Seperator)
	if c.Slice >= len(parts) {
		panic("invalid slice number")
	}
	return parts[c.Slice]
}

type URLDecode struct {
	Grabber
}

func (u URLDecode) Grab(r http.Request) string {
	str, err := url.QueryUnescape(u.Grabber.Grab(r))
	e(err)
	return str
}

type URLEncode struct {
	Grabber
}

func (u URLEncode) Grab(r http.Request) string {
	return url.QueryEscape(u.Grabber.Grab(r))
}

type FindRepeating struct {
	Grabber
}

func (f FindRepeating) Grab(r http.Request) string {
	str := f.Grabber.Grab(r)
	for length := 1; length < len(str); length++ {
		if r := strings.Repeat(str[:length], 1+(len(str)/length)); r[:len(str)] == str {
			return str[:length]
		}
	}
	return str
}

type PHPSerialize struct {
	ObjectName string
	Fields     map[string]interface{}
}

func (p PHPSerialize) Grab(r http.Request) string {
	var m memio.Buffer
	fmt.Fprintf(&m, "O:%d:\"%s\":%d:{", len(p.ObjectName), p.ObjectName, len(p.Fields))
	for name, field := range p.Fields {
		oName := "\x00" + p.ObjectName + "\x00" + name
		fmt.Fprintf(&m, "s:%d:\"%s\";", len(oName), oName)
		switch f := field.(type) {
		case Grabber:
			g := f.Grab(r)
			fmt.Fprintf(&m, "s:%d:\"%s\";", len(g), g)
		case string:
			fmt.Fprintf(&m, "s:%d:\"%s\";", len(f), f)
		default:
			panic("type unsupported for PHP serialization")
		}
	}
	fmt.Fprintf(&m, "}")
	return string(m)
}

var randomNames = map[string]string{}

func init() {
	rand.Seed(time.Now().UnixNano())
}

type Random struct {
	Name, Chars string
	Length      int
}

func (r Random) Grab(http.Request) string {
	if str, ok := randomNames[r.Name]; ok {
		return str
	}
	var b memio.Buffer
	for i := 0; i < r.Length; i++ {
		b.WriteByte(r.Chars[rand.Intn(len(r.Chars))])
	}
	str := string(b)
	randomNames[r.Name] = str
	return str
}
