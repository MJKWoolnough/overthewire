package main

import (
	"io"
	"mime/multipart"
	"net/http"
	"net/url"

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
	SetData
}

func (h Headers) Grab(r http.Request) string {
	newHeaders := make(http.Header)
	for key, value := range r.Header {
		newHeaders[key] = value
	}
	h.Set(r, newHeaders)
	r.Header = newHeaders
	p := h.Grabber.Grab(r)
	return p
}

type Post struct {
	Grabber
	SetData
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
	p.Set(r, MPSetter{m})
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
	SetData
}

func (g Get) Grab(r http.Request) string {
	values := make(url.Values, len(g.SetData))
	g.Set(r, values)
	oldQuery := r.URL.RawQuery
	r.URL.RawQuery = values.Encode()
	s := g.Grabber.Grab(r)
	r.URL.RawPath = oldQuery
	return s
}

type SetData map[string]Grabber

type SetDataGrabber interface {
	Grabber
	SetKey(string, Grabber)
}

type Setter interface {
	Set(string, string)
}

func (sd SetData) Set(r http.Request, s Setter) {
	for key, g := range sd {
		s.Set(key, g.Grab(r))
	}
}

func (sd SetData) SetKey(Key string, Value Grabber) {
	sd[Key] = Value
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

type GetHeader struct {
	Header string
}

func (g GetHeader) Grab(r http.Request) string {
	resp, err := http.DefaultClient.Do(&r)
	e(err)
	e(resp.Body.Close())
	return resp.Header.Get(g.Header)
}

type LoadAll []Grabber

func (l LoadAll) Grab(r http.Request) string {
	for _, g := range l[:len(l)-1] {
		g.Grab(r)
	}
	return l[len(l)-1].Grab(r)
}

type PostBody struct {
	Grabber
	memio.Buffer
}

func (p PostBody) Grab(r http.Request) string {
	r.Body = &p.Buffer
	r.Method = http.MethodPost
	r.ContentLength = int64(len(p.Buffer))
	return Headers{p.Grabber, map[string]Grabber{"Content-Type": Text{"application/x-www-form-urlencoded"}}}.Grab(r)
}

type Query struct {
	Grabber
	RawQuery Grabber
}

func (q Query) Grab(r http.Request) string {
	oldQuery := r.URL.RawQuery
	r.URL.RawQuery = q.RawQuery.Grab(r)
	str := q.Grabber.Grab(r)
	r.URL.RawPath = oldQuery
	return str
}
