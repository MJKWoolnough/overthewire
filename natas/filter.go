package main

import (
	"net/http"
	"strings"

	"github.com/MJKWoolnough/errors"
	xmlpath "gopkg.in/xmlpath.v2"
)

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
