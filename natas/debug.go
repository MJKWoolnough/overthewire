package main

import (
	"io"
	"log"
	"net/http"
	"os"

	"vimagination.zapto.org/memio"
)

type Debug struct {
	Grabber
	Prefix string
}

func (d Debug) Grab(r http.Request) string {
	var body io.ReadCloser
	if r.Body != nil {
		m := *r.Body.(*memio.Buffer)
		body = &m
	}
	r.Write(os.Stdout)
	if body != nil {
		r.Body = body
	}
	str := d.Grabber.Grab(r)
	log.Printf("%s: %s", d.Prefix, str)
	return str
}
