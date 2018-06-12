package main

import (
	"net/http"
	"time"
)

type Sleep struct {
	time.Duration
}

func (s Sleep) Grab(http.Request) string {
	time.Sleep(s.Duration)
	return ""
}
