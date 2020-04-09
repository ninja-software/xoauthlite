package xoauthlite

import (
	"log"
	"net/url"
	"time"
)

// OidcClient holds detail of oauth connection client
type OidcClient struct {
	Alias        string
	Authority    string
	ClientID     string
	ClientSecret string
	CreatedDate  time.Time
	Scopes       []string
	RedirectURL  *url.URL
}

// Debug decides if echo should print message on console
var Debug = false

func echo(in ...interface{}) {
	if !Debug {
		return
	}
	log.Println(in...)
}
