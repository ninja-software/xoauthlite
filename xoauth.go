package xoauthexample

import (
	"net/url"
	"time"
)

type OidcClient struct {
	Authority    string
	Alias        string
	GrantType    string
	ClientID     string
	ClientSecret string
	CreatedDate  time.Time
	Scopes       []string
	RedirectURL  *url.URL
}
