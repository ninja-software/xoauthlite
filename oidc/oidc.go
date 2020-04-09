package oidc

import "log"

// Debug decides if echo should print message on console
var Debug = false

func echo(format string, in ...interface{}) {
	if !Debug {
		return
	}
	log.Printf(format, in...)
}

// DefaultAuthority default Xero authority server url
const DefaultAuthority = "https://identity.xero.com"

// DefaultScopes default Xero oauth2 scopes
var DefaultScopes []string = []string{
	"openid",
	"profile",
	"email",
	"offline_access",
}
