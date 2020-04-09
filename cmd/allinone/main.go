package main

import (
	"log"
	"net/url"
	"os"

	"github.com/ninja-software/xoauthlite"
	"github.com/ninja-software/xoauthlite/oidc"
)

// quick and easy get token,
// auto start/stop http server

func main() {
	u, err := url.Parse("http://localhost:8080/callback")
	if err != nil {
		log.Fatal(err)
	}

	clientConfig := &xoauthlite.OidcClient{
		Authority:    oidc.DefaultAuthority,
		ClientID:     os.Getenv("XERO_CLIENT_ID"),
		ClientSecret: os.Getenv("XERO_CLIENT_SECRET"),
		Scopes:       oidc.DefaultScopes,
		RedirectURL:  u,
	}

	var wellKnownConfig, wellKnownErr = oidc.GetMetadata(clientConfig.Authority)
	if wellKnownErr != nil {
		panic(wellKnownErr)
	}

	xoauthlite.Request(*wellKnownConfig, *clientConfig)
}
