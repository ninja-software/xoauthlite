package main

import (
	"log"
	"net/url"
	"os"

	"github.com/ninja-software/xoauthlite"
	"github.com/ninja-software/xoauthlite/oidc"
)

func main() {
	u, err := url.Parse("http://localhost:8080/callback")
	if err != nil {
		log.Fatal(err)
	}

	clientConfig := &xoauthlite.OidcClient{
		Authority:    "https://identity.xero.com",
		ClientID:     os.Getenv("XERO_CLIENT_ID"),
		ClientSecret: os.Getenv("XERO_CLIENT_SECRET"),
		Scopes: []string{
			"openid",
			"profile",
			"email",
			"accounting.contacts",
			"accounting.transactions",
			"offline_access",
		},
		RedirectURL: u,
	}

	var wellKnownConfig, wellKnownErr = oidc.GetMetadata(clientConfig.Authority)
	if wellKnownErr != nil {
		panic(wellKnownErr)
	}

	xoauthlite.Request(wellKnownConfig, *clientConfig)
}
