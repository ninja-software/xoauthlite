package main

import (
	"fmt"
	"log"
	"net/url"
	"os"

	"github.com/ninja-software/xoauthlite"
	"github.com/ninja-software/xoauthlite/oidc"
)

// quick and easy get token,
// auto start/stop http server

func main() {
	clientID := os.Getenv("XERO_CLIENT_ID")
	clientSecret := os.Getenv("XERO_CLIENT_SECRET")
	redirectURL := os.Getenv("XERO_REDIRECT_URL")
	if clientID == "" {
		log.Fatal(fmt.Errorf("empty client id"))
	}
	if clientSecret == "" {
		log.Fatal(fmt.Errorf("empty client secret"))
	}
	u, err := url.Parse(redirectURL)
	if err != nil {
		log.Fatal(err)
	}

	clientConfig := &xoauthlite.OidcClient{
		Authority:    oidc.DefaultAuthority,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       oidc.DefaultScopes,
		RedirectURL:  u,
	}

	var wellKnownConfig, wellKnownErr = oidc.GetMetadata(clientConfig.Authority)
	if wellKnownErr != nil {
		panic(wellKnownErr)
	}

	xoauthlite.Request(*wellKnownConfig, *clientConfig)
}
