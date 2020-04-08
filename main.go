package main

import (
	"os"
	"time"

	"github.com/ninja-software/xoauth-example/oidc"
)

// // Scopes: OAuth 2.0 scopes provide a way to limit the amount of access that is granted to an access token.
// var xeroOauthConfig = &oauth2.Config{
// 	RedirectURL:  "http://localhost:5000/oauth/xero/callback",
// 	ClientID:     os.Getenv("XERO_CLIENT_ID"),
// 	ClientSecret: os.Getenv("XERO_CLIENT_SECRET"),
// 	Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
// 	Endpoint:     google.Endpoint,
// }

type OidcClient struct {
	Authority    string
	Alias        string
	GrantType    string
	ClientId     string
	ClientSecret string
	CreatedDate  time.Time
	Scopes       []string
}

var clientConfig *OidcClient = &OidcClient{
	Authority:    "https://identity.xero.com",
	ClientId:     os.Getenv("XERO_CLIENT_ID"),
	ClientSecret: os.Getenv("XERO_CLIENT_SECRET"),
	Scopes: []string{
		"openid",
		"profile",
		"email",
		"accounting.contacts",
		"accounting.transactions",
		"offline_access",
	},
}

// func Handler() http.Handler {
// 	mux := http.NewServeMux()
// 	// Root
// 	mux.Handle("/", showLogin)

// 	// OauthXero
// 	mux.HandleFunc("/auth/xero/login", oauthXeroLogin)
// 	mux.HandleFunc("/auth/xero/callback", handleOidcCallback)

// 	return mux
// }

func main() {
	// // We create a simple server using http.Server and run.
	// server := &http.Server{
	// 	Addr:    ":5000",
	// 	Handler: Handler(),
	// }

	// log.Printf("Starting HTTP Server. Listening at %q", server.Addr)
	// if err := server.ListenAndServe(); err != http.ErrServerClosed {
	// 	log.Printf("%v", err)
	// } else {
	// 	log.Println("Server closed!")
	// }

	var wellKnownConfig, wellKnownErr = oidc.GetMetadata(clientConfig.Authority)
	if wellKnownErr != nil {
		panic(wellKnownErr)
	}

	dryRun := false
	localHostPort := 8080

	Request(wellKnownConfig, *clientConfig, dryRun, localHostPort)
}
