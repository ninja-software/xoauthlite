package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/ninja-software/xoauthlite"
	"github.com/ninja-software/xoauthlite/oidc"
)

var gViewModel *xoauthlite.TokenResultViewModel

// manually setup http server and get token

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
		log.Fatal(wellKnownErr)
	}

	// not used
	codeChallenge := ""
	codeVerifier := ""

	// build browser link
	state, stateErr := oidc.GenerateRandomStringURLSafe(24)
	if stateErr != nil {
		log.Fatal(stateErr)
	}
	authorisationURL, err := oidc.BuildCodeAuthorisationRequest(
		*wellKnownConfig,
		clientConfig.ClientID,
		clientConfig.RedirectURL.String(),
		clientConfig.Scopes,
		state,
		codeChallenge,
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Open browser to", authorisationURL)

	// setup http server
	m := http.NewServeMux()
	s := http.Server{
		Addr:    fmt.Sprintf(":%s", u.Port()),
		Handler: m,
	}
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	// Open a web server to receive the redirect
	m.HandleFunc("/callback", handler(clientConfig, wellKnownConfig, codeVerifier, state, cancel))

	go func() {
		if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Println(err)
		}
	}()

	select {
	case <-ctx.Done():
		// Shutdown the server when the context is canceled
		err := s.Shutdown(ctx)
		if err != nil {
			log.Println(err)
		}
	}

	// prepare to print to screen
	viewModel := *gViewModel
	viewModel.Claims = nil
	jsonData, jsonErr := json.MarshalIndent(viewModel, "", "    ")
	if jsonErr != nil {
		log.Println("failed to parse to json format")
		cancel()
		return
	}
	fmt.Println(string(jsonData))
}

func handler(cc *xoauthlite.OidcClient, wellKnownConfig *oidc.WellKnownConfiguration, codeVerifier, state string, cancel context.CancelFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		var authorisationResponse, err = oidc.ValidateAuthorisationResponse(r.URL, state)
		if err != nil {
			log.Println(err)
			cancel()
			return
		}

		gViewModel, err = xoauthlite.VerifyCode(cc.ClientID, cc.ClientSecret, cc.RedirectURL.String(), *wellKnownConfig, codeVerifier, authorisationResponse.Code)
		if err != nil {
			log.Println(err)
			cancel()
			return
		}

		w.Write([]byte("{\"status\": \"success\"}"))
		cancel()
	}
}
