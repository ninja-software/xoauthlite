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

// manually setup http server and get token

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

		viewModel, err := xoauthlite.VerifyCode(cc.ClientID, cc.ClientSecret, cc.RedirectURL.String(), *wellKnownConfig, codeVerifier, authorisationResponse.Code)
		if err != nil {
			log.Println(err)
			cancel()
			return
		}

		// prepare to print to screen
		viewModel2 := *viewModel
		viewModel2.Claims = nil
		jsonData, jsonErr := json.MarshalIndent(viewModel2, "", "    ")
		if jsonErr != nil {
			log.Println("failed to parse to json format")
			cancel()
			return
		}

		fmt.Println(string(jsonData))
		w.Write([]byte("{\"status\": \"success\"}"))
		cancel()
	}
}
