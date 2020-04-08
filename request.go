package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/ninja-software/xoauth-example/oidc"
)

func request(wellKnownConfig oidc.WellKnownConfiguration, client OidcClient, codeVerifier string, codeChallenge string, dryRun bool, localHostPort int) {
	redirectUri := fmt.Sprintf("http://localhost:%d/callback", localHostPort)
	state, stateErr := oidc.GenerateRandomStringURLSafe(24)
	if stateErr != nil {
		panic("failed to generate random state. Check that your OS has a crypto implementation available")
	}

	authorisationUrl := oidc.BuildCodeAuthorisationRequest(
		wellKnownConfig,
		client.ClientId,
		redirectUri,
		client.Scopes,
		state,
		codeChallenge,
	)

	if dryRun {
		fmt.Println("Dry run, authorisation request URL", authorisationUrl)
		return
	}

	m := http.NewServeMux()
	s := http.Server{
		Addr:    fmt.Sprintf(":%d", localHostPort),
		Handler: m,
	}
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	// Open a web server to receive the redirect
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleOidcCallback(w, r,
			client.Alias,
			client.ClientId,
			client.ClientSecret,
			redirectUri,
			wellKnownConfig,
			state,
			codeVerifier,
			cancel,
		)
	})

	fmt.Println("Open browser to", authorisationUrl)

	go func() {
		if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	select {
	case <-ctx.Done():
		// Shutdown the server when the context is canceled
		err := s.Shutdown(ctx)
		if err != nil {
			log.Fatalln(err)
		}
	}
}

func Request(wellKnownConfig oidc.WellKnownConfiguration, client OidcClient, dryRun bool, localHostPort int) {
	request(wellKnownConfig, client, "", "", dryRun, localHostPort)
}
