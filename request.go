package xoauthexample

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/ninja-software/xoauth-example/oidc"
)

// Request starts callback server and request token
func Request(wellKnownConfig oidc.WellKnownConfiguration, client OidcClient) {
	// filler from original code
	codeVerifier := ""
	codeChallenge := ""

	state, stateErr := oidc.GenerateRandomStringURLSafe(24)
	if stateErr != nil {
		panic("failed to generate random state. Check that your OS has a crypto implementation available")
	}

	authorisationURL := oidc.BuildCodeAuthorisationRequest(
		wellKnownConfig,
		client.ClientID,
		client.RedirectURL.String(),
		client.Scopes,
		state,
		codeChallenge,
	)

	m := http.NewServeMux()
	s := http.Server{
		Addr:    fmt.Sprintf(":%s", client.RedirectURL.Port()),
		Handler: m,
	}
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	// Open a web server to receive the redirect
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleOidcCallback(w, r,
			client.Alias,
			client.ClientID,
			client.ClientSecret,
			client.RedirectURL.String(),
			wellKnownConfig,
			state,
			codeVerifier,
			cancel,
		)
	})

	fmt.Println("Open browser to", authorisationURL)

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
