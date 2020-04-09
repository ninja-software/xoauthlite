package xoauthlite

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/ninja-software/xoauthlite/oidc"
)

// Request starts callback server and request token
func Request(wellKnownConfig oidc.WellKnownConfiguration, client OidcClient) error {
	// from original code
	codeVerifier := ""
	codeChallenge := ""

	state, stateErr := oidc.GenerateRandomStringURLSafe(24)
	if stateErr != nil {
		return fmt.Errorf("failed to generate random state. Check that your OS has a crypto implementation available")
	}

	authorisationURL, err := oidc.BuildCodeAuthorisationRequest(
		wellKnownConfig,
		client.ClientID,
		client.RedirectURL.String(),
		client.Scopes,
		state,
		codeChallenge,
	)
	if err != nil {
		return fmt.Errorf("failed to build authorisation request %w", err)
	}

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

	return nil
}
