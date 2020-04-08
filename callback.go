package xoauthlite

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/ninja-software/xoauthlite/oidc"
)

// renderAndLogError prints the error message to the browser, then shut down the web server gracefully
func renderAndLogError(w http.ResponseWriter, cancelFunc context.CancelFunc, errorMessage string) {
	_, streamErr := fmt.Fprintf(w, errorMessage)
	if streamErr != nil {
		log.Printf("Failed to write to stream %v\n", streamErr)
	}

	echo(errorMessage)

	cancelFunc()
}

// handleOidcCallback waits for the OIDC server to redirect to our listening web server
// It exchanges the `code` for a token set. If successful, the token set is logged to StdOut,
// and the web server is shut down gracefully
func handleOidcCallback(
	w http.ResponseWriter,
	r *http.Request,
	clientName string,
	clientID string,
	clientSecret string,
	redirectURI string,
	wellKnownConfig oidc.WellKnownConfiguration,
	state string,
	codeVerifier string,
	cancel context.CancelFunc,
) {
	var authorisationResponse, err = oidc.ValidateAuthorisationResponse(r.URL, state)
	if err != nil {
		renderAndLogError(w, cancel, fmt.Sprintf("%v", err))
		return
	}

	echo("Received OIDC response")
	var result, codeExchangeErr = oidc.ExchangeCodeForToken(wellKnownConfig.TokenEndpoint, authorisationResponse.Code, clientID, clientSecret, codeVerifier, redirectURI)
	if codeExchangeErr != nil {
		renderAndLogError(w, cancel, fmt.Sprintf("%v", codeExchangeErr))
		return
	}

	echo("Validating token")
	var claims, validateErr = oidc.ValidateToken(result.IdentityToken, wellKnownConfig)
	if validateErr != nil {
		renderAndLogError(w, cancel, fmt.Sprintf("%v", validateErr))
		return
	}

	// show webpage
	t := template.New("credentials")
	_, parseErr := t.Parse(TokenResultView())
	if parseErr != nil {
		renderAndLogError(w, cancel, fmt.Sprintf("%v", parseErr))
		return
	}
	var viewModel = TokenResultViewModel{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		IDToken:      result.IdentityToken,
		Claims:       claims,
		Authority:    wellKnownConfig.Issuer,
	}
	tplErr := t.Execute(w, viewModel)
	if tplErr != nil {
		renderAndLogError(w, cancel, fmt.Sprintf("%v", tplErr))
		return
	}

	cancel()
}
