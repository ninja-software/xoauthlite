package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/ninja-software/xoauth-example/oidc"
)

// renderAndLogError prints the error message to the browser, then shut down the web server gracefully
func renderAndLogError(w http.ResponseWriter, cancelFunc context.CancelFunc, errorMessage string) {
	_, streamErr := fmt.Fprintf(w, errorMessage)

	log.Printf(errorMessage)

	if streamErr != nil {
		log.Printf("Failed to write to stream %v\n", streamErr)
	}

	cancelFunc()
}

// handleOidcCallback waits for the OIDC server to redirect to our listening web server
// It exchanges the `code` for a token set. If successful, the token set is logged to StdOut,
// and the web server is shut down gracefully
func handleOidcCallback(
	w http.ResponseWriter,
	r *http.Request,
	clientName string,
	clientId string,
	clientSecret string,
	redirectUri string,
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

	log.Println("Received OIDC response")
	var result, codeExchangeErr = oidc.ExchangeCodeForToken(wellKnownConfig.TokenEndpoint, authorisationResponse.Code, clientId, clientSecret, codeVerifier, redirectUri)
	if codeExchangeErr != nil {
		renderAndLogError(w, cancel, fmt.Sprintf("%v", codeExchangeErr))
		return
	}

	log.Println("Validating token")
	var claims, validateErr = oidc.ValidateToken(result.IdentityToken, wellKnownConfig)
	if validateErr != nil {
		renderAndLogError(w, cancel, fmt.Sprintf("%v", validateErr))
		return
	}
	fmt.Printf("claims:\n%+v", claims)

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
		IdToken:      result.IdentityToken,
		Claims:       claims,
		Authority:    wellKnownConfig.Issuer,
	}
	tplErr := t.Execute(w, viewModel)
	if tplErr != nil {
		renderAndLogError(w, cancel, fmt.Sprintf("%v", tplErr))
		return
	}

	// echo json to console
	jsonData, jsonErr := json.MarshalIndent(result, "", "    ")
	if jsonErr != nil {
		renderAndLogError(w, cancel, fmt.Sprintf("%v", jsonErr))
		return
	}
	log.Print("Tokens", jsonData)

	cancel()
}
