package oidc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// WellKnownPath Xero public path holding OpenID configuration
const WellKnownPath = "/.well-known/openid-configuration"

// GetSchemeAndHost extract only scheme and host
func GetSchemeAndHost(urlString string) (string, error) {
	parsed, err := url.Parse(urlString)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host), nil
}

// WellKnownConfiguration struct to parse JSON OpenID configuration
type WellKnownConfiguration struct {
	AuthorisationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JwksURI               string `json:"jwks_uri"`
	Issuer                string `json:"issuer"`
}

// GetMetadata discover metadata and construct OpenID configuration
func GetMetadata(authority string) (WellKnownConfiguration, error) {
	var result WellKnownConfiguration

	var authorityBaseURL, parseErr = GetSchemeAndHost(authority)
	if parseErr != nil {
		return result, parseErr
	}

	var wellKnownURL = fmt.Sprintf("%s%s", authorityBaseURL, WellKnownPath)

	response, requestErr := http.Get(wellKnownURL)
	if requestErr != nil {
		return result, requestErr
	}

	if response.StatusCode != 200 {
		return result, fmt.Errorf("got %d when requesting %s", response.StatusCode, wellKnownURL)
	}

	decoder := json.NewDecoder(response.Body)
	decodeErr := decoder.Decode(&result)
	if decodeErr != nil {
		return result, decodeErr
	}

	if result.TokenEndpoint == "" {
		return result, fmt.Errorf("no token endpoint in OIDC metadata")
	}

	if result.AuthorisationEndpoint == "" {
		return result, fmt.Errorf("no authorisation endpoint in OIDC metadata")
	}

	return result, nil
}
