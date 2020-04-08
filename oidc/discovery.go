package oidc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

const WellKnownPath = "/.well-known/openid-configuration"

func GetSchemeAndHost(urlString string) (string, error) {
	parsed, err := url.Parse(urlString)

	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host), nil
}

type WellKnownConfiguration struct {
	AuthorisationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JwksUri               string `json:"jwks_uri"`
	Issuer                string `json:"issuer"`
}

func GetMetadata(authority string) (WellKnownConfiguration, error) {
	var authorityBaseUrl, parseErr = GetSchemeAndHost(authority)
	var result WellKnownConfiguration

	if parseErr != nil {
		return result, parseErr
	}

	var wellKnownUrl = fmt.Sprintf("%s%s", authorityBaseUrl, WellKnownPath)

	fmt.Printf("Requesting OIDC metadata from %s\n", wellKnownUrl)

	response, requestErr := http.Get(wellKnownUrl)
	if requestErr != nil {
		return result, requestErr
	}

	if response.StatusCode != 200 {
		return result, fmt.Errorf("got %d when requesting %s\n", response.StatusCode, wellKnownUrl)
	}

	decoder := json.NewDecoder(response.Body)
	decodeErr := decoder.Decode(&result)
	if decodeErr != nil {
		return result, decodeErr
	}

	fmt.Printf("Received OIDC metadata for authority: %s\n", result.Issuer)

	if result.TokenEndpoint == "" {
		return result, fmt.Errorf("no token endpoint in OIDC metadata")
	}

	if result.AuthorisationEndpoint == "" {
		return result, fmt.Errorf("no authorisation endpoint in OIDC metadata")
	}

	return result, nil
}
