package oidc

import (
	"net/url"
)

type RefreshResult struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

func RefreshToken(authority string, clientID string, clientSecret string, refreshToken string) (RefreshResult, error) {
	var result RefreshResult

	var metadata, metadataErr = GetMetadata(authority)
	if metadataErr != nil {
		return result, metadataErr
	}

	echo("Exchanging refresh_token at token endpoint: %s", metadata.TokenEndpoint)

	formData := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}

	var postError = FormPost(metadata.TokenEndpoint, clientID, clientSecret, formData, &result)
	if postError != nil {
		return result, postError
	}

	return result, nil
}
