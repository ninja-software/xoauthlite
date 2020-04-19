package oidc

import (
	"net/url"
)

// reference:
// https://developer.xero.com/documentation/oauth2/auth-flow

// RefreshResult parse result of refreshed Token
type RefreshResult struct {
	IDToken      string `json:"id_token"`      // only exist if scope contains openid
	AccessToken  string `json:"access_token"`  // token that has the expiry extended
	ExpiresIn    int    `json:"expires_in"`    // new access token expiry time
	RefreshToken string `json:"refresh_token"` // next single use refresh token
	TokenType    string `json:"token_type"`    // access token's type. xero sends "Bearer"
	Scope        string `json:"scope"`         // series of scope the token is allowed, space seperated
}

// RefreshToken refresh provided token to extend expiry time
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

	var postError = formPost(metadata.TokenEndpoint, clientID, clientSecret, formData, &result)
	if postError != nil {
		return result, postError
	}

	return result, nil
}
