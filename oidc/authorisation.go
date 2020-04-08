package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type TokenResultSet struct {
	AccessToken   string `json:"access_token"`
	IdentityToken string `json:"id_token"`
	RefreshToken  string `json:"refresh_token"`
	TokenType     string `json:"token_type"`
	ExpiresIn     int    `json:"expires_in"`
	ExpiresAt     int64  `json:"expires_at"`
}

type AccessTokenResultSet struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	ExpiresAt   int64  `json:"expires_at"`
}

func BuildCodeAuthorisationRequest(configuration WellKnownConfiguration, clientID string, redirectURI string, scopes []string, state string, codeChallenge string) string {
	urlToBuild, urlErr := url.Parse(configuration.AuthorisationEndpoint)
	if urlErr != nil {
		log.Fatal(urlErr)
	}

	scope := strings.Join(scopes, " ")

	q := url.Values{}
	q.Add("response_type", "code")
	q.Add("response_mode", "query")
	q.Add("client_id", clientID)
	q.Add("redirect_uri", redirectURI)
	q.Add("scope", scope)
	q.Add("state", state)

	if codeChallenge != "" {
		q.Add("code_challenge", codeChallenge)
		q.Add("code_challenge_method", "S256")
	}

	urlToBuild.RawQuery = q.Encode()

	return urlToBuild.String()
}

type AuthorisationResponse struct {
	Code  string
	State string
}

func ValidateAuthorisationResponse(url *url.URL, state string) (AuthorisationResponse, error) {
	var response AuthorisationResponse
	var query = url.Query()
	var code = query.Get("code")
	var stateFromQuery = query.Get("state")

	if stateFromQuery != state {
		return response, errors.New(`oidc Error: state parameters don't match`)
	}

	if code == "" {
		return response, errors.New(`oidc Error: no code in OIDC response`)
	}

	response = AuthorisationResponse{
		Code:  code,
		State: state,
	}

	return response, nil
}

func FormPost(tokenEndpoint string, clientID string, clientSecret string, formData url.Values, result interface{}) error {
	client := &http.Client{}

	encoded := formData.Encode()
	request, requestBuildErr := http.NewRequest("POST", tokenEndpoint, strings.NewReader(encoded))
	if requestBuildErr != nil {
		return requestBuildErr
	}

	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	if clientSecret != "" {
		request.SetBasicAuth(clientID, clientSecret)
	}

	request.Header.Add("Content-Length", strconv.Itoa(len(encoded)))

	response, responseErr := client.Do(request)
	if responseErr != nil {
		return fmt.Errorf("Error POSTing code %w", responseErr)
	}

	decoder := json.NewDecoder(response.Body)

	if response.StatusCode != 200 {
		var errorResult interface{}
		todoErr := decoder.Decode(&errorResult)
		if todoErr != nil {
			return fmt.Errorf("received error from code endpoint, but unable to deserialise error message. statusCode: %d", response.StatusCode)
		}

		errorBody, errorBodyError := json.MarshalIndent(errorResult, "", " ")
		if errorBodyError != nil {
			return errorBodyError
		}

		return fmt.Errorf("received error from code endpoint. statusCode: %d, body: %s",
			response.StatusCode,
			string(errorBody))
	}

	decodeErr := decoder.Decode(&result)
	if decodeErr != nil {
		return fmt.Errorf("failed to decode JSON %w", decodeErr)
	}

	return nil
}

func ExchangeCodeForToken(tokenEndpoint string, code string, clientID string, clientSecret string, codeVerifier string, redirectURI string) (TokenResultSet, error) {
	var result TokenResultSet

	formData := url.Values{
		"code":         {code},
		"grant_type":   {"authorization_code"},
		"redirect_uri": {redirectURI},
	}

	// https://tools.ietf.org/html/rfc6749#section-4.1.3
	if codeVerifier != "" {
		formData.Add("code_verifier", codeVerifier)
	}

	// https://tools.ietf.org/html/rfc6749#section-4.1.3
	if clientSecret == "" {
		formData.Add("client_id", clientID)
	}

	var postError = FormPost(tokenEndpoint, clientID, clientSecret, formData, &result)
	if postError != nil {
		return result, postError
	}

	result.ExpiresAt = AbsoluteExpiry(time.Now(), result.ExpiresIn)

	return result, nil
}

func RequestWithClientCredentials(tokenEndpoint string, clientID string, clientSecret string, scope string) (AccessTokenResultSet, error) {
	var result AccessTokenResultSet

	formData := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {scope},
	}

	var postError = FormPost(tokenEndpoint, clientID, clientSecret, formData, &result)
	if postError != nil {
		return result, postError
	}

	result.ExpiresAt = AbsoluteExpiry(time.Now(), result.ExpiresIn)

	return result, nil
}

func AbsoluteExpiry(now time.Time, expiresIn int) int64 {
	// ExpiresIn returns expiry time in seconds
	var future = now.Add(time.Second * time.Duration(expiresIn))
	// Subtract a minute to account for clock skew etc
	future.Add(time.Minute * time.Duration(-1))
	return future.Unix()
}
