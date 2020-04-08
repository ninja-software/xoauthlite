package main

import (
	"encoding/json"
	"log"
	"time"

	"github.com/ninja-software/xoauth-example/oidc"
)

func Refresh(tokenSet oidc.TokenResultSet) (oidc.TokenResultSet, error) {
	if tokenSet.RefreshToken == "" {
		log.Fatalln("No refresh token is present in the saved credentials - unable to perform a refresh")
	}

	refreshResult, refreshErr := oidc.RefreshToken(clientConfig.Authority,
		clientConfig.ClientId,
		clientConfig.ClientSecret,
		tokenSet.RefreshToken,
	)
	if refreshErr != nil {
		return tokenSet, refreshErr
	}

	tokenSet.RefreshToken = refreshResult.RefreshToken
	tokenSet.AccessToken = refreshResult.AccessToken
	tokenSet.ExpiresIn = refreshResult.ExpiresIn
	tokenSet.ExpiresAt = oidc.AbsoluteExpiry(time.Now(), refreshResult.ExpiresIn)

	var serialised, marshalErr = json.MarshalIndent(tokenSet, "", " ")
	if marshalErr != nil {
		return tokenSet, marshalErr
	}

	log.Println("token", string(serialised))

	return tokenSet, nil
}
