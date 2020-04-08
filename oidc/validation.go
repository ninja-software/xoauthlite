package oidc

import (
	"errors"
	"fmt"
	"log"

	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
)

func lookUpKey(keyID string, keys *jwk.Set) (interface{}, error) {

	if key := keys.LookupKeyID(keyID); len(key) == 1 {
		return key[0].Materialize()
	}

	return nil, fmt.Errorf("unable to find key with id %s", keyID)
}

func getKeyValidatorFunc(keys *jwk.Set) func(token *jwt.Token) (interface{}, error) {
	return func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		keyID, keyOk := token.Header["kid"].(string)
		if !keyOk {
			return nil, errors.New("unable to parse `kid` as string")
		}

		var rsaPubKey, keyLookupErr = lookUpKey(keyID, keys)
		if keyLookupErr != nil {
			return nil, fmt.Errorf("couldn't find key with id: %s", keyID)
		}

		log.Printf("Using public key: %s", keyID)

		return rsaPubKey, nil
	}
}

// ValidateToken validates token and make sure it is not fake or manipulated
func ValidateToken(tokenString string, configuration WellKnownConfiguration) (interface{}, error) {
	keys, jwksError := jwk.FetchHTTP(configuration.JwksURI)
	if jwksError != nil {
		return nil, errors.New("expecting JWT header to have string kid")
	}

	token, tokenErr := jwt.Parse(tokenString, getKeyValidatorFunc(keys))
	if tokenErr != nil {
		return nil, tokenErr
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("failed to parse claims from JWT")
	}
	if !token.Valid {
		return nil, errors.New("the JWT was invalid")
	}

	return claims, nil
}
