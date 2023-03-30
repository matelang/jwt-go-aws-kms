package main

import (
	"context"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/golang-jwt/jwt/v5"
	"github.com/matelang/jwt-go-aws-kms/v2/jwtkms"
)

const keyID = "aa2f90bf-f09f-42b7-b4f3-2083bd00f9ad"

func main() {
	awsCfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion("eu-central-1"))
	if err != nil {
		panic(err)
	}

	now := time.Now()
	jwtToken := jwt.NewWithClaims(jwtkms.SigningMethodECDSA256, &jwt.RegisteredClaims{
		Audience:  jwt.ClaimStrings{"api.example.com"},
		ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour * 24)),
		ID:        "1234-5678",
		IssuedAt:  jwt.NewNumericDate(now),
		Issuer:    "sso.example.com",
		NotBefore: jwt.NewNumericDate(now),
		Subject:   "john.doe@example.com",
	})

	kmsConfig := jwtkms.NewKMSConfig(kms.NewFromConfig(awsCfg), keyID, false)

	str, err := jwtToken.SignedString(kmsConfig.WithContext(context.Background()))
	if err != nil {
		log.Fatalf("can not sign JWT %s", err)
	}

	log.Printf("Signed JWT %s\n", str)

	claims := jwt.RegisteredClaims{}

	_, err = jwt.ParseWithClaims(str, &claims, func(token *jwt.Token) (interface{}, error) {
		return kmsConfig, nil
	})
	if err != nil {
		log.Fatalf("can not parse/verify token %s", err)
	}

	log.Printf("Parsed and validated token with claims %v", claims)
}
