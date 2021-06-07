package main

import (
	"context"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/dgrijalva/jwt-go"
	"github.com/matelang/jwt-go-aws-kms/v2/jwtkms"
)

const keyID = "aa2f90bf-f09f-42b7-b4f3-2083bd00f9ad"

func main() {
	awsCfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion("eu-central-1"))
	if err != nil {
		panic(err)
	}

	kmsConfig := &jwtkms.Config{
		KMSClient: kms.NewFromConfig(awsCfg),
		KMSKeyID:  keyID,
	}

	now := time.Now()
	jwtToken := jwt.NewWithClaims(jwtkms.SigningMethodKmsEcdsa256, &jwt.StandardClaims{
		Audience:  "api.example.com",
		ExpiresAt: now.Add(1 * time.Hour * 24).Unix(),
		Id:        "1234-5678",
		IssuedAt:  now.Unix(),
		Issuer:    "sso.example.com",
		NotBefore: now.Unix(),
		Subject:   "john.doe@example.com",
	})

	str, err := jwtToken.SignedString(kmsConfig)

	if err != nil {
		log.Fatalf("can not sign JWT %s", err)
	}
	log.Printf("Signed JWT %s\n", str)

	claims := jwt.StandardClaims{}

	_, err = jwt.ParseWithClaims(str, &claims, func(token *jwt.Token) (interface{}, error) {
		return kmsConfig, nil
	})
	if err != nil {
		log.Fatalf("can not parse/verify token %s", err)
	}

	log.Printf("Parsed and validated token with claims %v", claims)
}
