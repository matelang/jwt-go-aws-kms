package main

import (
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/dgrijalva/jwt-go"
	"github.com/matelang/jwt-go-aws-kms/v2/jwtkms"
	"log"
	"time"
)

const keyId = "bc1891a3-aa0e-4115-a432-2083bd00f9ad"

func main() {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))
	svc := kms.New(sess)

	keyConfig := &jwtkms.KmsConfig{
		Svc:      svc,
		KmsKeyId: keyId,
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

	str, err := jwtToken.SignedString(keyConfig)

	if err != nil {
		log.Fatalf("can not sign JWT %s", err)
	}
	log.Printf("Signed JWT %s\n", str)

	claims := jwt.StandardClaims{}
	_, err = jwt.ParseWithClaims(str, &claims, func(token *jwt.Token) (interface{}, error) {
		return keyConfig, nil
	})
	if err != nil {
		log.Fatalf("can not parse/verify token %s", err)
	}
	log.Printf("Parsed and validated token with claims %v", claims)
}
