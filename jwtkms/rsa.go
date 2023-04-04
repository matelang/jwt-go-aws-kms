package jwtkms

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

var rsaPubKeyCheckerFunc = func(cfg interface{}) bool {
	_, isBuiltInRSA := cfg.(*rsa.PublicKey)
	return isBuiltInRSA
}

var rsaPKCS1LocalVerificationFunc = func(hash crypto.Hash) func(cfg *Config, hashedSigningString []byte, sig []byte) error {
	return func(cfg *Config, hashedSigningString []byte, sig []byte) error {
		var rsaPublicKey *rsa.PublicKey

		cachedKey := pubkeyCache.Get(cfg.kmsKeyID)
		if cachedKey == nil {
			getPubKeyOutput, err := cfg.kmsClient.GetPublicKey(cfg.ctx, &kms.GetPublicKeyInput{
				KeyId: aws.String(cfg.kmsKeyID),
			})
			if err != nil {
				return err
			}

			cachedKey, err = x509.ParsePKIXPublicKey(getPubKeyOutput.PublicKey)
			if err != nil {
				return err
			}

			pubkeyCache.Add(cfg.kmsKeyID, cachedKey)
		}

		rsaPublicKey, ok := cachedKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("invalid key type for key")
		}

		return rsa.VerifyPKCS1v15(rsaPublicKey, hash, hashedSigningString, sig)
	}
}

var rsaPSSLocalVerificationFunc = func(hash crypto.Hash, opts *rsa.PSSOptions) func(cfg *Config, hashedSigningString []byte, sig []byte) error {
	return func(cfg *Config, hashedSigningString []byte, sig []byte) error {
		var rsaPublicKey *rsa.PublicKey

		cachedKey := pubkeyCache.Get(cfg.kmsKeyID)
		if cachedKey == nil {
			getPubKeyOutput, err := cfg.kmsClient.GetPublicKey(cfg.ctx, &kms.GetPublicKeyInput{
				KeyId: aws.String(cfg.kmsKeyID),
			})
			if err != nil {
				return fmt.Errorf("getting public key: %w", err)
			}

			cachedKey, err = x509.ParsePKIXPublicKey(getPubKeyOutput.PublicKey)
			if err != nil {
				return fmt.Errorf("parsing public key: %w", err)
			}

			pubkeyCache.Add(cfg.kmsKeyID, cachedKey)
		}

		rsaPublicKey, ok := cachedKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("invalid key type for key")
		}

		if err := rsa.VerifyPSS(rsaPublicKey, hash, hashedSigningString, sig, opts); err != nil {
			return fmt.Errorf("verifying signature locally: %w", err)
		}

		return nil
	}
}
