# AWS KMS adapter for dgrijalva/jwt-go library

This library provides an AWS KMS(Key Management Service) adapter to be used with the popular GoLang JWT library 
[dgrijalva/jwt-go](https://github.com/dgrijalva/jwt-go).

It will *Sign* a JWT token using an assymetric key stored in AWS KMS.

Verification can be done both using KMS *Verify* method or locally with a cached public key (default). 

## Special thanks
Shouting out to:

* [dgrijalva](https://github.com/dgrijalva)
    
  for the easy to extend GoLang JWT Library
  
* [Mikael Gidmark](https://stackoverflow.com/users/300598/mikael-gidmark)
  
  AWS KMS ECC returns the signature in DER-encoded object as defined by ANS X9.62–2005 as mentioned [here](https://stackoverflow.com/a/66205185/8195214)

* [codelittinc](https://github.com/codelittinc)
  
  for their DER to (R,S) and (R,S) to DER methods found [here](https://github.com/codelittinc/gobitauth/blob/master/sign.go#L70)
