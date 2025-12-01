package util

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"strings"
	"time"
)

type CodexClaim struct {
	Aud                   []string `json:"aud"`
	ClientId              string   `json:"client_id"`
	Exp                   int64    `json:"exp"`
	HttpsApiOpenaiComAuth struct {
		ChatgptAccountId        string `json:"chatgpt_account_id"`
		ChatgptAccountUserId    string `json:"chatgpt_account_user_id"`
		ChatgptComputeResidency string `json:"chatgpt_compute_residency"`
		ChatgptPlanType         string `json:"chatgpt_plan_type"`
		ChatgptUserId           string `json:"chatgpt_user_id"`
		UserId                  string `json:"user_id"`
	} `json:"https://api.openai.com/auth"`
	HttpsApiOpenaiComProfile struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	} `json:"https://api.openai.com/profile"`
	Iat         int64    `json:"iat"`
	Iss         string   `json:"iss"`
	Jti         string   `json:"jti"`
	Nbf         int64    `json:"nbf"`
	PwdAuthTime int64    `json:"pwd_auth_time"`
	Scp         []string `json:"scp"`
	SessionId   string   `json:"session_id"`
	Sub         string   `json:"sub"`
}

// Validates time based claims "exp, iat, nbf".
// There is no accounting for clock skew.
// As well, if any of the above claims are not in the token, it will still
// be considered a valid claim.
func (c CodexClaim) Valid() error {
	vErr := new(jwt.ValidationError)
	now := jwt.TimeFunc().Unix()
	now += 10000
	// The claims below are optional, by default, so if they are set to the
	// default value in Go, let's not fail the verification for them.
	if !c.VerifyExpiresAt(now, false) {
		delta := time.Unix(now, 0).Sub(time.Unix(int64(c.Exp), 0))
		vErr.Inner = fmt.Errorf("token is expired by %v", delta)
		vErr.Errors |= jwt.ValidationErrorExpired
	}

	if !c.VerifyIssuedAt(now, false) {
		vErr.Inner = fmt.Errorf("Token used before issued")
		vErr.Errors |= jwt.ValidationErrorIssuedAt
	}

	if !c.VerifyNotBefore(now, false) {
		vErr.Inner = fmt.Errorf("token is not valid yet")
		vErr.Errors |= jwt.ValidationErrorNotValidYet
	}

	if vErr.Errors == 0 {
		return nil
	}

	return vErr
}

// Compares the aud claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *CodexClaim) VerifyAudience(cmp string, req bool) bool {
	return verifyAud(c.Aud, cmp, req)
}

// Compares the exp claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *CodexClaim) VerifyExpiresAt(cmp int64, req bool) bool {
	return verifyExp(int64(c.Exp), cmp, req)
}

// Compares the iat claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *CodexClaim) VerifyIssuedAt(cmp int64, req bool) bool {
	return verifyIat(int64(c.Iat), cmp, req)
}

// Compares the iss claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *CodexClaim) VerifyIssuer(cmp string, req bool) bool {
	return verifyIss(c.Iss, cmp, req)
}

// Compares the nbf claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *CodexClaim) VerifyNotBefore(cmp int64, req bool) bool {
	return true
}

type OpenaiClaim struct {
	HttpsApiOpenaiComProfile struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	} `json:"https://api.openai.com/profile,omitempty"`
	HttpsApiOpenaiComAuth struct {
		Poid   string `json:"poid"`
		UserId string `json:"user_id"`
	} `json:"https://api.openai.com/auth,omitempty"`
	Iss   string   `json:"iss,omitempty"`
	Sub   string   `json:"sub,omitempty"`
	Aud   []string `json:"aud,omitempty"`
	Iat   int64    `json:"iat,omitempty"`
	Exp   int64    `json:"exp,omitempty"`
	Azp   string   `json:"azp,omitempty"`
	Scope string   `json:"scope,omitempty"`
}

// Validates time based claims "exp, iat, nbf".
// There is no accounting for clock skew.
// As well, if any of the above claims are not in the token, it will still
// be considered a valid claim.
func (c OpenaiClaim) Valid() error {
	vErr := new(jwt.ValidationError)
	now := jwt.TimeFunc().Unix()
	now += 10000
	// The claims below are optional, by default, so if they are set to the
	// default value in Go, let's not fail the verification for them.
	if !c.VerifyExpiresAt(now, false) {
		delta := time.Unix(now, 0).Sub(time.Unix(c.Exp, 0))
		vErr.Inner = fmt.Errorf("token is expired by %v", delta)
		vErr.Errors |= jwt.ValidationErrorExpired
	}

	if !c.VerifyIssuedAt(now, false) {
		vErr.Inner = fmt.Errorf("Token used before issued")
		vErr.Errors |= jwt.ValidationErrorIssuedAt
	}

	if !c.VerifyNotBefore(now, false) {
		vErr.Inner = fmt.Errorf("token is not valid yet")
		vErr.Errors |= jwt.ValidationErrorNotValidYet
	}

	if vErr.Errors == 0 {
		return nil
	}

	return vErr
}

// Compares the aud claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *OpenaiClaim) VerifyAudience(cmp string, req bool) bool {
	return verifyAud(c.Aud, cmp, req)
}

// Compares the exp claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *OpenaiClaim) VerifyExpiresAt(cmp int64, req bool) bool {
	return verifyExp(c.Exp, cmp, req)
}

// Compares the iat claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *OpenaiClaim) VerifyIssuedAt(cmp int64, req bool) bool {
	return verifyIat(c.Iat, cmp, req)
}

// Compares the iss claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *OpenaiClaim) VerifyIssuer(cmp string, req bool) bool {
	return verifyIss(c.Iss, cmp, req)
}

// Compares the nbf claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *OpenaiClaim) VerifyNotBefore(cmp int64, req bool) bool {
	return true
}

func verifyAud(aud []string, cmp string, required bool) bool {
	if len(aud) == 0 {
		return !required
	}
	// use a var here to keep constant time compare when looping over a number of claims
	result := false

	var stringClaims string
	for _, a := range aud {
		if subtle.ConstantTimeCompare([]byte(a), []byte(cmp)) != 0 {
			result = true
		}
		stringClaims = stringClaims + a
	}

	// case where "" is sent in one or many aud claims
	if len(stringClaims) == 0 {
		return !required
	}

	return result
}

func verifyExp(exp int64, now int64, required bool) bool {
	if exp == 0 {
		return !required
	}
	return now <= exp
}

func verifyIat(iat int64, now int64, required bool) bool {
	if iat == 0 {
		return !required
	}
	return now >= iat
}

func verifyIss(iss string, cmp string, required bool) bool {
	if iss == "" {
		return !required
	}
	if subtle.ConstantTimeCompare([]byte(iss), []byte(cmp)) != 0 {
		return true
	} else {
		return false
	}
}

func verifyNbf(nbf int64, now int64, required bool) bool {
	if nbf == 0 {
		return !required
	}
	return now >= nbf
}

// CheckToken checks the JWT token against the provided public key and algorithm
//func CheckToken(tokenString string) (*jwt.Token, error) {
//	// Read the public key
//	pubKeyData := []byte(`-----BEGIN PUBLIC KEY-----
//MIIC+zCCAeOgAwIBAgIJLlfMWYK8snRdMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAM
//TEG9wZW5haS5hdXRoMC5jb20wHhcNMjAwMjExMDUyMjI5WhcNMzMxMDIwMDUyMjI5Wj
//AbMRkwFwYDVQQDExBvcGVuYWkuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCA
//Q8AMIIBCgKCAQEA27rOErDOPvPc3mOADYtQBeenQm5NS5VHVaoO/Zmgsf1M0Wa/2WgL
//m9jX65Ru/K8Az2f4MOdpBxxLL686ZS+K7eJC/oOnrxCRzFYBqQbYo+JMeqNkrCn34ye
//d4XkX4ttoHi7MwCEpVfb05Qf/ZAmNI1XjecFYTyZQFrd9LjkX6lr05zY6aM/+MCBNeB
//Wp35pLLKhiq9AieB1wbDPcGnqxlXuU/bLgIyqUltqLkr9JHsf/2T4VrXXNyNeQyBq5w
//jYlRkpBQDDDNOcdGpx1buRrZ2hFyYuXDRrMcR6BQGC0ur9hI5obRYlchDFhlb0ElsJ2
//bshDDGRk5k3doHqbhj2IgQIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQ
//WBBSzpMyU3UZWR9zdv+ckg/L6GZCcJDAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQ
//ELBQADggEBAEuUscoo1BZmCUZG8TEki0NHFjv08u2SHdcMU1xR0PfyKY6h+pLrSrGq8
//kYfjCHb/OPt0+Han0fiGRTnKurQ/u1leuJ7qHVHRILmP3e1MC8PUELjHpBo3f38Kk6U
//lbR5pbL5K7ZHeEO6CLNTOg54xLY/6e2ben4wv/LP39E6Gg56+iT/goJHkV64+nu3v3d
//Tmj+uSHWfkq93oG5tsOk2nTN4UCpyT5fWGv4eh7q2cKElMQM5GT/uZnCjEdDmJU2M11
//k6Ttg+FMNPgvH6R4e+lqhtmslXwXv9Xm95eS6JokJaYUimNX+dzhD+eRq+88vGJO63s
//afkEyGvifAMJFPwO78=
//-----END PUBLIC KEY-----`)
//
//	// Parse the token
//	token, err := jwt.ParseWithClaims(tokenString, &OpenaiClaim{}, func(token *jwt.Token) (interface{}, error) {
//		// Check the signing method
//		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
//			return nil, errors.New("Unexpected signing method")
//		}
//		return jwt.ParseRSAPublicKeyFromPEM(pubKeyData)
//	})
//	if err != nil {
//		return nil, err
//	}
//	return token, nil
//}

// CheckToken parses the JWT token without verifying its signature
func CheckToken(tokenString string) (*jwt.Token, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT token format")
	}

	// Decode the payload (second part)
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	// Decode into your custom claims
	claims := &CodexClaim{}
	if err := json.Unmarshal(payloadBytes, claims); err != nil {
		return nil, err
	}

	err = claims.Valid()
	if err != nil {
		return nil, err
	}

	// Decode and parse the header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("failed to decode header: " + err.Error())
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, errors.New("failed to unmarshal header: " + err.Error())
	}
	// Construct a dummy token with the claims (no signature verified)
	return &jwt.Token{
		Header: header,
		Claims: claims,
		Valid:  true,
	}, nil
}
