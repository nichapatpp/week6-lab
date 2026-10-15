
package auth

import (
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Issuer struct {
	Secret []byte
	TTL    time.Duration
}

type Claims struct {
	Role string `json:"role"`
	jwt.RegisteredClaims
}

func (i *Issuer) Issue(memberID int64, role string) (string, error) {
	now := time.Now()

	claims := Claims{
		Role: role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   strconv.FormatInt(memberID, 10),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(i.TTL)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(i.Secret)
}
