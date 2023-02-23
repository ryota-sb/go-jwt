package util

import (
	"os"
	"strconv"
	"time"
	"errors"

	"github.com/golang-jwt/jwt/v4"
)

// IDとUsernameは、カスタムクレームでjwt.RegisteredClaimsは、JWTペイロードに含まれるクレーム
type MyJWTClaims struct {
	ID string `json:"id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// 署名を行う際に、[]byte型の秘密鍵を使用するので、[]byte関数で変換
func getJWTSecret() []byte {
	return []byte(os.Getenv("JWT_SECRET_KEY"))
}

// トークンの生成
func GenerateSignedString(userId int64, username string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, MyJWTClaims{
		ID: strconv.Itoa(int(userId)),
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: strconv.Itoa(int(userId)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
	})

	return token.SignedString(getJWTSecret())
}

func ValidateToken(signedToken string) (err error) {
	token, err := jwt.ParseWithClaims(
		signedToken,
		&MyJWTClaims{},
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signed method")
			}
			return getJWTSecret(), nil
		},
	)

	if err != nil {
		v, _ := err.(*jwt.ValidationError)
		switch v.Errors {
		case jwt.ValidationErrorSignatureInvalid:
			err = errors.New("signature validation failed")
			return
		case jwt.ValidationErrorExpired:
			err = errors.New("token is expired")
			return
		default:
			err = errors.New("token is invalid")
			return
		}
	}

	if !token.Valid {
		err = errors.New("unauthorized")
		return
	}

	return
}