package util

import (
	"golang.org/x/crypto/bcrypt"
)

// 平文のパスワードを受け取り、ハッシュ化したパスワードを返す
func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hashedPassword), nil
}

// 平文のパスワードとハッシュ化されたパスワードが一致するかを検証する
// (元データが同じであれば、同じ計算アルゴリズムを用いる限り、同じハッシュ値が生成される)
func CheckPassword(hashedPassword string, inputPassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(inputPassword))
}