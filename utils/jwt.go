package utils

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var mySigningKey []byte

func init() {
	mySigningKey = []byte(os.Getenv("SECRET_KEY"))
}

func GetJwt() string {
	// Creating a new JWT with 30 minute expiry time
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(30 * time.Minute).Unix(),
	})

	tokenString, err := token.SignedString(mySigningKey)
	if err != nil {
		log.Fatal(err)
	}

	return tokenString
}

func ValidateJwt(tokenString string) bool {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// mySigningKey is a []byte containing your secret, e.g. []byte("my_secret_key")
		return mySigningKey, nil
	})

	if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		log.Print("Token is valid")
		return true
	}

	log.Print("Token is invalid")
	fmt.Println(err)
	return false
}
