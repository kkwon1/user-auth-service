package routes

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
	"user-auth-service/db"

	"github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var UsersCollection *mongo.Collection
var mySigningKey []byte

func init() {
	var client = db.GetClient()
	UsersCollection = client.Database("authDB").Collection("users")

	mySigningKey = []byte(os.Getenv("SECRET_KEY"))
}

type User struct {
	Username string
	Email    string
	Password string
}

func CreateUser(w http.ResponseWriter, r *http.Request) {
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)

	var u User
	decodeError := json.NewDecoder(r.Body).Decode(&u)
	if decodeError != nil {
		log.Fatal(decodeError)
		http.Error(w, decodeError.Error(), http.StatusBadRequest)
	}

	log.Print("Testing hash")
	bPassword := []byte(u.Password)
	hash, hashError := bcrypt.GenerateFromPassword(bPassword, bcrypt.MinCost)
	if hashError != nil {
		log.Fatal(hashError)
	}
	log.Print(string(hash))

	_, insertError := UsersCollection.InsertOne(ctx, bson.D{
		{Key: "username", Value: u.Username},
		{Key: "email", Value: u.Email},
		{Key: "password", Value: string(hash)},
	})

	if insertError != nil {
		log.Fatal(insertError)
	}

	log.Print("Inserted a new user into users collection")
}

func DeleteUser(w http.ResponseWriter, r *http.Request) {
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)

	var usernameToDelete User
	decodeError := json.NewDecoder(r.Body).Decode(&usernameToDelete)
	if decodeError != nil {
		log.Fatal(decodeError)
		http.Error(w, decodeError.Error(), http.StatusBadRequest)
	}

	res, deleteError := UsersCollection.DeleteOne(ctx, bson.M{"username": usernameToDelete.Username})

	if deleteError != nil {
		log.Fatal(deleteError)
	}

	if res.DeletedCount == 0 {
		fmt.Println("DeleteOne() document not found: ", res)
	} else {
		fmt.Println("DeleteOne result:", res)
	}
}

func Login(w http.ResponseWriter, r *http.Request) {
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)

	var u User
	decodeError := json.NewDecoder(r.Body).Decode(&u)
	if decodeError != nil {
		log.Fatal(decodeError)
		http.Error(w, decodeError.Error(), http.StatusBadRequest)
	}

	log.Print("Testing password matching")

	var retrievedUser User

	findError := UsersCollection.FindOne(ctx, bson.M{"username": u.Username}).Decode(&retrievedUser)

	if findError != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	loginIsValid := comparePassword(retrievedUser.Password, u.Password)

	if loginIsValid {
		log.Print("Amazing! It's the correct password")

		// Creating a new JWT with 30 minute expiry time
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(30 * time.Minute).Unix(),
		})

		tokenString, err := token.SignedString(mySigningKey)

		log.Print(tokenString)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(tokenString))
		if err != nil {
			log.Fatal(err)
		}
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
}

func TestToken(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	valid := validateJwt(tokenString)
	if valid {
		log.Print("Token is VALID")

	} else {
		log.Print("Token is INVALID!!!")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
}

func validateJwt(tokenString string) bool {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// mySigningKey is a []byte containing your secret, e.g. []byte("my_secret_key")
		return mySigningKey, nil
	})

	if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		log.Print("Token is VALID")
		return true
	}

	log.Print("Token is INVALID!!!")
	fmt.Println(err)
	return false
}

// Compare the password with hash to check that input password is correct
func comparePassword(hashedPwd string, plainPwd string) bool {
	bytePwd := []byte(plainPwd)
	byteHash := []byte(hashedPwd)
	err := bcrypt.CompareHashAndPassword(byteHash, bytePwd)
	if err != nil {
		log.Println(err)
		return false
	}

	return true
}
