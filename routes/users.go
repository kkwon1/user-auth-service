package routes

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
	"user-auth-service/db"

	"github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var UsersCollection *mongo.Collection

func init() {
	var client = db.GetClient()
	UsersCollection = client.Database("authDB").Collection("users")
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

		// Create a new token object, specifying signing method and the claims
		// you would like it to contain.
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"foo": "bar",
			"nbf": time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
		})

		mySigningKey := []byte("MySigningKey")
		// Sign and get the complete encoded token as a string using the secret
		tokenString, err := token.SignedString(mySigningKey)

		log.Print(tokenString)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

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