package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func HashPassword(password string) (string, error) {
	byteSlice := []byte(password)
	if len(byteSlice) > 72 {
		return "", fmt.Errorf("the password is longer than 72 bytes at: %v", len(byteSlice))
	}

	cost := 12
	hashedPassword, err := bcrypt.GenerateFromPassword(byteSlice, cost)
	if err != nil {
		return "", err
	}

	return string(hashedPassword), nil
}

func CheckPasswordHash(password, hash string) error {
	sliceByteHash := []byte(hash)
	sliceBytePass := []byte(password)
	err := bcrypt.CompareHashAndPassword(sliceByteHash, sliceBytePass)
	if err != nil {
		return err
	}
	return nil
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {

	claim := jwt.RegisteredClaims{
		Issuer:    "chirpy",
		Subject:   userID.String(),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)
	signedToken, err := newToken.SignedString([]byte(tokenSecret))
	if err != nil {
		fmt.Println("Signing token error:")
		fmt.Println(err)
		return "", err
	}
	return signedToken, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	token, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(tokenSecret), nil
	})
	if err != nil {
		fmt.Println("Parse with claims error:")
		fmt.Println(err)
		return uuid.Nil, err
	}
	id, err := token.Claims.GetSubject()
	if err != nil {
		fmt.Println("Getting id error:")
		fmt.Println(err)
		return uuid.Nil, err
	}
	parsedId, err := uuid.Parse(id)
	if err != nil {
		fmt.Println("Parsing id error:")
		fmt.Println(err)
		return uuid.Nil, err
	}

	return parsedId, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	bearer := headers.Get("Authorization")
	if bearer == "" {
		return "", fmt.Errorf("in %v couldn't find the bearer", headers)
	}
	bearerTrimmed := strings.TrimPrefix(bearer, "Bearer")
	spacesTrimmed := strings.TrimSpace(bearerTrimmed)

	return spacesTrimmed, nil
}

func MakeRefreshToken() (string, error) {
	src := make([]byte, 32)
	_, err := rand.Read(src)
	if err != nil {
		fmt.Println("Generating random 32 byte token error:")
		fmt.Println(err)
		return "", err
	}
	token := hex.EncodeToString(src)

	return token, nil
}

func GetAPIKey(headers http.Header) (string, error) {
	apiKey := headers.Get("Authorization")
	if apiKey == "" {
		return "", fmt.Errorf("in %v couldn't find the bearer", headers)
	}
	bearerTrimmed := strings.TrimPrefix(apiKey, "ApiKey ")
	spacesTrimmed := strings.TrimSpace(bearerTrimmed)

	return spacesTrimmed, nil
}
