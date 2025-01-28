package auth

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"encoding/base64"

	"github.com/google/uuid"
)

func TestMakeJWT(t *testing.T) {
	result, err := MakeJWT(uuid.New(), "thisisasecretapparently", (2 * time.Hour))
	if err != nil {
		fmt.Println("Making JWT id error:")
		fmt.Println(err)
		return
	}
	payload := strings.Split(result, ".")[1]
	decodedPayload, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		fmt.Println("Decoding payload error:")
		fmt.Println(err)
		return
	}
	var claims map[string]interface{}
	err = json.Unmarshal(decodedPayload, &claims)
	if err != nil {
		fmt.Println("Unmarshaling decoded payload error:")
		fmt.Println(err)
		return
	}

	if claims["iss"] == "chirpy" {
		fmt.Println("Issuer is correct!")
	} else {
		fmt.Println("Unexpected issuer:", claims["iss"])
	}
}
