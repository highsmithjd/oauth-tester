package token

import (
	"encoding/json"
	"fmt"

	"github.com/fatih/color"
	"github.com/golang-jwt/jwt/v5"
)

func PrettyPrintJWT(rawToken string) {
	if rawToken == "" {
		fmt.Println("No token to decode")
		return
	}

	// Parse token without verifying signature (just decode)
	token, _, err := new(jwt.Parser).ParseUnverified(rawToken, jwt.MapClaims{})
	if err != nil {
		fmt.Println("Failed to parse token:", err)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		fmt.Println("Invalid token claims")
		return
	}

	pretty, err := json.MarshalIndent(claims, "", "  ")
	if err != nil {
		fmt.Println("Failed to marshal claims:", err)
		return
	}

	c := color.New(color.FgGreen)
	fmt.Println(c.Sprint(string(pretty)))
}
