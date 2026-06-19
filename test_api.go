package main

import (
	"fmt"
	"github.com/The-17/agentsecrets/pkg/config"
)

func main() {
	fmt.Printf("IsAuthenticated: %v\n", config.IsAuthenticated())
	fmt.Printf("GetEmail: %q\n", config.GetEmail())
	tokens, err := config.LoadTokens()
	if err != nil {
		fmt.Printf("LoadTokens Error: %v\n", err)
	} else if tokens != nil {
		fmt.Printf("Access Token: %q\n", tokens.AccessToken)
		fmt.Printf("Refresh Token: %q\n", tokens.RefreshToken)
		fmt.Printf("Expires At: %q\n", tokens.ExpiresAt)
	} else {
		fmt.Println("Tokens: nil")
	}
}
