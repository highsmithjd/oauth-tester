package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"oauth-tester/internal/auth"
	"oauth-tester/internal/graph"
	"oauth-tester/internal/token"
)

func main() {
	var flow string
	flag.StringVar(&flow, "flow", "", "OAuth flow to run (authcode, devicecode, clientcred)")
	flag.Parse()

	if flow == "" {
		fmt.Print("Select OAuth flow (authcode, devicecode, clientcred): ")
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		flow = strings.TrimSpace(scanner.Text())
	}

	scanner := bufio.NewScanner(os.Stdin)

	fmt.Print("Enter Tenant ID or domain: ")
	scanner.Scan()
	tenant := strings.TrimSpace(scanner.Text())

	fmt.Print("Enter Client ID: ")
	scanner.Scan()
	clientID := strings.TrimSpace(scanner.Text())

	var clientSecret string
	if flow == "clientcred" || flow == "authcode" {
		fmt.Print("Enter Client Secret: ")
		scanner.Scan()
		clientSecret = strings.TrimSpace(scanner.Text())
	}

	scopes := []string{"https://graph.microsoft.com/.default"}
	if flow == "authcode" || flow == "devicecode" {
		fmt.Print("Enter scopes (space-separated, default: openid profile offline_access User.Read): ")
		scanner.Scan()
		inputScopes := strings.TrimSpace(scanner.Text())
		if inputScopes != "" {
			scopes = strings.Fields(inputScopes)
		} else {
			scopes = []string{"openid", "profile", "offline_access", "User.Read"}
		}
	}

	var tokenResp *auth.TokenResponse
	var err error

	switch flow {
	case "authcode":
		tokenResp, err = auth.RunAuthCodeFlow(tenant, clientID, clientSecret, scopes)
	case "devicecode":
		tokenResp, err = auth.RunDeviceCodeFlow(tenant, clientID, scopes)
	case "clientcred":
		tokenResp, err = auth.RunClientCredentialsFlow(tenant, clientID, clientSecret, scopes)
	default:
		log.Fatalf("Unsupported flow: %s", flow)
	}

	if err != nil {
		log.Fatalf("OAuth flow failed: %v", err)
	}

	fmt.Println("\nAccess Token Claims:")
	token.PrettyPrintJWT(tokenResp.AccessToken)

	if tokenResp.IDToken != "" {
		fmt.Println("\nID Token Claims:")
		token.PrettyPrintJWT(tokenResp.IDToken)
	}

	if tokenResp.RefreshToken != "" {
		fmt.Println("\nRefresh Token present")
	}

	fmt.Println("\nTesting Microsoft Graph /me call...")
	profile, err := graph.GetUserProfile(tokenResp.AccessToken)
	if err != nil {
		log.Printf("Graph API call failed: %v", err)
	} else {
		fmt.Printf("Hello, %s (%s)\n", profile.DisplayName, profile.UserPrincipalName)
	}
}
