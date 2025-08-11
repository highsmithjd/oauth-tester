package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"golang.org/x/oauth2/clientcredentials"
)

const (
	authURLTemplate  = "https://login.microsoftonline.com/%s/oauth2/v2.0/authorize"
	tokenURLTemplate = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"
	deviceCodeURL    = "https://login.microsoftonline.com/%s/oauth2/v2.0/devicecode"
)

type TokenResponse struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
}

// openBrowser tries to open the URL in a browser, depending on OS.
func openBrowser(url string) {
	var err error

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}

	if err != nil {
		log.Printf("Please open the following URL manually in your browser:\n%s", url)
	}
}

func RunAuthCodeFlow(tenant, clientID, clientSecret string, scopes []string) (*TokenResponse, error) {
	ctx := context.Background()

	// Generate PKCE code verifier and challenge
	codeVerifier, codeChallenge, err := generatePKCE()
	if err != nil {
		return nil, fmt.Errorf("failed to generate PKCE: %v", err)
	}

	// Start local HTTP server to catch callback
	codeCh := make(chan string)
	srv := &http.Server{Addr: ":8080"}
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "No code in query", http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, "Authentication successful! You can close this window.")
		go func() {
			codeCh <- code
			srv.Shutdown(ctx)
		}()
	})

	go func() {
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("ListenAndServe(): %v", err)
		}
	}()

	// Build authorization URL with PKCE
	authURL := fmt.Sprintf(authURLTemplate, tenant)
	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("response_type", "code")
	params.Set("redirect_uri", "http://localhost:8080/callback")
	params.Set("scope", scopesToString(scopes))
	params.Set("state", "state")
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")
	params.Set("access_type", "offline")

	fullAuthURL := authURL + "?" + params.Encode()
	openBrowser(fullAuthURL)
	fmt.Println("Waiting for authentication...")

	code := <-codeCh

	// Exchange code for token with PKCE code verifier and client secret
	tokenEndpoint := fmt.Sprintf(tokenURLTemplate, tenant)
	tokenData := map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     clientID,
		"code":          code,
		"redirect_uri":  "http://localhost:8080/callback",
		"code_verifier": codeVerifier,
	}

	// Add client secret if provided
	if clientSecret != "" {
		tokenData["client_secret"] = clientSecret
	}

	tokenResp, err := requestToken(ctx, tokenEndpoint, tokenData)
	if err != nil {
		return nil, err
	}

	return tokenResp, nil
}

func RunDeviceCodeFlow(tenant, clientID string, scopes []string) (*TokenResponse, error) {
	ctx := context.Background()

	type deviceCodeResp struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
		Message                 string `json:"message"`
	}

	// Step 1: Request device code
	reqBody := map[string]string{
		"client_id": clientID,
		"scope":     scopesToString(scopes),
	}
	url := fmt.Sprintf(deviceCodeURL, tenant)

	// Use HTTP client to POST device code request
	resp, err := postForm(ctx, url, reqBody)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var dc deviceCodeResp
	if err := jsonNewDecoder(resp.Body).Decode(&dc); err != nil {
		return nil, err
	}

	fmt.Println(dc.Message)

	// Step 2: Poll token endpoint
	tokenEndpoint := fmt.Sprintf(tokenURLTemplate, tenant)

	for {
		time.Sleep(time.Duration(dc.Interval) * time.Second)

		tokenResp, err := requestToken(ctx, tokenEndpoint, map[string]string{
			"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
			"client_id":   clientID,
			"device_code": dc.DeviceCode,
		})

		if err != nil {
			return nil, err
		}

		if tokenResp.AccessToken != "" {
			return tokenResp, nil
		}
	}
}

func RunClientCredentialsFlow(tenant, clientID, clientSecret string, scopes []string) (*TokenResponse, error) {
	ctx := context.Background()

	conf := clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     fmt.Sprintf(tokenURLTemplate, tenant),
		Scopes:       scopes,
	}

	tok, err := conf.Token(ctx)
	if err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken: tok.AccessToken,
	}, nil
}

// Helper funcs below...

// generatePKCE generates a code verifier and challenge for PKCE
func generatePKCE() (codeVerifier, codeChallenge string, err error) {
	// Generate random bytes for code verifier
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return "", "", err
	}
	codeVerifier = base64.RawURLEncoding.EncodeToString(verifierBytes)

	// Generate code challenge using SHA256
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge = base64.RawURLEncoding.EncodeToString(hash[:])

	return codeVerifier, codeChallenge, nil
}

func scopesToString(scopes []string) string {
	return strings.Join(scopes, " ")
}

func postForm(ctx context.Context, url string, data map[string]string) (*http.Response, error) {
	form := urlValues(data)
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{}
	return client.Do(req)
}

func urlValues(data map[string]string) url.Values {
	vals := url.Values{}
	for k, v := range data {
		vals.Set(k, v)
	}
	return vals
}

func jsonNewDecoder(body io.Reader) *json.Decoder {
	return json.NewDecoder(body)
}

func requestToken(ctx context.Context, tokenEndpoint string, form map[string]string) (*TokenResponse, error) {
	resp, err := postForm(ctx, tokenEndpoint, form)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var tr struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		Error        string `json:"error"`
		ErrorDesc    string `json:"error_description"`
	}

	if err := jsonNewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, err
	}

	if tr.Error != "" {
		return nil, fmt.Errorf("oauth error: %s - %s", tr.Error, tr.ErrorDesc)
	}

	return &TokenResponse{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		IDToken:      tr.IDToken,
	}, nil
}
