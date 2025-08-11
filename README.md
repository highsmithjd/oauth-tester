# OAuth Tester

A command-line tool for testing OAuth 2.0 flows with Microsoft Entra ID. Supports authorization code flow, device code flow, and client credentials flow.

## Features

- **Authorization Code Flow** - with PKCE and client secret support
- **Device Code Flow** - for SPA clients and cross-platform authentication
- **Client Credentials Flow** - for service-to-service authentication
- **JWT Token Decoding** - Pretty-print access tokens and ID tokens
- **Microsoft Graph Integration** - Test API calls with obtained tokens

## Prerequisites

- Go 1.23 or later
- Microsoft Entra ID application registration

## Installation

1. Clone the repository:
```bash
git clone <your-repo-url>
cd oauth-tester
```

2. Install dependencies:
```bash
go mod tidy
```

3. Build the application:
```bash
go build ./cmd/main.go
```

## Usage

Run the application:
```bash
go run ./cmd/main.go
```

Or use command-line flags:
```bash
go run ./cmd/main.go -flow authcode
```

### Supported Flows

- `authcode` - Authorization Code Flow (requires client secret)
- `devicecode` - Device Code Flow (works with SPA clients)
- `clientcred` - Client Credentials Flow (service-to-service)

### Example Usage

1. **Authorization Code Flow**:
   - Enter your Microsoft Entra ID Tenant ID
   - Enter your Client ID
   - Enter your Client Secret
   - Complete authentication in browser

2. **Device Code Flow**:
   - Enter your Microsoft Entra ID Tenant ID
   - Enter your Client ID
   - Visit the provided URL and enter the code

3. **Client Credentials Flow**:
   - Enter your Microsoft Entra ID Tenant ID
   - Enter your Client ID
   - Enter your Client Secret

## Microsoft Entra ID Setup

1. Go to Azure Portal → Microsoft Entra ID → App registrations
2. Create a new registration or use existing one
3. For Authorization Code Flow:
   - Set application type to "Web"
   - Add redirect URI: `http://localhost:8080/callback`
   - Create a client secret
4. For Device Code Flow:
   - Works with SPA applications
   - No redirect URI needed

## Security Notes

- Client secrets should be kept secure and not committed to version control
- The application runs a local HTTP server on port 8080 for callback handling
- PKCE is automatically used for authorization code flow security

## License

MIT License
