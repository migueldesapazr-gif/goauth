# OAuth Providers

GoAuth supports multiple OAuth providers out of the box.

## Quick Setup

```go
auth, _ := goauth.New(
    goauth.WithDatabase(db),
    goauth.WithSecrets(secrets),
    goauth.WithAppURL("https://myapp.com"),
    
    goauth.WithGoogle(clientID, clientSecret),
    goauth.WithDiscord(clientID, clientSecret),
    goauth.WithGitHub(clientID, clientSecret),
    goauth.WithMicrosoft(clientID, clientSecret),
    goauth.WithTwitch(clientID, clientSecret),
)
```

## Endpoints Created

| Provider | Login URL | Callback URL |
|----------|-----------|--------------|
| Google | `/auth/google` | `/auth/google/callback` |
| Discord | `/auth/discord` | `/auth/discord/callback` |
| GitHub | `/auth/github` | `/auth/github/callback` |
| Microsoft | `/auth/microsoft` | `/auth/microsoft/callback` |
| Twitch | `/auth/twitch` | `/auth/twitch/callback` |

## Provider Setup

### Google

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a project → APIs & Services → Credentials
3. Create OAuth 2.0 Client ID
4. Add redirect URI: `https://yourapp.com/auth/google/callback`

```env
GOAUTH_GOOGLE_CLIENT_ID=xxx.apps.googleusercontent.com
GOAUTH_GOOGLE_CLIENT_SECRET=xxx
```

### Discord

1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Create Application → OAuth2
3. Add redirect URI: `https://yourapp.com/auth/discord/callback`

```env
GOAUTH_DISCORD_CLIENT_ID=xxx
GOAUTH_DISCORD_CLIENT_SECRET=xxx
```

### GitHub

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. New OAuth App
3. Set callback URL: `https://yourapp.com/auth/github/callback`

```env
GOAUTH_GITHUB_CLIENT_ID=xxx
GOAUTH_GITHUB_CLIENT_SECRET=xxx
```

### Microsoft

1. Go to [Azure Portal](https://portal.azure.com/)
2. App registrations → New registration
3. Add redirect URI: `https://yourapp.com/auth/microsoft/callback`

```env
GOAUTH_MICROSOFT_CLIENT_ID=xxx
GOAUTH_MICROSOFT_CLIENT_SECRET=xxx
```

### Twitch

1. Go to [Twitch Developer Console](https://dev.twitch.tv/console)
2. Register Application
3. Add redirect URI: `https://yourapp.com/auth/twitch/callback`

```env
GOAUTH_TWITCH_CLIENT_ID=xxx
GOAUTH_TWITCH_CLIENT_SECRET=xxx
```

## Custom Provider

```go
provider := goauth.NewCustomProvider(
    "gitlab",                                    // name
    clientID, clientSecret,                      // credentials
    "https://gitlab.com/oauth/authorize",        // auth URL
    "https://gitlab.com/oauth/token",            // token URL
    "https://gitlab.com/api/v4/user",            // user info URL
    []string{"read_user"},                       // scopes
    nil,                                         // user parser (nil = auto)
)

auth, _ := goauth.New(
    goauth.WithDatabase(db),
    goauth.WithSecrets(secrets),
    goauth.WithOAuth(provider),
)
```

## Frontend Integration

```html
<!-- Login buttons -->
<a href="/auth/google">Login with Google</a>
<a href="/auth/discord">Login with Discord</a>
<a href="/auth/github">Login with GitHub</a>
```

The callback returns JSON with tokens:
```json
{
    "access_token": "...",
    "refresh_token": "...",
    "user_id": "...",
    "is_new_user": true,
    "provider": "google"
}
```
