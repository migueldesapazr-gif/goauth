# GoAuth Examples

Example applications demonstrating different GoAuth configurations.

## Examples

| Example | Description |
|---------|-------------|
| [minimal](minimal/) | Simplest possible setup |
| [full](full/) | Full configuration with all features |
| [oauth_only](oauth_only/) | OAuth authentication only |
| [privacy](privacy/) | Privacy-focused, minimal data |

## Running Examples

1. Set environment variables (see each example's requirements)
2. Run the example:

```bash
cd examples/minimal
go run main.go
```

## Environment Variables

All examples need at minimum:

```bash
export DATABASE_URL="postgres://user:pass@localhost/myapp"
export GOAUTH_JWT_SECRET=$(openssl rand -base64 32)
export GOAUTH_ENCRYPTION_KEY=$(openssl rand -base64 32)
export GOAUTH_PEPPER=$(openssl rand -base64 32)
```

For OAuth examples, add provider credentials:

```bash
export GOOGLE_CLIENT_ID=xxx
export GOOGLE_CLIENT_SECRET=xxx
export DISCORD_CLIENT_ID=xxx
export DISCORD_CLIENT_SECRET=xxx
export GITHUB_CLIENT_ID=xxx
export GITHUB_CLIENT_SECRET=xxx
```
