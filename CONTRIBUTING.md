# Contributing to GoAuth

Thank you for your interest in contributing! This document provides guidelines.

## Code of Conduct

Be respectful and inclusive. We welcome contributions from everyone.

## How to Contribute

### Reporting Bugs

1. Check existing issues first
2. Create a new issue with:
   - Go version
   - Database used
   - Steps to reproduce
   - Expected vs actual behavior

### Security Issues

**Do not open public issues for security vulnerabilities.**

Email security concerns privately to the maintainers.

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Add tests for new functionality
5. Run tests: `go test ./...`
6. Run linter: `golangci-lint run`
7. Commit with clear messages
8. Push and create a Pull Request

### Code Style

- Follow standard Go conventions
- Use `gofmt` for formatting
- Add godoc comments for exported functions
- Keep functions focused and small
- Handle errors explicitly

### Testing

- Write tests for new features
- Maintain existing test coverage
- Test edge cases and error conditions

### Documentation

- Update README if adding features
- Add godoc comments
- Update CHANGELOG.md

## Development Setup

```bash
# Clone
git clone https://github.com/YOURUSERNAME/goauth
cd goauth

# Install dependencies
go mod download

# Run tests
go test ./...

# Run with race detector
go test -race ./...
```

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
