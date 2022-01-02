![test](https://github.com/kernle32dll/keybox-go/workflows/test/badge.svg)
[![Go Reference](https://pkg.go.dev/badge/github.com/kernle32dll/keybox-go.svg)](https://pkg.go.dev/github.com/kernle32dll/keybox-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/kernle32dll/keybox-go)](https://goreportcard.com/report/github.com/kernle32dll/keybox-go)
[![codecov](https://codecov.io/gh/kernle32dll/keybox-go/branch/master/graph/badge.svg)](https://codecov.io/gh/kernle32dll/keybox-go)

# keybox-go

keybox-go is a tiny library for interacting with private and public keys in Go.

The initial implementation was inspired by [github.com/dgrijalva/jwt-go](https://github.com/dgrijalva/jwt-go), but has
greatly superseeded it (e.g. by supporting password protected keys).

Download:

```
go get github.com/kernle32dll/keybox-go
```

Detailed documentation can be found on [pkg.go.dev](https://pkg.go.dev/github.com/kernle32dll/keybox-go).

## Compatibility

keybox-go is automatically tested against Go 1.15.X, 1.16.X and 1.17.X.