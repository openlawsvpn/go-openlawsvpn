# go-openvpn3

Pure-Go OpenVPN3 client protocol implementation — AWS Client VPN + SAML/CRV1 flow.

Zero C dependencies. `CGO_ENABLED=0` builds a fully static binary.
`gomobile bind` produces an `.aar` for Android without NDK or CMake.

## Status

Working end-to-end on Linux (CLI). Android gomobile API complete; `.aar` build
pipeline in `.github/workflows/aar.yml`.

## Build

```bash
# Linux CLI
CGO_ENABLED=0 go build -o ovpn3 ./cmd/ovpn3
sudo ./ovpn3 -config your.ovpn

# Android .aar (requires gomobile + Android NDK)
gomobile bind -o go-openvpn3.aar -target android -androidapi 26 \
    github.com/openlawsvpn/go-openvpn3
```

## Test

```bash
# Unit tests (no network):
go test -race ./...

# Integration tests (runs local mock server — no Docker required):
go test -v -tags=integration -timeout 120s .
```

## Known limitations

### OpenVPN-PRF key derivation (plain OpenVPN 2.x)

AWS Client VPN always negotiates TLS-EKM (`key-derivation tls-ekm` in
PUSH_REPLY), so key derivation is fully correct for that use case.

Plain OpenVPN 2.x servers that do **not** push `key-derivation tls-ekm` use
the OpenVPN-PRF method, which requires the TLS `ServerRandom` (the 32-byte
random from the server's `ServerHello`). Go's `crypto/tls` does not expose
this value in `ConnectionState`, so the fallback path substitutes zeros. The
TLS handshake and authentication succeed, but the derived data-channel keys
will be wrong — packets fail to decrypt and no traffic flows.

No fix is possible without forking `crypto/tls`. Track the upstream Go
proposal if plain OpenVPN 2.x support without EKM becomes a requirement.

### SAML assertion is single-use

AWS Client VPN SAML assertions are cryptographically bound to the original
`AuthnRequest` ID. The server marks the assertion consumed on first use.
Retrying Phase 2 with the same token returns `AUTH_FAILED,Invalid username
or password` even within the token's TTL.

For reconnects: if the server's CRV1 session is still alive the client can
reconnect with the cached token. If the session has expired (`AUTH_FAILED`),
the user must complete the browser SAML flow again.

## License

Business Source License 1.1. Converts to MIT on 2031-01-01.
See [LICENSE](LICENSE) for details. Commercial use requires a separate license —
contact contact@openlawsvpn.com.
