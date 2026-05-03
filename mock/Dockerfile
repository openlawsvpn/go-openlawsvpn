# mock/Dockerfile — builds the go-openlawsvpn mock server Docker image.
#
# Image: ghcr.io/openlawsvpn/ovpn3-mock-server
#
# The image:
#   1. Builds the Go mock server (CGO_ENABLED=0, fully static)
#   2. Generates test PKI (CA, server cert, client cert)
#   3. Exposes TCP/443
#
# The Go mock server replaces the earlier openvpn3-core C++ stub. It
# implements the same control-channel + TLS exchange using the packages
# in this repository, making the mock trivially buildable without any
# C++ toolchain.

FROM golang:1.25 AS builder

WORKDIR /src

# Copy go.mod/go.sum first so the module cache layer is reusable.
COPY go.mod go.sum ./
RUN go mod download

# Copy source.
COPY . .

# Build a fully static binary.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" \
    -o /out/mock-server ./mock/mockserver

# ---- PKI generation stage ----
FROM ubuntu:24.04 AS pki

RUN apt-get update && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

COPY mock/gencerts.sh /gencerts.sh
RUN chmod +x /gencerts.sh && /gencerts.sh

# ---- runtime image ----
FROM scratch

# Copy the static binary and PKI.
COPY --from=builder /out/mock-server /mock-server
COPY --from=pki /etc/mock-vpn /etc/mock-vpn

EXPOSE 443/tcp

ENTRYPOINT ["/mock-server"]
