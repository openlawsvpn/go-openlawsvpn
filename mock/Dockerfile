FROM golang:1.25 AS builder

WORKDIR /src

# Copy go.mod/go.sum first so the module cache layer is reusable.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" \
    -o /out/mock-server ./mock/mockserver

FROM ubuntu:24.04 AS pki

RUN apt-get update && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

COPY mock/gencerts.sh /gencerts.sh
RUN chmod +x /gencerts.sh && /gencerts.sh

FROM scratch

COPY --from=builder /out/mock-server /mock-server
COPY --from=pki /etc/mock-vpn /etc/mock-vpn

EXPOSE 443/tcp

ENTRYPOINT ["/mock-server"]
