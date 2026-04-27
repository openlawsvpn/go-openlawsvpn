package relay

import (
	"context"
	"crypto/tls"
	"net"
)

func dialTLS(ctx context.Context, addr, serverName string) (net.Conn, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		Config:    &tls.Config{ServerName: serverName},
	}
	return dialer.DialContext(ctx, "tcp", addr)
}
