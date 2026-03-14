package netclient

import (
	"context"
	"fmt"
	"net"
)

const defaultPort = 1337

func ConnectToPeer(ctx context.Context, peerIP net.IP) (net.Conn, error) {
	addr := fmt.Sprintf("[%s]:%d", peerIP.String(), defaultPort)
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connect to peer %s: %w", addr, err)
	}
	return conn, nil
}
