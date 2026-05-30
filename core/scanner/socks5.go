package scanner

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

type socks5Dialer struct {
	address string
	auth    string
	timeout time.Duration
}

func (d *socks5Dialer) Dial(network, addr string) (net.Conn, error) {
	if !strings.HasPrefix(network, "tcp") {
		return nil, errors.New("socks5 only supports tcp")
	}
	timeout := d.timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	conn, err := net.DialTimeout("tcp", d.address, timeout)
	if err != nil {
		return nil, err
	}
	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
		defer conn.SetDeadline(time.Time{})
	}

	if err := d.handshake(conn, addr); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

func (d *socks5Dialer) handshake(conn net.Conn, addr string) error {
	methods := []byte{0x00}
	if d.auth != "" {
		methods = []byte{0x00, 0x02}
	}
	if _, err := conn.Write([]byte{0x05, byte(len(methods))}); err != nil {
		return err
	}
	if _, err := conn.Write(methods); err != nil {
		return err
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != 0x05 {
		return errors.New("invalid socks5 response")
	}
	if resp[1] == 0x02 {
		if err := d.authUserPass(conn); err != nil {
			return err
		}
	} else if resp[1] != 0x00 {
		return errors.New("unsupported socks5 auth")
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	port, err := parsePort(portStr)
	if err != nil {
		return err
	}

	req := []byte{0x05, 0x01, 0x00}
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		req = append(req, 0x01)
		req = append(req, ip4...)
	} else if ip6 := ip.To16(); ip6 != nil {
		req = append(req, 0x04)
		req = append(req, ip6...)
	} else {
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}

	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, port)
	req = append(req, portBuf...)

	if _, err := conn.Write(req); err != nil {
		return err
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[1] != 0x00 {
		return errors.New("socks5 connect failed")
	}

	var addrLen int
	switch header[3] {
	case 0x01:
		addrLen = 4
	case 0x04:
		addrLen = 16
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return err
		}
		addrLen = int(lenBuf[0])
	default:
		return errors.New("invalid socks5 address type")
	}

	if addrLen > 0 {
		if _, err := io.CopyN(io.Discard, conn, int64(addrLen)); err != nil {
			return err
		}
	}
	if _, err := io.CopyN(io.Discard, conn, 2); err != nil {
		return err
	}
	return nil
}

func (d *socks5Dialer) authUserPass(conn net.Conn) error {
	parts := strings.SplitN(d.auth, ":", 2)
	if len(parts) != 2 {
		return errors.New("invalid proxy auth")
	}
	user := parts[0]
	pass := parts[1]
	if len(user) > 255 || len(pass) > 255 {
		return errors.New("proxy auth too long")
	}

	req := []byte{0x01, byte(len(user))}
	req = append(req, []byte(user)...)
	req = append(req, byte(len(pass)))
	req = append(req, []byte(pass)...)

	if _, err := conn.Write(req); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[1] != 0x00 {
		return errors.New("socks5 auth failed")
	}
	return nil
}

func parsePort(raw string) (uint16, error) {
	port, err := strconv.Atoi(raw)
	if err != nil {
		return 0, err
	}
	if port < 1 || port > 65535 {
		return 0, errors.New("invalid port")
	}
	return uint16(port), nil
}
