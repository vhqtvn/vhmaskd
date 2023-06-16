package auth

import (
	"net"
	"strings"
	"time"
)

type PasswordAuth struct {
	Password string
}

func NewPasswordAuth(password string) *PasswordAuth {
	return &PasswordAuth{
		Password: password,
	}
}
func (p *PasswordAuth) HandleAuth(conn *net.Conn) (*net.Addr, *time.Time, error) {
	buf := make([]byte, 64)
	//read a line with max 64 bytes from socket
	// timeout after 5 seconds
	(*conn).SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := (*conn).Read(buf)
	if err != nil {
		return nil, nil, err
	}
	//compare password hash
	if strings.Trim(string(buf), "\r\n\t\x00") == p.Password {
		addr := (*conn).RemoteAddr()
		// extract only ip
		return &addr, nil, nil
	}
	return nil, nil, nil
}
