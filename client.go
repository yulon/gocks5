package gocks5

import (
	"errors"
	"net"
	"time"

	"github.com/yulon/go-netil"
)

func PassRawConn(rawCon net.Conn, username, password string) (*Conn, time.Duration, error) {
	con := newConn(rawCon)
	rtt, err := con.sendHandshake(username, password)
	if err != nil {
		con.Close()
		return nil, rtt, err
	}
	return con, rtt, nil
}

func Pass(proxy, username, password string) (*Conn, time.Duration, error) {
	tcpCon, err := net.Dial("tcp", proxy)
	if err != nil {
		return nil, -1, err
	}
	return PassRawConn(tcpCon, username, password)
}

var ErrorUnsupportedGSSAPI = errors.New("unsupported GSSAPI")
var ErrorUnsupportedMethods = errors.New("unsupported methods")
var ErrorUnknowMethod = errors.New("unknow method")
var ErrorBadCertificate = errors.New("bad certificate")
var ErrorInvalidCertificate = errors.New("invalid certificate")
var ErrorUnauthorized = errors.New("unauthorized")

func (con *Conn) sendHandshake(username, password string) (time.Duration, error) {
	usernameLen := len(username)
	passwordLen := len(password)
	hasUsernamePassword := usernameLen > 0 || passwordLen > 0

	/*
		+----+----------+----------+
		|VER | NMETHODS | METHODS  |
		+----+----------+----------+
		| 1  |    1     | 1 to 255 |
		+----+----------+----------+
	*/

	p := []byte{Ver, 1, MethodNone}
	if hasUsernamePassword {
		if usernameLen == 0 || usernameLen > 255 || passwordLen == 0 || passwordLen > 255 {
			return -1, ErrorBadCertificate
		}
		p[1]++
		p = append(p, MethodUsernamePassword)
	}

	now := time.Now()

	err := netil.WriteAll(con, p)
	if err != nil {
		return -1, err
	}
	authSz := 3 + usernameLen + passwordLen
	buf := make([]byte, authSz)

	/*
		+----+--------+
		|VER | METHOD |
		+----+--------+
		| 1  |   1    |
		+----+--------+
	*/

	err = netil.ReadFull(con, buf[:2])
	if err != nil {
		return -1, err
	}

	rtt := time.Now().Sub(now)

	switch buf[1] {
	case MethodNone:
		return rtt, nil

	case MethodGSSAPI:
		return rtt, ErrorUnsupportedGSSAPI

	case MethodUsernamePassword:
		/*
			+----+------+----------+------+----------+
			|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
			+----+------+----------+------+----------+
			| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
			+----+------+----------+------+----------+
		*/

		base := 0
		buf[base] = UserPassVer

		base++
		buf[base] = byte(usernameLen)

		base++
		copy(buf[base:], []byte(username))

		base += usernameLen
		buf[base] = byte(passwordLen)

		base++
		copy(buf[base:], []byte(password))

		err := netil.WriteAll(con, buf)
		if err != nil {
			return rtt, err
		}

		/*
			+----+--------+
			|VER | STATUS |
			+----+--------+
			| 1  |   1    |
			+----+--------+
		*/

		err = netil.ReadFull(con, buf[:2])
		if err != nil {
			return rtt, err
		}

		if buf[1] != UserPassStatusSuccess {
			return rtt, ErrorUnauthorized
		}
		return rtt, nil

	case MethodUnsupportAll:
		return rtt, ErrorUnsupportedMethods
	}
	return rtt, ErrorUnknowMethod
}

var ErrorServerFailure = errors.New("server failure")
var ErrorNotAllowed = errors.New("not allowed")
var ErrorNetworkUnreachable = errors.New("network unreachable")
var ErrorHostUnreachable = errors.New("host unreachable")
var ErrorConnectionRefused = errors.New("connection refused")
var ErrorTTLExpired = errors.New("TTL expired")
var ErrorCommandNotSupported = errors.New("command not supported")
var ErrorAddressNotSupported = errors.New("address not supported")
var ErrorUnknowReply = errors.New("unknow reply")

func (con *Conn) Command(cmd byte, addr net.Addr) (net.Addr, time.Duration, error) {
	now := time.Now()

	err := con.WriteAddr(cmd, addr)
	if err != nil {
		return nil, -1, err
	}

	rep, addr, err := con.ReadAddr()
	if err != nil {
		return nil, -1, err
	}

	rtt := time.Now().Sub(now)

	if rep != RepSuccess {
		switch rep {
		case RepServerFailure:
			return nil, rtt, ErrorServerFailure
		case RepNotAllowed:
			return nil, rtt, ErrorNotAllowed
		case RepNetworkUnreachable:
			return nil, rtt, ErrorNetworkUnreachable
		case RepHostUnreachable:
			return nil, rtt, ErrorHostUnreachable
		case RepConnectionRefused:
			return nil, rtt, ErrorConnectionRefused
		case RepTTLExpired:
			return nil, rtt, ErrorTTLExpired
		case RepCommandNotSupported:
			return nil, rtt, ErrorCommandNotSupported
		case RepAddressNotSupported:
			return nil, rtt, ErrorAddressNotSupported
		}
		return nil, rtt, ErrorUnknowReply
	}
	return addr, rtt, nil
}

func (con *Conn) DialTCP(addr net.Addr) (net.Conn, time.Duration, error) {
	_, rtt, err := con.Command(CmdConnect, addr)
	if err != nil {
		return nil, rtt, err
	}
	return con.Conn, rtt, nil
}

func DialTCPPass(proxy, username, password string, addr net.Addr) (net.Conn, time.Duration, time.Duration, error) {
	con, pxyRtt, err := Pass(proxy, username, password)
	if err != nil {
		return nil, pxyRtt, -1, err
	}
	tcpCon, dstRtt, err := con.DialTCP(addr)
	if err != nil {
		con.Close()
		return nil, pxyRtt, dstRtt, err
	}
	return tcpCon, pxyRtt, dstRtt, err
}

func (con *Conn) ListenUDP() (net.PacketConn, time.Duration, error) {
	udpPxyAddr, rtt, err := con.Command(CmdUDPAssociate, &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, rtt, err
	}
	udpPxyPubAddr, err := netil.PublicAddr(udpPxyAddr, con.RemoteAddr())
	if err != nil {
		return nil, rtt, err
	}
	udpPxyPubUDPAddr, err := netil.ToUDPAddr(udpPxyPubAddr)
	if err != nil {
		return nil, rtt, err
	}
	udpPxyClt, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, rtt, err
	}
	return &packetConn{udpPxyClt, udpPxyPubUDPAddr, con.Conn}, rtt, nil
}

func ListenUDPPass(proxy, username, password string) (net.PacketConn, time.Duration, time.Duration, error) {
	con, pxyRtt, err := Pass(proxy, username, password)
	if err != nil {
		return nil, pxyRtt, -1, err
	}
	udpCon, dstRtt, err := con.ListenUDP()
	if err != nil {
		con.Close()
		return nil, pxyRtt, dstRtt, err
	}
	return udpCon, pxyRtt, dstRtt, err
}
