package gocks5

import (
	"errors"
	"net"
	"time"
)

func Pass(addr, user, passwd string) (*Conn, time.Duration, error) {
	tcpCon, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, -1, err
	}
	con := &Conn{tcpCon}
	rtt, err := con.sendHandshake(user, passwd)
	if err != nil {
		con.Close()
		return nil, rtt, err
	}
	return con, rtt, nil
}

var ErrorNotSuportedGSSAPI = errors.New("not suported GSSAPI")
var ErrorNoMethodAvailabled = errors.New("no method availabled")
var ErrorUnknowMethod = errors.New("unknow method")
var ErrorBadCertificate = errors.New("bad certificate")
var ErrorInvalidCertificate = errors.New("invalid certificate")
var ErrorAuthenticationFailed = errors.New("authentication failed")

func (con *Conn) sendHandshake(user, passwd string) (time.Duration, error) {
	userLen := len(user)
	passwdLen := len(passwd)
	hasUserPasswd := userLen > 0 || passwdLen > 0

	/*
		+----+----------+----------+
		|VER | NMETHODS | METHODS  |
		+----+----------+----------+
		| 1  |    1     | 1 to 255 |
		+----+----------+----------+
	*/

	p := []byte{Ver, 1, MethodNone}
	if hasUserPasswd {
		if userLen == 0 || userLen > 255 || passwdLen == 0 || passwdLen > 255 {
			return -1, ErrorBadCertificate
		}
		p[1]++
		p = append(p, MethodUsernamePassword)
	}

	now := time.Now()

	err := writeAll(con, p)
	if err != nil {
		return -1, err
	}
	authSz := 3 + userLen + passwdLen
	buf := make([]byte, authSz)

	/*
		+----+--------+
		|VER | METHOD |
		+----+--------+
		| 1  |   1    |
		+----+--------+
	*/

	err = readFull(con, buf[:2])
	if err != nil {
		return -1, err
	}

	rtt := time.Now().Sub(now)

	switch buf[1] {
	case MethodNone:
		return rtt, nil

	case MethodGSSAPI:
		return rtt, ErrorNotSuportedGSSAPI

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
		buf[base] = byte(userLen)

		base++
		copy(buf[base:], []byte(user))

		base += userLen
		buf[base] = byte(passwdLen)

		base++
		copy(buf[base:], []byte(passwd))

		err := writeAll(con, buf)
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

		err = readFull(con, buf[:2])
		if err != nil {
			return rtt, err
		}

		if buf[1] != UserPassStatusSuccess {
			return rtt, ErrorAuthenticationFailed
		}
		return rtt, nil

	case MethodUnsupportAll:
		return rtt, ErrorNoMethodAvailabled
	}
	return rtt, ErrorUnknowMethod
}

var ErrorServerFailure = errors.New("server failure")
var ErrorNotAllowed = errors.New("request not allowed")
var ErrorNetworkUnreachable = errors.New("network unreachable")
var ErrorHostUnreachable = errors.New("host unreachable")
var ErrorConnectionRefused = errors.New("connection refused")
var ErrorTTLExpired = errors.New("TTL expired")
var ErrorCommandNotSupported = errors.New("request command not supported")
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

func DialTCPPass(server, user, passwd string, dst net.Addr) (net.Conn, time.Duration, time.Duration, error) {
	con, pxyRtt, err := Pass(server, user, passwd)
	if err != nil {
		return nil, pxyRtt, -1, err
	}
	tcpCon, dstRtt, err := con.DialTCP(dst)
	if err != nil {
		con.Close()
		return nil, pxyRtt, dstRtt, err
	}
	return tcpCon, pxyRtt, dstRtt, err
}

func (con *Conn) ListenUDP() (net.PacketConn, time.Duration, error) {
	udpPxyAddr, rtt, err := con.Command(CmdUDP, &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, rtt, err
	}
	udpPxyPubAddr, err := con.ResolveRemoteAddr(udpPxyAddr)
	if err != nil {
		return nil, rtt, err
	}
	udpPxyPubUDPAddr, err := AddrToUDP(udpPxyPubAddr)
	if err != nil {
		return nil, rtt, err
	}
	udpPxyUDPCon, err := net.DialUDP("udp", nil, udpPxyPubUDPAddr)
	if err != nil {
		return nil, rtt, err
	}
	return &udpConn{con.Conn, udpPxyUDPCon}, rtt, nil
}

func ListenUDPPass(server, user, passwd string) (net.PacketConn, time.Duration, time.Duration, error) {
	con, pxyRtt, err := Pass(server, user, passwd)
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
