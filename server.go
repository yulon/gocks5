package gocks5

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/yulon/go-netil"
)

type Server struct {
	Dial                   func(addr net.Addr) (net.Conn, error)
	ListenPacket           func() (net.PacketConn, error)
	PreAuth                func(cltAddr net.Addr) bool
	Auth                   func(cltAddr net.Addr, user *url.Userinfo) (bool, *UserConfig)
	DisableConcAuth        bool
	AuthConcLimit          *netil.QuantityLimiter
	StreamForwardConcLimit *netil.QuantityLimiter
	ProxyPacketConnPool    *netil.PacketConnPool
	PublicPacketConnPool   *netil.PacketConnPool
	DisableResponseError   bool
	IdleTimeout            time.Duration
}

type UserConfig struct {
	Dial         func(addr net.Addr) (net.Conn, error)
	ListenPacket func() (net.PacketConn, error)
}

var ErrorMethodNumberZero = errors.New("method number zero")
var ErrorUsernameEmpty = errors.New("username empty")
var ErrorPasswordEmpty = errors.New("password empty")

func (con *Conn) recvHandshake(buf []byte, svr *Server) (string, *UserConfig, error) {
	/*
		+----+----------+----------+
		|VER | NMETHODS | METHODS  |
		+----+----------+----------+
		| 1  |    1     | 1 to 255 |
		+----+----------+----------+
	*/

	err := netil.ReadFull(con, buf[:2])
	if err != nil {
		return "", nil, err
	}
	if buf[0] != Ver {
		return "", nil, errors.New("unsupported SOCKS version " + strconv.Itoa(int(buf[0])))
	}

	if buf[1] == 0 {
		return "", nil, ErrorMethodNumberZero
	}

	n := int(buf[1])
	err = netil.ReadFull(con, buf[:n])
	if err != nil {
		return "", nil, err
	}

	method := MethodNone
	if svr.Auth != nil {
		method = MethodUsernamePassword
	}

	foundMethod := false
	for _, b := range buf[:n] {
		if b == method {
			foundMethod = true
			break
		}
	}
	if !foundMethod {
		err = ErrorUnsupportedMethods
		if svr.DisableResponseError {
			return "", nil, err
		}
		method = MethodUnsupportAll
	}

	/*
		+----+--------+
		|VER | METHOD |
		+----+--------+
		| 1  |   1    |
		+----+--------+
	*/

	buf[0] = Ver
	buf[1] = method
	werr := netil.WriteAll(con, buf[:2])
	if werr != nil {
		if err == nil {
			err = werr
		}
		return "", nil, err
	}

	if svr.Auth == nil {
		return "", nil, nil
	}

	/*
		+----+------+----------+------+----------+
		|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
		+----+------+----------+------+----------+
		| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
		+----+------+----------+------+----------+
	*/

	err = netil.ReadFull(con, buf[:2])
	if err != nil {
		return "", nil, err
	}
	if buf[0] != UserPassVer {
		return "", nil, errors.New("unsupported auth " + strconv.Itoa(int(buf[0])))
	}

	usernameLen := int(buf[1])
	if usernameLen == 0 {
		return "", nil, ErrorUsernameEmpty
	}
	err = netil.ReadFull(con, buf[:usernameLen+1])
	if err != nil {
		return "", nil, err
	}
	username := string(buf[:usernameLen])

	passwordLen := int(buf[usernameLen])
	if passwordLen == 0 {
		return "", nil, ErrorPasswordEmpty
	}
	err = netil.ReadFull(con, buf[:passwordLen])
	if err != nil {
		return "", nil, err
	}
	password := string(buf[:passwordLen])

	ok, uc := svr.Auth(con.RemoteAddr(), url.UserPassword(username, password))

	/*
		+----+--------+
		|VER | STATUS |
		+----+--------+
		| 1  |   1    |
		+----+--------+
	*/

	status := UserPassStatusSuccess
	if !ok {
		err = ErrorUnauthorized
		if svr.DisableResponseError {
			return "", nil, err
		}
		status = UserPassStatusFailure
	}

	buf[0] = UserPassVer
	buf[1] = status
	werr = netil.WriteAll(con, buf[:2])
	if err == nil {
		err = werr
	}
	if err != nil {
		return "", nil, err
	}
	return username, uc, nil
}

func (svr *Server) authBegin() bool {
	if svr.AuthConcLimit == nil {
		return false
	}
	svr.AuthConcLimit.Lock()
	return true
}

func (svr *Server) authDone(isLimitedConc bool, needRecBuf bool, buf []byte) {
	if isLimitedConc {
		svr.AuthConcLimit.Unlock()
	}
	if needRecBuf {
		//netil.RecycleBuffer(buf)
	}
}

func (svr *Server) streamForwardBegin() bool {
	if svr.StreamForwardConcLimit == nil {
		return false
	}
	svr.StreamForwardConcLimit.Lock()
	return true
}

func (svr *Server) streamForwardDone(isLimitedConc bool, needRecBuf bool, buf []byte) {
	if isLimitedConc {
		svr.StreamForwardConcLimit.Unlock()
	}
	if needRecBuf {
		//netil.RecycleBuffer(buf)
	}
}

var fakeBuf [32 * 1024]byte

func (con *Conn) listenUDPProxy() (*net.UDPConn, error) {
	udpPxyAddr, err := netil.CopyToUDPAddr(con.LocalAddr())
	if err != nil {
		return nil, err
	}
	udpPxyAddr.Port = 0

	udpPxyRawCon, err := net.ListenUDP("udp", udpPxyAddr)
	if err != nil {
		return nil, err
	}
	return udpPxyRawCon, nil
}

func (svr *Server) forward(cltCon *Conn, username string, uc *UserConfig, isLimitedConc bool, buf []byte, needRecBuf bool) error {
	cmd, dstAddr, err := cltCon.ReadAddr()
	if err != nil {
		svr.streamForwardDone(isLimitedConc, needRecBuf, buf)
		cltCon.Close()
		return err
	}

	dial := svr.Dial
	listenPacket := svr.ListenPacket
	if uc != nil {
		if uc.Dial != nil {
			dial = uc.Dial
		}
		if uc.ListenPacket != nil {
			listenPacket = uc.ListenPacket
		}
	}

	if cmd == CmdConnect {
		destCon, err := netil.DialOrDirect(dstAddr, dial)
		if err != nil {
			svr.streamForwardDone(isLimitedConc, needRecBuf, buf)
			cltCon.Close()
			return err
		}

		destDialerAddr, err := netil.ToTCPAddr(destCon.LocalAddr())
		if err != nil {
			svr.streamForwardDone(isLimitedConc, needRecBuf, buf)
			cltCon.Close()
			destCon.Close()
			return err
		}

		//err = cltCon.WriteAddr(RepSuccess, DomainAddr(":"+strconv.Itoa(destDialerAddr.Port)))
		err = cltCon.WriteAddr(RepSuccess, &net.TCPAddr{IP: net.IPv4zero, Port: destDialerAddr.Port, Zone: destDialerAddr.Zone})
		if err != nil {
			svr.streamForwardDone(isLimitedConc, needRecBuf, buf)
			cltCon.Close()
			destCon.Close()
			return err
		}

		netil.ForwardTimeout(cltCon, destCon, buf, svr.IdleTimeout, 5*time.Second)

		svr.streamForwardDone(isLimitedConc, needRecBuf, buf)
		return nil
	}
	svr.streamForwardDone(isLimitedConc, needRecBuf, buf)

	if cmd != CmdUDPAssociate {
		cltCon.WriteAddr(RepCommandNotSupported, nil)
		cltCon.Close()
		return errors.New("command " + strconv.Itoa(int(cmd)) + " not supported")
	}

	if svr.ProxyPacketConnPool != nil {
		udpPxyCon, err := svr.ProxyPacketConnPool.Get(username+"@"+cltCon.LocalAddr().String(), "", func() (net.PacketConn, error) {
			upcon, err := cltCon.listenUDPProxy()
			if err != nil {
				return nil, err
			}
			go func() {
				netil.ForwardPacket(&packetConn{PacketConn: upcon}, nil, "", listenPacket, svr.PublicPacketConnPool)
			}()
			return upcon, nil
		})
		if err != nil {
			cltCon.Close()
			return err
		}

		udpPxyAddr, err := netil.ToUDPAddr(udpPxyCon.LocalAddr())
		if err != nil {
			cltCon.Close()
			return err
		}
		err = cltCon.WriteAddr(RepSuccess, &net.UDPAddr{IP: net.IPv4zero, Port: udpPxyAddr.Port, Zone: udpPxyAddr.Zone})
		if err != nil {
			cltCon.Close()
			return err
		}

		go func() {
			defer cltCon.Close()
			for {
				_, err := cltCon.Read(fakeBuf[:])
				if err != nil {
					return
				}
			}
		}()
		return nil
	}

	udpPxyRawCon, err := cltCon.listenUDPProxy()
	if err != nil {
		cltCon.Close()
		return err
	}
	udpPxyCon := &packetConn{PacketConn: udpPxyRawCon, keepAliveCon: cltCon}

	udpPxyAddr, err := netil.ToUDPAddr(udpPxyRawCon.LocalAddr())
	if err != nil {
		udpPxyCon.Close()
		return err
	}
	//err = cltCon.WriteAddr(RepSuccess, DomainAddr(":"+strconv.Itoa(udpPxyAddr.Port)))
	err = cltCon.WriteAddr(RepSuccess, &net.UDPAddr{IP: net.IPv4zero, Port: udpPxyAddr.Port, Zone: udpPxyAddr.Zone})
	if err != nil {
		udpPxyCon.Close()
		return err
	}

	go func() {
		defer udpPxyCon.Close()
		for {
			_, err := cltCon.Read(fakeBuf[:])
			if err != nil {
				return
			}
		}
	}()

	return netil.ForwardPacket(udpPxyCon, nil, username, listenPacket, svr.PublicPacketConnPool)
}

func (svr *Server) handle(rawCon net.Conn, isLimitedConc bool, buf []byte) error {
	needRecBuf := false
	if len(buf) == 0 {
		buf = make([]byte, 4096)
	}

	cltCon := newConn(rawCon)

	username, uc, err := cltCon.recvHandshake(buf, svr)
	if err != nil {
		svr.authDone(isLimitedConc, needRecBuf, buf)
		cltCon.Close()
		return err
	}
	svr.authDone(isLimitedConc, false, nil)

	if svr.DisableConcAuth {
		go func() {
			svr.forward(cltCon, username, uc, svr.streamForwardBegin(), buf, needRecBuf)
		}()
		return nil
	}
	return svr.forward(cltCon, username, uc, svr.streamForwardBegin(), buf, needRecBuf)
}

func (svr *Server) Handle(rawCon net.Conn, buf []byte) error {
	return svr.handle(rawCon, false, buf)
}

func (svr *Server) Serve(lnr net.Listener) error {
	defer lnr.Close()

	for {
		rawCon, err := lnr.Accept()
		if err != nil {
			return err
		}
		if svr.PreAuth != nil && !svr.PreAuth(rawCon.RemoteAddr()) {
			continue
		}
		if svr.DisableConcAuth {
			svr.handle(rawCon, false, nil)
			continue
		}
		isLimitedConc := svr.authBegin()
		go func() {
			svr.handle(rawCon, isLimitedConc, nil)
		}()
	}
}

func Serve(lnr net.Listener) error {
	svr := &Server{}
	return svr.Serve(lnr)
}

func (svr *Server) ListenAndServe(addr string) error {
	lnr, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return svr.Serve(lnr)
}

func ListenAndServe(addr string) error {
	svr := &Server{}
	return svr.ListenAndServe(addr)
}
