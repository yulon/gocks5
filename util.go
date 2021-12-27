package gocks5

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
)

var errClosed = errors.New("connection is closed")
var errBufferOverflow = errors.New("buffer overflow")

func writeAll(w io.Writer, p []byte) error {
	wSzAll := 0
	for wSzAll < len(p) {
		wSz, err := w.Write(p[wSzAll:])
		if err != nil {
			return err
		}
		wSzAll += wSz
	}
	return nil
}

func readFull(r io.Reader, p []byte) error {
	rSzAll := 0
	for rSzAll < len(p) {
		rSz, err := r.Read(p[rSzAll:])
		if err != nil {
			return err
		}
		rSzAll += rSz
	}
	return nil
}

func readLeast(r io.Reader, p []byte, leastSz int) (int, error) {
	rSzAll := 0
	for rSzAll < leastSz {
		rSz, err := r.Read(p[rSzAll:])
		if err != nil {
			return 0, err
		}
		rSzAll += rSz
	}
	return rSzAll, nil
}

func readString(r io.Reader, b []byte) (string, []byte, error) {
	rSzAll := 0
	for {
		rSz, err := r.Read(b[rSzAll:])
		if err != nil {
			return "", nil, err
		}
		for i := 0; i < rSz; i++ {
			if b[rSzAll+i] == 0 {
				return string(b[:rSzAll+i]), b[rSzAll+i+1:], nil
			}
		}
		rSzAll += rSz
	}
}

var errNotFoundTailingString = errors.New("not found a tailing string")

func splitTailingString(p []byte) (int, string, error) {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == 0 {
			return i, string(p[i+1:]), nil
		}
	}
	return 0, "", errNotFoundTailingString
}

func writeStrWithSz(w io.Writer, str string) error {
	strBytes := []byte(str)
	strLen := uint16(len(strBytes))
	err := binary.Write(w, binary.LittleEndian, &strLen)
	if err != nil {
		return err
	}
	return writeAll(w, strBytes)
}

func copyAndClose(dest io.WriteCloser, src io.ReadCloser) {
	defer src.Close()
	defer dest.Close()
	io.Copy(dest, src)
}

func linkConn(dest, src net.Conn) {
	go copyAndClose(src, dest)
	copyAndClose(dest, src)
}

func copyAndClosePacketConn(dest, src net.PacketConn) {
	defer src.Close()
	defer dest.Close()
	p := make([]byte, 2048)
	for {
		n, addr, err := src.ReadFrom(p)
		if err != nil {
			return
		}
		_, err = dest.WriteTo(p[:n], addr)
		if err != nil {
			return
		}
	}
}

func linkPacketConn(dest, src net.PacketConn) {
	go copyAndClosePacketConn(src, dest)
	copyAndClosePacketConn(dest, src)
}

func ipZeroFrom(r net.IP) net.IP {
	ip4 := r.To4()
	if ip4 != nil {
		return net.IPv4zero
	}
	return net.IPv6zero
}
