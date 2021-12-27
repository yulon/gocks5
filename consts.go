package gocks5

const (
	// Ver is socks protocol version
	Ver byte = 0x05

	// MethodNone is none method
	MethodNone byte = 0x00
	// MethodGSSAPI is gssapi method
	MethodGSSAPI byte = 0x01 // MUST support // todo
	// MethodUsernamePassword is username/assword auth method
	MethodUsernamePassword byte = 0x02 // SHOULD support
	// MethodUnsupportAll means unsupport all given methods
	MethodUnsupportAll byte = 0xFF

	// UserPassVer is username/password auth protocol version
	UserPassVer byte = 0x01
	// UserPassStatusSuccess is success status of username/password auth
	UserPassStatusSuccess byte = 0x00
	// UserPassStatusFailure is failure status of username/password auth
	UserPassStatusFailure byte = 0x01 // just other than 0x00

	// CmdConnect is connect command
	CmdConnect byte = 0x01
	// CmdBind is bind command
	CmdBind byte = 0x02
	// CmdUDP is UDP command
	CmdUDP byte = 0x03

	// AtypIPv4 is ipv4 address type
	AtypIPv4 byte = 0x01 // 4 octets
	// AtypDomain is domain address type
	AtypDomain byte = 0x03 // The first octet of the address field contains the number of octets of name that follow, there is no terminating NUL octet.
	// AtypIPv6 is ipv6 address type
	AtypIPv6 byte = 0x04 // 16 octets

	// RepSuccess means that success for repling
	RepSuccess byte = 0x00
	// RepServerFailure means the server failure
	RepServerFailure byte = 0x01
	// RepNotAllowed means the request not allowed
	RepNotAllowed byte = 0x02
	// RepNetworkUnreachable means the network unreachable
	RepNetworkUnreachable byte = 0x03
	// RepHostUnreachable means the host unreachable
	RepHostUnreachable byte = 0x04
	// RepConnectionRefused means the connection refused
	RepConnectionRefused byte = 0x05
	// RepTTLExpired means the TTL expired
	RepTTLExpired byte = 0x06
	// RepCommandNotSupported means the request command not supported
	RepCommandNotSupported byte = 0x07
	// RepAddressNotSupported means the request address not supported
	RepAddressNotSupported byte = 0x08
)
