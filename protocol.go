package tuicv4

const (
	Version = 4
)

const (
	CommandAuthenticate = iota
	CommandConnect
	CommandPacket
	CommandDissociate
	CommandHeartbeat
	CommandResponse = 0xff
)

const (
	OptionResponseSuccess          = 0x00
	OptionResponseFailed           = 0xff
	ErrorCodeProtocolError         = uint64(0xfffffff0)
	ErrorCodeAuthenticationFailed  = uint64(0xfffffff1)
	ErrorCodeAuthenticationTimeout = uint64(0xfffffff2)
	ErrorCodeBadCommand            = uint64(0xfffffff3)
)

const AuthenticateLen = 2 + 32
