package tuicv4

import (
	"context"
	"io"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
	"lukechampine.com/blake3"
)

type ClientOptions struct {
	Context           context.Context
	Dialer            N.Dialer
	ServerAddress     M.Socksaddr
	TLSConfig         aTLS.Config
	Password          string
	CongestionControl string
	UDPStream         bool
	UDPMTU            int
	ZeroRTTHandshake  bool
	Heartbeat         time.Duration

	allowAllCongestionControl bool // do not export
}

type Client struct {
	ctx               context.Context
	dialer            N.Dialer
	serverAddr        M.Socksaddr
	tlsConfig         aTLS.Config
	quicConfig        *quic.Config
	password          string
	congestionControl string
	udpStream         bool
	udpMTU            int
	zeroRTTHandshake  bool
	heartbeat         time.Duration

	connAccess sync.Mutex
	conn       *clientQUICConnection
}

func NewClient(options ClientOptions) (*Client, error) {
	if options.Heartbeat == 0 {
		options.Heartbeat = 10 * time.Second
	}
	quicConfig := &quic.Config{
		DisablePathMTUDiscovery: !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		EnableDatagrams:         true,
		MaxIncomingUniStreams:   1 << 60,
	}
	switch options.CongestionControl {
	case "":
		options.CongestionControl = "cubic"
	case "cubic", "new_reno", "bbr", "bbr2":
	default:
		if !options.allowAllCongestionControl {
			return nil, E.New("unknown congestion control algorithm: ", options.CongestionControl)
		}
	}
	udpMTU := options.UDPMTU
	if udpMTU == 0 {
		udpMTU = 1200 - 3
	}
	return &Client{
		ctx:               options.Context,
		dialer:            options.Dialer,
		serverAddr:        options.ServerAddress,
		tlsConfig:         options.TLSConfig,
		quicConfig:        quicConfig,
		password:          options.Password,
		congestionControl: options.CongestionControl,
		udpStream:         options.UDPStream,
		udpMTU:            options.UDPMTU,
		zeroRTTHandshake:  options.ZeroRTTHandshake,
		heartbeat:         options.Heartbeat,
	}, nil
}

func (c *Client) offer(ctx context.Context) (*clientQUICConnection, error) {
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	conn := c.conn
	if conn != nil && conn.active() {
		return conn, nil
	}
	conn, err := c.offerNew(ctx)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (c *Client) offerNew(_ context.Context) (*clientQUICConnection, error) {
	udpConn, err := c.dialer.DialContext(c.ctx, "udp", c.serverAddr)
	if err != nil {
		return nil, err
	}
	var quicConn *quic.Conn
	if c.zeroRTTHandshake {
		quicConn, err = qtls.DialEarly(c.ctx, bufio.NewUnbindPacketConn(udpConn), udpConn.RemoteAddr(), c.tlsConfig, c.quicConfig)
	} else {
		quicConn, err = qtls.Dial(c.ctx, bufio.NewUnbindPacketConn(udpConn), udpConn.RemoteAddr(), c.tlsConfig, c.quicConfig)
	}
	if err != nil {
		udpConn.Close()
		return nil, E.Cause(err, "open connection")
	}
	setCongestion(c.ctx, quicConn, c.congestionControl)
	conn := &clientQUICConnection{
		quicConn:   quicConn,
		rawConn:    udpConn,
		connDone:   make(chan struct{}),
		udpConnMap: make(map[uint32]*udpPacketConn),
	}
	go func() {
		hErr := c.clientHandshake(quicConn)
		if hErr != nil {
			conn.closeWithError(hErr)
		}
	}()
	if c.udpStream {
		go c.loopUniStreams(conn)
	} else {
		go c.loopMessages(conn)
	}
	go c.loopHeartbeats(conn)
	c.conn = conn
	return conn, nil
}

func (c *Client) clientHandshake(conn *quic.Conn) error {
	authStream, err := conn.OpenUniStream()
	if err != nil {
		return E.Cause(err, "open handshake stream")
	}
	defer authStream.Close()
	tuicAuthToken := blake3.Sum256([]byte(c.password))
	authRequest := buf.NewSize(AuthenticateLen)
	authRequest.WriteByte(Version)
	authRequest.WriteByte(CommandAuthenticate)
	authRequest.Write(tuicAuthToken[:])
	return common.Error(authStream.Write(authRequest.Bytes()))
}

func (c *Client) loopHeartbeats(conn *clientQUICConnection) {
	ticker := time.NewTicker(c.heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-conn.connDone:
			return
		case <-ticker.C:
			stream, err := conn.quicConn.OpenUniStream()
			if err != nil {
				continue
			}
			_, _ = stream.Write([]byte{Version, CommandHeartbeat})
			stream.Close()
		}
	}
}

func (c *Client) DialConn(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	conn, err := c.offer(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := conn.quicConn.OpenStream()
	if err != nil {
		return nil, err
	}
	return &clientConn{
		Stream:      stream,
		parent:      conn,
		destination: destination,
	}, nil
}

func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	conn, err := c.offer(ctx)
	if err != nil {
		return nil, err
	}
	var sessionID uint32
	clientPacketConn := newUDPPacketConn(c.ctx, conn.quicConn, c.udpStream, c.udpMTU, false, func() {
		conn.udpAccess.Lock()
		delete(conn.udpConnMap, sessionID)
		conn.udpAccess.Unlock()
	})
	conn.udpAccess.Lock()
	sessionID = conn.udpSessionID
	conn.udpSessionID++
	conn.udpConnMap[sessionID] = clientPacketConn
	conn.udpAccess.Unlock()
	clientPacketConn.sessionID = sessionID
	return clientPacketConn, nil
}

func (c *Client) CloseWithError(err error) error {
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	conn := c.conn
	if conn != nil {
		conn.closeWithError(err)
	}
	return nil
}

type clientQUICConnection struct {
	quicConn     *quic.Conn
	rawConn      io.Closer
	closeOnce    sync.Once
	connDone     chan struct{}
	connErr      error
	udpAccess    sync.RWMutex
	udpConnMap   map[uint32]*udpPacketConn
	udpSessionID uint32
}

func (c *clientQUICConnection) active() bool {
	select {
	case <-c.quicConn.Context().Done():
		return false
	default:
	}
	select {
	case <-c.connDone:
		return false
	default:
	}
	return true
}

func (c *clientQUICConnection) closeWithError(err error) {
	c.closeOnce.Do(func() {
		c.connErr = err
		close(c.connDone)
		_ = c.quicConn.CloseWithError(0, "")
		_ = c.rawConn.Close()
	})
}

type clientConn struct {
	*quic.Stream
	parent         *clientQUICConnection
	destination    M.Socksaddr
	requestWritten bool
	responseRead   bool
}

func (c *clientConn) NeedHandshake() bool {
	return !c.requestWritten
}

func (c *clientConn) Read(b []byte) (n int, err error) {
	if !c.responseRead {
		// TUIC is not resistant to active detection at all,
		// so it is okay to read byte-by-byte.
		var data [1]byte
		_, err = c.Stream.Read(data[:])
		if data[0] != Version {
			return 0, E.New("unknown version: ", data[0])
		}
		_, err = c.Stream.Read(data[:])
		if data[0] != CommandResponse {
			return 0, E.New("unknown command: ", data[0])
		}
		_, err = c.Stream.Read(data[:])
		if data[0] == OptionResponseFailed {
			return 0, E.New("response failed")
		}
		if data[0] != OptionResponseSuccess {
			return 0, E.New("unknown response: ", data[0])
		}
		c.responseRead = true
	}
	n, err = c.Stream.Read(b)
	return n, qtls.WrapError(err)
}

func (c *clientConn) Write(b []byte) (n int, err error) {
	if !c.requestWritten {
		request := buf.NewSize(2 + AddressSerializer.AddrPortLen(c.destination) + len(b))
		defer request.Release()
		request.WriteByte(Version)
		request.WriteByte(CommandConnect)
		err = AddressSerializer.WriteAddrPort(request, c.destination)
		if err != nil {
			return n, err
		}
		request.Write(b)
		_, err = c.Stream.Write(request.Bytes())
		if err != nil {
			c.parent.closeWithError(E.Cause(err, "create new connection"))
			return 0, qtls.WrapError(err)
		}
		c.requestWritten = true
		return len(b), nil
	}
	n, err = c.Stream.Write(b)
	return n, qtls.WrapError(err)
}

func (c *clientConn) Close() error {
	c.Stream.CancelRead(0)
	return c.Stream.Close()
}

func (c *clientConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *clientConn) RemoteAddr() net.Addr {
	return c.destination
}
