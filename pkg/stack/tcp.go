package stack

import (
	"encoding/binary"
	"net/netip"
	"sync"

	"ivat/pkg/headers"
)

// TCP 状态（RFC 9293 的最小子集）。
type tcpState int

const (
	tcpClosed tcpState = iota
	tcpSynSent
	tcpSynReceived
	tcpEstablished
	tcpFinWait
	tcpCloseWait
)

// TCPListener 监听本地端口。
type TCPListener struct {
	host   *Host
	port   uint16
	accept chan *TCPConn
}

// Accept 阻塞等待新连接（仿真中通过通道即时交付）。
func (l *TCPListener) Accept() *TCPConn { return <-l.accept }

// TCPConn 是一条 TCP 连接的最小实现。
type TCPConn struct {
	host        *Host
	listener    *TCPListener
	state       tcpState
	localPort   uint16
	remoteIP    netip.Addr
	remotePort  uint16
	iss         uint32 // 初始发送序号
	sndNXT      uint32
	rcvNXT      uint32
	established chan struct{}
	closeOnce   sync.Once
	mu          sync.Mutex
}

func (c *TCPConn) markEstablished() {
	c.closeOnce.Do(func() { close(c.established) })
}

// connKey 统一按"本机端口 + 对端地址 + 对端端口"索引连接，
// 主动端与被动端生成的键一致，入向段才能匹配到既有连接。
func connKey(local uint16, rip netip.Addr, rport uint16) string {
	return rip.String() + ":" + itoa(rport) + "->" + itoa(local)
}

func itoa(v uint16) string {
	const digits = "0123456789"
	if v == 0 {
		return "0"
	}
	var b [5]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = digits[v%10]
		v /= 10
	}
	return string(b[i:])
}

// ListenTCP 在本机端口上监听。
func (h *Host) ListenTCP(port uint16) *TCPListener {
	h.mu.Lock()
	defer h.mu.Unlock()
	l := &TCPListener{host: h, port: port, accept: make(chan *TCPConn, 16)}
	h.tcpLis[port] = l
	return l
}

// DialTCP 主动发起连接，发送 SYN。对端 SYN-ACK 到达时连接建立。
func (h *Host) DialTCP(dst netip.Addr, dstPort uint16) *TCPConn {
	h.mu.Lock()
	c := &TCPConn{
		host: h, localPort: h.ephemeralPort(),
		remoteIP: dst, remotePort: dstPort,
		iss:         h.nextISN(),
		established: make(chan struct{}),
	}
	c.sndNXT = c.iss + 1 // SYN 占一个序号
	c.rcvNXT = 0
	c.state = tcpSynSent
	h.tcpConn[connKey(c.localPort, dst, dstPort)] = c
	h.mu.Unlock()

	c.sendFlags(headers.TCPFlagSYN, nil, mssOption(h.InterfaceMTU))
	return c
}

// Established 等待三次握手完成（仿真即时）。
func (c *TCPConn) Established() <-chan struct{} { return c.established }

// Write 发送一段数据（自动带 PSH/ACK）。
func (c *TCPConn) Write(data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sendFlagsLocked(headers.TCPFlagPSH|headers.TCPFlagACK, data, nil)
}

// Close 发送 FIN 关闭本侧。
func (c *TCPConn) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sendFlagsLocked(headers.TCPFlagFIN|headers.TCPFlagACK, nil, nil)
	c.state = tcpFinWait
}

// State 返回当前状态码。
func (c *TCPConn) State() tcpState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// IsClosed 判断连接是否已关闭或处于挥手收尾。
func (c *TCPConn) IsClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state == tcpClosed || c.state == tcpCloseWait || c.state == tcpFinWait
}

// Remote 返回对端地址与端口。
func (c *TCPConn) Remote() (netip.Addr, uint16) { return c.remoteIP, c.remotePort }

func (h *Host) ephemeralPort() uint16 {
	// 用全局自增 ID 派生，仿真中天然不重复。
	return 40000 + (h.nextID() % 20000)
}

func (h *Host) nextISN() uint32 {
	return uint32(h.nextID())*0x9e37 + 1000
}

// mssOption 构造 SYN 里的 MSS 选项（kind=3, len=4, mss=MTU-40）。
func mssOption(mtu int) []byte {
	mss := mtu - headers.V4MinHeaderLen - headers.TCPMinLen
	opt := make([]byte, 4)
	opt[0] = 2 // MSS kind
	opt[1] = 4
	binary.BigEndian.PutUint16(opt[2:4], uint16(mss))
	return opt
}

func (c *TCPConn) sendFlags(flags uint8, data []byte, opts []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sendFlagsLocked(flags, data, opts)
}

// sendFlagsLocked 构造并发送一个 TCP 段。调用方持锁。
func (c *TCPConn) sendFlagsLocked(flags uint8, data []byte, opts []byte) {
	h := c.host
	hdrLen := headers.TCPMinLen + len(opts)
	th := &headers.TCPHeader{
		SrcPort:    c.localPort,
		DstPort:    c.remotePort,
		Seq:        c.sndNXT,
		Ack:        c.rcvNXT,
		DataOffset: uint8(hdrLen),
		Flags:      flags,
		Window:     65535,
		RawOptions: opts,
	}
	if flags&headers.TCPFlagACK == 0 {
		th.Ack = 0
	}
	seg := headers.BuildTCP(th, data)
	csum := headers.TransportChecksum(
		headers.PseudoHeaderV4(h.IP.As4(), c.remoteIP.As4(), headers.ProtoTCP, len(seg)),
		seg, headers.TCPChecksumPos())
	binary.BigEndian.PutUint16(seg[headers.TCPChecksumPos():], csum)

	c.sndNXT += uint32(len(data))
	if flags&headers.TCPFlagSYN != 0 || flags&headers.TCPFlagFIN != 0 {
		c.sndNXT++
	}
	h.sendV4(c.remoteIP, headers.ProtoTCP, seg, true)
}

func (h *Host) handleTCP(ip *headers.IPv4Header, seg []byte) {
	th, err := headers.ParseTCP(seg)
	if err != nil {
		return
	}
	h.mu.Lock()
	// 入向段：本机端口=目的端口，对端=源地址+源端口
	conn, known := h.tcpConn[connKey(th.DstPort, ip.Src, th.SrcPort)]
	lis, isListen := h.tcpLis[th.DstPort]
	h.mu.Unlock()
	if th.Flags&headers.TCPFlagRST != 0 {
		if known {
			conn.mu.Lock()
			conn.state = tcpClosed
			conn.mu.Unlock()
		}
		return
	}

	switch {
	case !known && th.Flags == headers.TCPFlagSYN && isListen:
		h.passiveOpen(lis, ip, th)
		return
	case !known:
		// 没有对应连接：回 RST
		h.sendRST(ip, th)
		return
	}

	conn.mu.Lock()

	if conn.state == tcpSynSent && th.Flags&(headers.TCPFlagSYN|headers.TCPFlagACK) ==
		(headers.TCPFlagSYN|headers.TCPFlagACK) {
		conn.rcvNXT = th.Seq + 1
		conn.state = tcpEstablished
		conn.sendFlagsLocked(headers.TCPFlagACK, nil, nil)
		conn.markEstablished()
		conn.mu.Unlock()
		return
	}
	// 仅在尚未建立时处理被动侧的握手 ACK，避免纯 ACK 重复进入把已建立
	// 连接的状态机搅乱（异步报文可能乱序到达）。
	if conn.state == tcpSynReceived && th.Flags&headers.TCPFlagACK != 0 {
		conn.state = tcpEstablished
		conn.markEstablished()
	}
	if conn.state != tcpEstablished && conn.state != tcpFinWait &&
		conn.state != tcpCloseWait {
		conn.mu.Unlock()
		return
	}

	// 数据：累计确认序号并缓存负载
	dataLen := uint32(len(seg) - int(th.DataOffset))
	var (
		hook     func(*TCPConn, []byte)
		echoData []byte
		finSeen  = th.Flags&headers.TCPFlagFIN != 0
	)
	if dataLen > 0 {
		payload := seg[th.DataOffset:]
		h.mu.Lock()
		key := ip.Src.String() + ":" + itoa(th.SrcPort)
		h.tcpRecv[key] = append(h.tcpRecv[key], payload...)
		hook = h.tcpDataHook
		echoData = append([]byte(nil), payload...)
		h.mu.Unlock()
		conn.rcvNXT = th.Seq + dataLen
		conn.sendFlagsLocked(headers.TCPFlagACK, nil, nil)
	}
	if finSeen {
		conn.rcvNXT = th.Seq + dataLen + 1
		conn.state = tcpCloseWait
		conn.sendFlagsLocked(headers.TCPFlagACK, nil, nil)
	}
	// 必须先释放连接锁再回调，回显应用的 Write 才能重新取锁发送。
	conn.mu.Unlock()
	if hook != nil && dataLen > 0 {
		hook(conn, echoData)
	}
	return
}

func (h *Host) passiveOpen(lis *TCPListener, ip *headers.IPv4Header, th *headers.TCPHeader) {
	h.mu.Lock()
	c := &TCPConn{
		host: h, listener: lis, localPort: th.DstPort,
		remoteIP: ip.Src, remotePort: th.SrcPort,
		iss:         h.nextISN(),
		established: make(chan struct{}),
	}
	c.sndNXT = c.iss + 1
	c.rcvNXT = th.Seq + 1
	c.state = tcpSynReceived
	h.tcpConn[connKey(th.DstPort, ip.Src, th.SrcPort)] = c
	h.mu.Unlock()

	c.mu.Lock()
	c.sendFlagsLocked(headers.TCPFlagSYN|headers.TCPFlagACK, nil, mssOption(h.InterfaceMTU))
	c.mu.Unlock()
	// 等对端 ACK 后由 handleTCP 入 accept；仿真里 ACK 立即到达，
	// 这里也先入队，accept 侧读取时连接已可用。
	lis.accept <- c
}

func (h *Host) sendRST(ip *headers.IPv4Header, th *headers.TCPHeader) {
	rst := &headers.TCPHeader{
		SrcPort: th.DstPort, DstPort: th.SrcPort,
		Seq: th.Ack, Flags: headers.TCPFlagRST, Window: 0,
		DataOffset: headers.TCPMinLen,
	}
	seg := headers.BuildTCP(rst, nil)
	csum := headers.TransportChecksum(
		headers.PseudoHeaderV4(h.IP.As4(), ip.Src.As4(), headers.ProtoTCP, len(seg)),
		seg, headers.TCPChecksumPos())
	binary.BigEndian.PutUint16(seg[headers.TCPChecksumPos():], csum)
	h.sendV4(ip.Src, headers.ProtoTCP, seg, true)
}
