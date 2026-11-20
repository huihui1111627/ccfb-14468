// Package stack 是仿真终端的迷你 IPv4 协议栈。
//
// 真实终端是只认 IPv4 的机顶盒/老电视，因此本栈只实现 IPv4：
//   - UDP（含端口不可达 ICMP、校验和）
//   - TCP（握手/数据/挥手的最小可用子集，含校验和与 MSS）
//   - ICMPv4 Echo（ping）与差错报文处理（PMTU 缓存、TTL 超时）
//
// 协议栈不碰真实网卡：进出报文通过注入的 Egress 函数交付，
// 由仿真网络（pkg/sim）接到 CE 的 LAN 口。
package stack

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"

	"ivat/pkg/headers"
)

// Egress 是协议栈向外发送完整 IPv4 报文的出口。
type Egress func(packet []byte)

// Host 是一台 IPv4 终端。
type Host struct {
	Name string
	IP   netip.Addr
	MAC  string // 仅用于展示
	// InterfaceMTU 是本机出口 MTU（以太网 1500；仿真可改小）。
	InterfaceMTU int

	out Egress

	mu      sync.Mutex
	udps    map[uint16]*UDPConn
	tcpLis  map[uint16]*TCPListener
	tcpConn map[string]*TCPConn
	// pmtu 缓存到每个目的地址的当前路径 MTU（RFC 1191 风格）。
	pmtu map[netip.Addr]int
	// 收到的 UDP/TCP 负载按流记录，供验收比对内容。
	udpRecv    map[string][][]byte
	udpPackets []*UDPPacket
	tcpRecv    map[string][]byte
	// tcpDataHook 在 TCP 数据入缓存后同步回调，供回显类应用即时响应。
	// 回调直接收到承载该数据的连接对象，避免再查表重入主机锁。
	tcpDataHook func(c *TCPConn, data []byte)
	// icmp 事件记录（ping 应答、超时、不可达）。
	icmpEvents []ICMPEvent
	idCounter  uint16
}

// ICMPEvent 记录终端收到的一个 ICMP 报文摘要。
type ICMPEvent struct {
	Type       uint8
	Code       uint8
	From       netip.Addr
	MTU        uint32
	InnerProto uint8
	InnerDst   netip.Addr
	InnerDPort uint16
}

func NewHost(name string, ip netip.Addr, out Egress) *Host {
	return &Host{
		Name:         name,
		IP:           ip,
		InterfaceMTU: 1500,
		out:          out,
		udps:         map[uint16]*UDPConn{},
		tcpLis:       map[uint16]*TCPListener{},
		tcpConn:      map[string]*TCPConn{},
		pmtu:         map[netip.Addr]int{},
		udpRecv:      map[string][][]byte{},
		tcpRecv:      map[string][]byte{},
	}
}

func (h *Host) nextID() uint16 {
	h.idCounter++
	return h.idCounter
}

// Deliver 是报文入口：CE 把 LAN 侧目的为本机的报文送到这里。
// 异步串行处理，避免"发送→网络→对端应答→再次进入本机"的同步
// 重入造成连接锁自锁。
func (h *Host) Deliver(packet []byte) {
	pkt := append([]byte(nil), packet...)
	go h.deliver(pkt)
}

func (h *Host) deliver(packet []byte) {
	ip, ihl, err := headers.ParseIPv4(packet)
	if err != nil {
		return
	}
	if ip.Dst != h.IP {
		return
	}
	payload := packet[ihl:]
	switch ip.Protocol {
	case headers.ProtoUDP:
		h.handleUDP(ip, payload)
	case headers.ProtoTCP:
		h.handleTCP(ip, payload)
	case headers.ProtoICMPv4:
		h.handleICMP(ip, payload)
	}
}

// ---------- 发送侧公共工具 ----------

func (h *Host) sendV4(dst netip.Addr, proto uint8, payload []byte, df bool) {
	total := headers.V4MinHeaderLen + len(payload)
	// 只按接口 MTU 约束；路径 MTU 差异靠对端回 Frag Needed/PTB 学习，
	// 不在出网卡前静默吞掉报文，否则 PMTUD 与 traceroute 无法工作。
	if total > h.InterfaceMTU {
		h.mu.Lock()
		h.pmtu[dst] = h.InterfaceMTU
		h.mu.Unlock()
		return
	}
	var flags uint16
	if df {
		flags = headers.V4FlagDF
	}
	hdr := &headers.IPv4Header{
		TOS:         0,
		TotalLength: uint16(total),
		ID:          h.nextID(),
		FlagsFrag:   flags,
		TTL:         64,
		Protocol:    proto,
		Src:         h.IP,
		Dst:         dst,
	}
	h.out(headers.BuildIPv4(hdr, payload))
}

func (h *Host) pathMTU(dst netip.Addr) int {
	if m, ok := h.pmtu[dst]; ok {
		return m
	}
	return h.InterfaceMTU
}

// PMTU 返回当前缓存的路径 MTU。
func (h *Host) PMTU(dst netip.Addr) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.pathMTU(dst)
}

func (h *Host) recordICMPLocal(dst netip.Addr, mtu uint32) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if cur, ok := h.pmtu[dst]; !ok || int(mtu) < cur {
		h.pmtu[dst] = int(mtu)
	}
}

// ---------- UDP ----------

// UDPConn 是一个绑定本地端口的 UDP socket。
type UDPConn struct {
	host *Host
	port uint16
}

func (h *Host) BindUDP(port uint16) *UDPConn {
	h.mu.Lock()
	defer h.mu.Unlock()
	c := &UDPConn{host: h, port: port}
	h.udps[port] = c
	return c
}

// SendTo 发送一个 UDP 数据报。
func (c *UDPConn) SendTo(dst netip.Addr, dstPort uint16, data []byte) {
	seg := headers.BuildUDP(&headers.UDPHeader{
		SrcPort: c.port, DstPort: dstPort, Length: uint16(headers.UDPLen + len(data)),
	}, data)
	csum := headers.TransportChecksum(
		headers.PseudoHeaderV4(c.host.IP.As4(), dst.As4(), headers.ProtoUDP, len(seg)),
		seg, headers.UDPChecksumPos())
	binary.BigEndian.PutUint16(seg[headers.UDPChecksumPos():], csum)
	c.host.sendV4(dst, headers.ProtoUDP, seg, true)
}

func (h *Host) handleUDP(ip *headers.IPv4Header, seg []byte) {
	uh, err := headers.ParseUDP(seg)
	if err != nil {
		return
	}
	h.mu.Lock()
	_, known := h.udps[uh.DstPort]
	h.mu.Unlock()
	if !known {
		// 端口不可达：回 ICMPv4 type3 code3，体内带回原报文头+数据前缀
		h.sendPortUnreachable(ip, seg)
		return
	}
	key := fmt.Sprintf("%s:%d", ip.Src, uh.SrcPort)
	h.mu.Lock()
	h.udpRecv[key] = append(h.udpRecv[key], append([]byte(nil), seg[headers.UDPLen:]...))
	h.udpPackets = append(h.udpPackets, &UDPPacket{
		From:     ip.Src,
		FromPort: uh.SrcPort,
		ToPort:   uh.DstPort,
		Data:     append([]byte(nil), seg[headers.UDPLen:]...),
	})
	h.mu.Unlock()
}

func (h *Host) sendPortUnreachable(orig *headers.IPv4Header, origSeg []byte) {
	body := h.quoteOriginal(orig, origSeg)
	msg := headers.BuildICMP(&headers.ICMPMessage{
		Type: headers.ICMP4DstUnreach, Code: headers.ICMP4PortUnreach, Body: body,
	})
	csum := headers.Checksum(msg)
	binary.BigEndian.PutUint16(msg[headers.ICMPChecksumPos():], csum)
	h.sendV4(orig.Src, headers.ProtoICMPv4, msg, false)
}

// quoteOriginal 按 RFC 792 把原始 IP 头加 8 字节传输头放进 ICMP 体内。
func (h *Host) quoteOriginal(orig *headers.IPv4Header, seg []byte) []byte {
	keep := headers.V4MinHeaderLen + 8
	if len(seg) < 8 {
		keep = headers.V4MinHeaderLen + len(seg)
	}
	origPkt := headers.BuildIPv4(orig, seg)
	if len(origPkt) > keep {
		origPkt = origPkt[:keep]
	}
	return origPkt
}

// UDPReceived 返回从某对端收到的全部数据报。
func (h *Host) UDPReceived(from netip.Addr, fromPort uint16) [][]byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.udpRecv[fmt.Sprintf("%s:%d", from, fromPort)]
}

// ---------- ICMP ----------

// Ping 发送一个 Echo Request，返回 ID/Seq 以便对应答配对。
func (h *Host) Ping(dst netip.Addr, seq uint16, ttl uint8) (id uint16) {
	id = h.nextID()
	var rest [4]byte
	headers.SetEchoID(&rest, id)
	headers.SetEchoSeq(&rest, seq)
	msg := headers.BuildICMP(&headers.ICMPMessage{
		Type: headers.ICMP4EchoRequest, Rest: rest,
		Body: []byte(fmt.Sprintf("ping-%s-%d", h.Name, seq)),
	})
	csum := headers.Checksum(msg)
	binary.BigEndian.PutUint16(msg[headers.ICMPChecksumPos():], csum)
	hdr := &headers.IPv4Header{
		TotalLength: uint16(headers.V4MinHeaderLen + len(msg)),
		ID:          h.nextID(),
		TTL:         ttl,
		Protocol:    headers.ProtoICMPv4,
		Src:         h.IP,
		Dst:         dst,
	}
	h.out(headers.BuildIPv4(hdr, msg))
	return id
}

func (h *Host) handleICMP(ip *headers.IPv4Header, seg []byte) {
	msg, err := headers.ParseICMP(seg)
	if err != nil {
		return
	}
	ev := ICMPEvent{Type: msg.Type, Code: msg.Code, From: ip.Src}
	switch msg.Type {
	case headers.ICMP4EchoRequest:
		h.replyEcho(ip, msg)
		return
	case headers.ICMP4EchoReply:
		h.mu.Lock()
		h.icmpEvents = append(h.icmpEvents, ev)
		h.mu.Unlock()
		return
	case headers.ICMP4DstUnreach:
		if msg.Code == headers.ICMP4FragNeededDF {
			ev.MTU = headers.MTU(msg.Rest)
			if inner, _, e := headers.ParseIPv4(msg.Body); e == nil {
				// 内层目的即本户曾发往的对端，PMTU 按该对端缓存。
				h.recordICMPLocal(inner.Dst, ev.MTU)
			}
		}
	case headers.ICMP4TimeExceed:
	}
	if inner, ihl, e := headers.ParseIPv4(msg.Body); e == nil && len(msg.Body) >= ihl {
		ev.InnerProto = inner.Protocol
		ev.InnerDst = inner.Dst
		if len(msg.Body) >= ihl+4 {
			ev.InnerDPort = binary.BigEndian.Uint16(msg.Body[ihl+2:])
		}
	}
	h.mu.Lock()
	h.icmpEvents = append(h.icmpEvents, ev)
	h.mu.Unlock()
}

func (h *Host) replyEcho(ip *headers.IPv4Header, req *headers.ICMPMessage) {
	reply := headers.BuildICMP(&headers.ICMPMessage{
		Type: headers.ICMP4EchoReply, Rest: req.Rest, Body: req.Body,
	})
	csum := headers.Checksum(reply)
	binary.BigEndian.PutUint16(reply[headers.ICMPChecksumPos():], csum)
	h.sendV4(ip.Src, headers.ProtoICMPv4, reply, false)
}

// ICMPEvents 返回收到的 ICMP 事件快照。
func (h *Host) ICMPEvents() []ICMPEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]ICMPEvent, len(h.icmpEvents))
	copy(out, h.icmpEvents)
	return out
}

// UDPReceived 返回某 TCP 对端流向本机的累计字节。
func (h *Host) TCPReceived(peer netip.Addr, peerPort uint16) []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.tcpRecv[fmt.Sprintf("%s:%d", peer, peerPort)]
}

// DebugTCPRecvKeys 仅供调试：返回本机记录 TCP 数据的全部对端键。
func (h *Host) DebugTCPRecvKeys() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	keys := make([]string, 0, len(h.tcpRecv))
	for k, v := range h.tcpRecv {
		keys = append(keys, fmt.Sprintf("%s=%d字节", k, len(v)))
	}
	return keys
}

// DebugTCPConns 仅供调试：返回连接表的键与状态。
func (h *Host) DebugTCPConns() map[string]int {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string]int, len(h.tcpConn))
	for k, c := range h.tcpConn {
		out[k] = int(c.State())
	}
	return out
}

// SetTCPDataHook 注册 TCP 数据到达回调（在接收处理中同步调用）。
func (h *Host) SetTCPDataHook(fn func(c *TCPConn, data []byte)) {
	h.mu.Lock()
	h.tcpDataHook = fn
	h.mu.Unlock()
}

// UDPPacket 是一条收到的 UDP 数据报及其来源（供回显服务器使用）。
type UDPPacket struct {
	From     netip.Addr
	FromPort uint16
	ToPort   uint16
	Data     []byte
	Echoed   bool
}

// UDPSnapshot 返回全部已收 UDP 数据报的快照。
func (h *Host) UDPSnapshot() []*UDPPacket {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]*UDPPacket(nil), h.udpPackets...)
}

// SendUDP 用临时源端口主动发送一个 UDP 数据报（服务器回显用）。
func (h *Host) SendUDP(dst netip.Addr, dstPort, srcPort uint16, data []byte) {
	seg := headers.BuildUDP(&headers.UDPHeader{
		SrcPort: srcPort, DstPort: dstPort,
		Length: uint16(headers.UDPLen + len(data)),
	}, data)
	csum := headers.TransportChecksum(
		headers.PseudoHeaderV4(h.IP.As4(), dst.As4(), headers.ProtoUDP, len(seg)),
		seg, headers.UDPChecksumPos())
	binary.BigEndian.PutUint16(seg[headers.UDPChecksumPos():], csum)
	h.sendV4(dst, headers.ProtoUDP, seg, true)
}
