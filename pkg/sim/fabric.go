// Package sim 是整套方案的网络仿真：用进程内函数调用模拟链路，
// 把用户侧网关（CE）、边界设备（BR）、IPv6 骨干、IPv4 外网和终端接起来。
//
// 仿真网络里唯一的"表"是链路层地址解析（等价于 NDP/MAC 表），
// 属于正常路由设施；BR 内部不存在任何按连接建立的映射表。
package sim

import (
	"encoding/binary"
	"net/netip"
	"sync"

	"ivat/pkg/headers"
)

// Port 是设备上的一个接口：向接口写报文即"链路发送"。
type Port func(packet []byte)

// V6Cloud 模拟 IPv6 骨干与接入网：按目的 IPv6 地址把报文送到对应 CE，
// 默认路由送往 BR。每经过一个模拟跳点递减 HopLimit，到 0 回 ICMPv6
// 超时；报文超过链路 MTU 时回 Packet Too Big。
type V6Cloud struct {
	mu sync.Mutex

	cePorts map[netip.Addr]Port // CE WAN 地址 → CE WAN 接口（链路层解析表）
	brPort  Port                // 默认路由：BR 骨干侧接口
	brAddr  netip.Addr

	// 跳数：CE 之间 2 跳，CE 到 BR 3 跳（可配置）。
	HopsCEToCE int
	HopsCEToBR int
	// LinkMTU 是骨干链路 MTU，0 表示不限制。
	LinkMTU int

	cloudAddr netip.Addr // 云自身产生 ICMP 时用的源地址
	stats     CloudStats
}

// CloudStats 记录骨干侧事件计数。
type CloudStats struct {
	Delivered  int
	HopExpired int
	TooBig     int
	Dropped    int
}

func NewV6Cloud(brAddr netip.Addr, brPort Port) *V6Cloud {
	return &V6Cloud{
		cePorts:    map[netip.Addr]Port{},
		brPort:     brPort,
		brAddr:     brAddr,
		HopsCEToCE: 2,
		HopsCEToBR: 3,
		LinkMTU:    1400,
		cloudAddr:  netip.MustParseAddr("fe80::1"),
	}
}

// AttachCE 把一台 CE 的 WAN 接口挂到接入云（等价于 NDP 学习）。
func (c *V6Cloud) AttachCE(wanAddr netip.Addr, p Port) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cePorts[wanAddr] = p
}

// Send 是接入云的收包入口（任何 CE 或 BR 向骨干发送都走这里）。
func (c *V6Cloud) Send(packet []byte) {
	h, err := headers.ParseIPv6(packet)
	if err != nil {
		c.mu.Lock()
		c.stats.Dropped++
		c.mu.Unlock()
		return
	}

	// 选路与跳数。
	c.mu.Lock()
	dstPort, isCE := c.cePorts[h.Dst]
	hops := c.HopsCEToCE
	if !isCE {
		dstPort = c.brPort
		hops = c.HopsCEToBR
	}
	mtu := c.LinkMTU
	c.mu.Unlock()

	// MTU 检查在递减之前：超长报文直接 PTB（RFC 8200 中间设备不分片）。
	if mtu > 0 && len(packet) > mtu {
		c.mu.Lock()
		c.stats.TooBig++
		c.mu.Unlock()
		c.sendPTB(h, packet, uint32(mtu))
		return
	}

	// 逐跳递减 HopLimit。
	remain := int(h.HopLimit) - hops
	if remain <= 0 {
		c.mu.Lock()
		c.stats.HopExpired++
		c.mu.Unlock()
		c.sendHopExpired(h, packet)
		return
	}
	out := append([]byte(nil), packet...)
	out[7] = byte(remain) // HopLimit 字段偏移固定为 7

	c.mu.Lock()
	c.stats.Delivered++
	c.mu.Unlock()
	dstPort(out)
}

func (c *V6Cloud) sendPTB(orig *headers.IPv6Header, origPkt []byte, mtu uint32) {
	var rest [4]byte
	headers.SetMTU(&rest, mtu, true)
	body := truncate(origPkt, 1232)
	msg := headers.BuildICMP(&headers.ICMPMessage{
		Type: headers.ICMP6PktTooBig, Rest: rest, Body: body,
	})
	csum := headers.TransportChecksum(
		headers.PseudoHeaderV6(c.cloudAddr.As16(), orig.Src.As16(),
			headers.ProtoICMPv6, len(msg)),
		msg, headers.ICMPChecksumPos())
	binary.BigEndian.PutUint16(msg[headers.ICMPChecksumPos():], csum)
	out := headers.BuildIPv6(&headers.IPv6Header{
		TrafficClass: 0, Length: uint16(len(msg)),
		NextHeader: headers.ProtoICMPv6, HopLimit: 64,
		Src: c.cloudAddr, Dst: orig.Src,
	}, msg)
	c.deliverBack(orig.Src, out)
}

func (c *V6Cloud) sendHopExpired(orig *headers.IPv6Header, origPkt []byte) {
	body := truncate(origPkt, 1232)
	msg := headers.BuildICMP(&headers.ICMPMessage{
		Type: headers.ICMP6TimeExceed,
		Code: headers.ICMP6HopLimitExceeded,
		Body: body,
	})
	csum := headers.TransportChecksum(
		headers.PseudoHeaderV6(c.cloudAddr.As16(), orig.Src.As16(),
			headers.ProtoICMPv6, len(msg)),
		msg, headers.ICMPChecksumPos())
	binary.BigEndian.PutUint16(msg[headers.ICMPChecksumPos():], csum)
	out := headers.BuildIPv6(&headers.IPv6Header{
		Length: uint16(len(msg)), NextHeader: headers.ProtoICMPv6,
		HopLimit: 64, Src: c.cloudAddr, Dst: orig.Src,
	}, msg)
	c.deliverBack(orig.Src, out)
}

// deliverBack 把差错报文送回源 CE（源是 BR 时送到 BR）。
func (c *V6Cloud) deliverBack(src netip.Addr, pkt []byte) {
	c.mu.Lock()
	p, isCE := c.cePorts[src]
	if !isCE {
		p = c.brPort
	}
	c.mu.Unlock()
	p(pkt)
}

// Stats 返回骨干统计快照。
func (c *V6Cloud) Stats() CloudStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

// V4Net 模拟 BR 之外的公网 IPv4 网络：把报文送到连接的服务器，
// 逐跳递减 TTL（到 0 回 ICMPv4 超时），并可配置链路 MTU（回 Frag Needed）。
type V4Net struct {
	mu sync.Mutex

	serverPort Port
	serverAddr netip.Addr
	brPort     Port
	routerAddr netip.Addr

	Hops    int
	LinkMTU int
	stats   CloudStats
}

func NewV4Net(routerAddr, serverAddr netip.Addr, serverPort, brPort Port) *V4Net {
	return &V4Net{
		serverPort: serverPort, serverAddr: serverAddr,
		brPort: brPort, routerAddr: routerAddr,
		Hops: 2, LinkMTU: 1500,
	}
}

// Send 是 v4 外网收包入口（来源为 BR）。
func (n *V4Net) Send(packet []byte) {
	h, ihl, err := headers.ParseIPv4(packet)
	if err != nil {
		return
	}
	if n.LinkMTU > 0 && len(packet) > n.LinkMTU {
		n.mu.Lock()
		n.stats.TooBig++
		n.mu.Unlock()
		n.sendFragNeeded(h, packet)
		return
	}
	ttl := int(h.TTL) - n.Hops
	if ttl <= 0 {
		n.mu.Lock()
		n.stats.HopExpired++
		n.mu.Unlock()
		n.sendTimeExceeded(h, packet)
		return
	}
	out := append([]byte(nil), packet...)
	out[8] = byte(ttl)
	// TTL 变化后重算 IPv4 头校验和。
	binary.BigEndian.PutUint16(out[10:], 0)
	binary.BigEndian.PutUint16(out[10:], headers.Checksum(out[:ihl]))

	n.mu.Lock()
	n.stats.Delivered++
	n.mu.Unlock()
	if h.Dst == n.serverAddr {
		n.serverPort(out)
		return
	}
	// 非服务器地址在仿真中按不可达处理
	n.sendDstUnreach(h, packet, headers.ICMP4HostUnreach)
}

// DeliverToBR 供服务器发包时调用。
func (n *V4Net) DeliverToBR(packet []byte) {
	h, ihl, err := headers.ParseIPv4(packet)
	if err != nil {
		return
	}
	ttl := int(h.TTL) - 1
	if ttl <= 0 {
		n.sendTimeExceeded(h, packet)
		return
	}
	out := append([]byte(nil), packet...)
	out[8] = byte(ttl)
	binary.BigEndian.PutUint16(out[10:], 0)
	binary.BigEndian.PutUint16(out[10:], headers.Checksum(out[:ihl]))
	n.brPort(out)
}

func (n *V4Net) sendFragNeeded(orig *headers.IPv4Header, origPkt []byte) {
	var rest [4]byte
	headers.SetMTU(&rest, uint32(n.LinkMTU), false)
	msg := headers.BuildICMP(&headers.ICMPMessage{
		Type: headers.ICMP4DstUnreach, Code: headers.ICMP4FragNeededDF,
		Rest: rest, Body: truncate(origPkt, 548),
	})
	n.finalizeV4ICMP(msg, orig.Src)
}

func (n *V4Net) sendTimeExceeded(orig *headers.IPv4Header, origPkt []byte) {
	msg := headers.BuildICMP(&headers.ICMPMessage{
		Type: headers.ICMP4TimeExceed, Code: 0,
		Body: truncate(origPkt, 548),
	})
	n.finalizeV4ICMP(msg, orig.Src)
}

func (n *V4Net) sendDstUnreach(orig *headers.IPv4Header, origPkt []byte, code uint8) {
	msg := headers.BuildICMP(&headers.ICMPMessage{
		Type: headers.ICMP4DstUnreach, Code: code,
		Body: truncate(origPkt, 548),
	})
	n.finalizeV4ICMP(msg, orig.Src)
}

func (n *V4Net) finalizeV4ICMP(msg []byte, dst netip.Addr) {
	binary.BigEndian.PutUint16(msg[headers.ICMPChecksumPos():], 0)
	binary.BigEndian.PutUint16(msg[headers.ICMPChecksumPos():], headers.Checksum(msg))
	out := headers.BuildIPv4(&headers.IPv4Header{
		TotalLength: uint16(headers.V4MinHeaderLen + len(msg)),
		ID:          0, TTL: 64, Protocol: headers.ProtoICMPv4,
		Src: n.routerAddr, Dst: dst,
	}, msg)
	n.brPort(out)
}

func truncate(pkt []byte, max int) []byte {
	if len(pkt) > max {
		return append([]byte(nil), pkt[:max]...)
	}
	return append([]byte(nil), pkt...)
}

// Stats 返回外网统计快照。
func (n *V4Net) Stats() CloudStats {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.stats
}
