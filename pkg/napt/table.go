// Package napt 在用户侧网关（CE）的端口集内部做一次有状态的 NAPT44。
//
// 注意层次：BR 对每户是完全无状态的（端口集算法即映射）；状态只存在于
// 户内这一台 CE，而且外部端口只能从本户的端口集里取。一户一台设备、
// 只记自己家的连接，单台 CE 的表项规模与十万户集中式设备差几个数量级，
// 即便表满也只影响这一户，不会波及全县。
package napt

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// 协议常量（与 IP 头协议号一致）。
const (
	ProtoICMP = 1
	ProtoTCP  = 6
	ProtoUDP  = 17
)

var (
	ErrNoPort       = errors.New("端口集内已无可用外部端口")
	ErrNoMapping    = errors.New("找不到匹配的 NAPT 映射")
	ErrPortNotInSet = errors.New("外部端口不属于本户端口集")
)

// Mapping 是一条 NAPT 映射（仅存在于本户 CE）。
type Mapping struct {
	Protocol   uint8
	InternalIP [4]byte
	InternalPt uint16 // TCP/UDP 端口；ICMP 为 echo ID
	ExternalPt uint16 // 必为本户端口集成员
	RemoteIP   [4]byte
	RemotePt   uint16 // 0 表示通配（允许对端任意）
	Created    time.Time
	LastUsed   time.Time
}

func key(proto uint8, ip [4]byte, port uint16, rip [4]byte, rport uint16) string {
	return fmt.Sprintf("%d|%d.%d.%d.%d|%d|%d.%d.%d.%d|%d",
		proto, ip[0], ip[1], ip[2], ip[3], port,
		rip[0], rip[1], rip[2], rip[3], rport)
}

// Table 是一户的 NAPT 表。
type Table struct {
	mu sync.Mutex

	allowed map[uint16]struct{} // 本户端口集（外部端口只许从这里分配）
	out     map[string]*Mapping // 正向：五元组 → 映射
	inbound map[string]*Mapping // 反向：协议+外部端口(+对端) → 映射
	byExt   map[string]*Mapping // 反向（通配）：协议+外部端口 → 映射，ICMP 差错修正用
	used    map[uint16]struct{} // 已占用外部端口

	// 空闲超时：UDP/ICMP 默认 120s，TCP 默认 7440s（RFC 4787 常见取值）。
	udpTimeout  time.Duration
	tcpTimeout  time.Duration
	icmpTimeout time.Duration
}

// NewTable 用端口集（maprule.Expand 的结果）构造 NAPT 表。
func NewTable(portSet []uint16) *Table {
	t := &Table{
		allowed:     make(map[uint16]struct{}, len(portSet)),
		out:         make(map[string]*Mapping),
		inbound:     make(map[string]*Mapping),
		byExt:       make(map[string]*Mapping),
		used:        make(map[uint16]struct{}),
		udpTimeout:  120 * time.Second,
		tcpTimeout:  7440 * time.Second,
		icmpTimeout: 120 * time.Second,
	}
	for _, p := range portSet {
		t.allowed[p] = struct{}{}
	}
	return t
}

// LookupOutbound 查已有映射；没有则用 nil, false 返回。
func (t *Table) LookupOutbound(proto uint8, internalIP [4]byte, internalPort uint16,
	remoteIP [4]byte, remotePort uint16) (*Mapping, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	m, ok := t.out[key(proto, internalIP, internalPort, remoteIP, remotePort)]
	if !ok {
		// 再试通配对端（endpoint-independent mapping，RFC 4787 建议）
		m, ok = t.out[key(proto, internalIP, internalPort, [4]byte{}, 0)]
	}
	return m, ok
}

// Allocate 为一条新的外出连接分配映射。
// 分配策略：优先复用内部端口（若它恰好在端口集内且空闲），否则顺序探测。
func (t *Table) Allocate(proto uint8, internalIP [4]byte, internalPort uint16,
	remoteIP [4]byte, remotePort uint16) (*Mapping, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	k := key(proto, internalIP, internalPort, remoteIP, remotePort)
	if m, ok := t.out[k]; ok {
		m.LastUsed = time.Now()
		return m, nil
	}

	ext, err := t.pickExternal(internalPort)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	m := &Mapping{
		Protocol:   proto,
		InternalIP: internalIP,
		InternalPt: internalPort,
		ExternalPt: ext,
		RemoteIP:   remoteIP,
		RemotePt:   remotePort,
		Created:    now,
		LastUsed:   now,
	}
	t.out[k] = m
	t.inbound[inKey(proto, ext, remoteIP, remotePort)] = m
	t.byExt[extKey(proto, ext)] = m
	t.used[ext] = struct{}{}
	return m, nil
}

// pickExternal 必须在持锁状态下调用。
func (t *Table) pickExternal(preferred uint16) (uint16, error) {
	if _, ok := t.allowed[preferred]; ok {
		if _, busy := t.used[preferred]; !busy {
			return preferred, nil
		}
	}
	for p := range t.allowed {
		if _, busy := t.used[p]; !busy {
			return p, nil
		}
	}
	return 0, ErrNoPort
}

// LookupInbound 处理入向报文：用协议+外部端口反查内部主机。
// 先按完整对端五元组匹配，失败再回退到端点无关映射（RFC 4787 建议行为），
// 使同域互访这类对端地址与建连时不同的流量也能到达户内主机。
func (t *Table) LookupInbound(proto uint8, externalPort uint16,
	remoteIP [4]byte, remotePort uint16) (*Mapping, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if m, ok := t.inbound[inKey(proto, externalPort, remoteIP, remotePort)]; ok {
		m.LastUsed = time.Now()
		return m, nil
	}
	if m, ok := t.byExt[extKey(proto, externalPort)]; ok {
		m.LastUsed = time.Now()
		return m, nil
	}
	return nil, ErrNoMapping
}

// LookupByExternal 只按协议+外部端口查映射。
// 用于 ICMP 差错报文修正：体内引用报文的对端字段已被翻译，
// 不能作为查表依据，但外部端口本身一定属于本户端口集。
func (t *Table) LookupByExternal(proto uint8, externalPort uint16) (*Mapping, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	m, ok := t.byExt[extKey(proto, externalPort)]
	if ok {
		m.LastUsed = time.Now()
	}
	return m, ok
}

func extKey(proto uint8, ext uint16) string {
	return fmt.Sprintf("%d|%d", proto, ext)
}

func inKey(proto uint8, ext uint16, rip [4]byte, rport uint16) string {
	return fmt.Sprintf("%d|%d|%d.%d.%d.%d|%d",
		proto, ext, rip[0], rip[1], rip[2], rip[3], rport)
}

// Release 显式释放映射（TCP RST/FIN 后调用）。
func (t *Table) Release(m *Mapping) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.out, key(m.Protocol, m.InternalIP, m.InternalPt, m.RemoteIP, m.RemotePt))
	delete(t.inbound, inKey(m.Protocol, m.ExternalPt, m.RemoteIP, m.RemotePt))
	delete(t.byExt, extKey(m.Protocol, m.ExternalPt))
	delete(t.used, m.ExternalPt)
}

// Sweep 清理超时映射，返回清理条数。
func (t *Table) Sweep() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	n := 0
	for k, m := range t.out {
		to := t.udpTimeout
		switch m.Protocol {
		case ProtoTCP:
			to = t.tcpTimeout
		case ProtoICMP:
			to = t.icmpTimeout
		}
		if now.Sub(m.LastUsed) > to {
			delete(t.out, k)
			delete(t.inbound, inKey(m.Protocol, m.ExternalPt, m.RemoteIP, m.RemotePt))
			delete(t.byExt, extKey(m.Protocol, m.ExternalPt))
			delete(t.used, m.ExternalPt)
			n++
		}
	}
	return n
}

// Stats 返回表项计数与容量。
type Stats struct {
	Entries  int
	Capacity int
}

func (t *Table) Stats() Stats {
	t.mu.Lock()
	defer t.mu.Unlock()
	return Stats{Entries: len(t.out), Capacity: len(t.allowed)}
}

// AssertPortInSet 供验收测试调用：确认外部端口确实属于本户端口集。
func (t *Table) AssertPortInSet(port uint16) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.allowed[port]; !ok {
		return ErrPortNotInSet
	}
	return nil
}
