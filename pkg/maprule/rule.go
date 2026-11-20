// Package maprule 实现 MAP-T/MAP-E 风格的无状态地址族转换规则。
//
// 核心思想（对应 RFC 7597 / RFC 7599）：
//   - 一个公网 IPv4 地址按端口切成 2^k 个端口集，端口集标识 PSID 长 k 位；
//   - 端口集由固定算法（RFC 7597 §5.1.1）展开，不保存任何表项；
//   - 每户的 IPv6 地址由规则前缀 + IPv4 后缀 + PSID 按位拼出；
//   - 边界设备（BR）只凭一条规则即可从 IPv4 目的地址和目的端口反解出
//     PSID，进而算出目的 IPv6，全程无状态、不查表。
package maprule

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"net/netip"
)

// WellKnownPortBoundary 以下为知名端口段，端口集展开时整段跳过。
const WellKnownPortBoundary = 1024

// Rule 是一条映射规则。转发映射（FMR）与基本映射（BMR）结构相同，
// 区别仅在用途：BMR 描述本网关自己的映射（含 PSID），FMR 只用于
// 无状态转发，PSID 从报文端口中反解。
type Rule struct {
	// RuleIPv6Prefix 规则的 IPv6 前缀（标准 MAP 布局通常 /64）。
	RuleIPv6Prefix netip.Prefix
	// RuleIPv4Prefix 规则覆盖的公网 IPv4 前缀。
	RuleIPv4Prefix netip.Prefix
	// EALen 嵌入地址位（EA bits）总长度 = IPv4 后缀位数 + PSID 位数。
	EALen int
	// PSIDOffset 端口公式中的偏移 a（RFC 7597），默认 6，
	// 取 6 时端口集天然从 1024 开始，整段知名端口被跳过。
	PSIDOffset int
	// PSIDLen PSID 字段长度 k，决定一个 IPv4 地址切出多少户（2^k）。
	PSIDLen int
	// ChecksumNeutral 为 true 时采用 RFC 6052 风格的校验和中立布局
	// （64:ff9b::/64 + IID = IPv4|PSID|0x0000），传输层校验和无需修改。
	ChecksumNeutral bool
	// Forwarding 为 true 表示这是一条转发映射（FMR），否则为基本映射（BMR）。
	Forwarding bool
	// DomainID 规则所属 MAP 域标识，同域两户可直接互访。
	DomainID int
	// Name 规则的可读名称。
	Name string
}

func (r *Rule) v4PrefixLen() int { return r.RuleIPv4Prefix.Bits() }

// SuffixLen 返回 IPv4 地址中参与 EA 编码的后缀位数。
func (r *Rule) SuffixLen() int { return 32 - r.v4PrefixLen() }

// PSIDCount 返回该规则下一个 IPv4 地址承载的户数（端口集个数）。
func (r *Rule) PSIDCount() int { return 1 << r.PSIDLen }

// MaxPSID 返回最大合法 PSID。
func (r *Rule) MaxPSID() uint16 { return uint16((1 << r.PSIDLen) - 1) }

// Validate 校验规则各字段自洽。
func (r *Rule) Validate() error {
	if r.RuleIPv6Prefix.Addr().BitLen() != 128 || !r.RuleIPv6Prefix.Addr().Is6() {
		return errors.New("RuleIPv6Prefix 必须是 IPv6 前缀")
	}
	if r.RuleIPv4Prefix.Addr().BitLen() != 32 {
		return errors.New("RuleIPv4Prefix 必须是 IPv4 前缀")
	}
	if r.PSIDLen <= 0 || r.PSIDLen > 16 {
		return fmt.Errorf("PSIDLen 必须在 1..16 之间，当前 %d", r.PSIDLen)
	}
	if r.PSIDOffset < 0 || r.PSIDOffset > 15 {
		return fmt.Errorf("PSIDOffset 必须在 0..15 之间，当前 %d", r.PSIDOffset)
	}
	if r.PSIDOffset+r.PSIDLen > 16 {
		return fmt.Errorf("PSIDOffset(%d)+PSIDLen(%d) 不能超过 16", r.PSIDOffset, r.PSIDLen)
	}
	if r.SuffixLen()+r.PSIDLen != r.EALen {
		return fmt.Errorf("EA 位数不自洽：IPv4后缀 %d + PSID %d != EALen %d",
			r.SuffixLen(), r.PSIDLen, r.EALen)
	}
	if r.EALen > 48 {
		return errors.New("EALen 过长，无法放入 IID")
	}
	if r.ChecksumNeutral {
		// 校验和中立布局固定使用 64:ff9b::/64（RFC 6052 / RFC 7915 §4.7）。
		want := netip.MustParsePrefix("64:ff9b::/64")
		if r.RuleIPv6Prefix != want {
			return fmt.Errorf("校验和中立布局要求前缀 %s，当前 %s", want, r.RuleIPv6Prefix)
		}
		if r.PSIDLen > 16 {
			return errors.New("校验和中立布局 PSID 最多 16 位")
		}
	}
	if !r.ChecksumNeutral && r.RuleIPv6Prefix.Bits() > 64 {
		return errors.New("标准 MAP 布局的 IPv6 前缀长度不能超过 /64")
	}
	return nil
}

// ExpandPortSet 按 RFC 7597 §5.1.1 的固定算法展开一个端口集。
//
// 记 k=PSIDLen、a=PSIDOffset、R=2^k、M=2^(16-a)-1，则：
//
//	P = i·R + PSID，i 取 1..M，且 P 不超过 65535
//
// PSID 恒等于端口的低 k 位（P mod R），这正是 BR 从端口反解户标识的依据；
// offset a 决定 i 的取值上界，并把 0..2^a-1 这段（默认即知名端口区）
// 排除在分配之外。知名端口（< 1024）再显式过滤一遍，任何配置下都不漏放。
//
// 例：k=4、a=6、PSID=7 → {1031, 2063, 3095, ...}（RFC 7597 示例）。
// 不同 PSID 的端口集天然不相交：低 k 位不同的端口不可能相等。
// 返回的端口按升序排列。
func ExpandPortSet(psid uint16, offset, psidLen int) ([]uint16, error) {
	if psidLen <= 0 || psidLen > 16 {
		return nil, fmt.Errorf("非法 PSIDLen %d", psidLen)
	}
	if offset < 0 || offset+psidLen > 16 {
		return nil, fmt.Errorf("非法 offset=%d psidLen=%d", offset, psidLen)
	}
	if int(psid) > (1<<psidLen)-1 {
		return nil, fmt.Errorf("PSID %d 超出 %d 位范围", psid, psidLen)
	}
	k := uint(psidLen)
	a := uint(offset)
	r := uint32(1) << k
	m := (uint32(1) << (16 - a)) - 1
	// 16 位端口空间给出的硬上界。
	iMax := (65535 - uint32(psid)) / r
	if m < iMax {
		iMax = m
	}
	out := make([]uint16, 0, iMax)
	for i := uint32(1); i <= iMax; i++ {
		p := uint16(i*r + uint32(psid))
		if p < WellKnownPortBoundary {
			continue // 跳过知名端口段
		}
		out = append(out, p)
	}
	return out, nil
}

// Expand 是规则方法版本的端口集展开。
func (r *Rule) Expand(psid uint16) ([]uint16, error) {
	return ExpandPortSet(psid, r.PSIDOffset, r.PSIDLen)
}

// PSIDFromPort 从传输层端口中反解 PSID（BR 无状态反查的关键一步）。
// 按 RFC 7597，PSID 即端口的低 k 位：PSID = port mod 2^k；
// 同时返回该端口是否在可分配区（非知名端口）。
func (r *Rule) PSIDFromPort(port uint16) (psid uint16, member bool) {
	psid = port & ((1 << uint(r.PSIDLen)) - 1)
	member = port >= WellKnownPortBoundary
	return
}

// ContainsPort 判断端口是否落在给定 PSID 的端口集内。
func (r *Rule) ContainsPort(psid uint16, port uint16) bool {
	got, ok := r.PSIDFromPort(port)
	return ok && got == psid
}

// eaBits 把 IPv4 后缀与 PSID 拼成 EA 位串：后缀在高位、PSID 在低位。
func (r *Rule) eaBits(v4 uint32, psid uint16) uint64 {
	suf := r.SuffixLen()
	var s uint64
	if suf > 0 {
		mask := uint32((1 << uint(suf)) - 1)
		s = uint64(v4&mask) << uint(r.PSIDLen)
	}
	return s | uint64(psid)
}

// splitEA 是 eaBits 的逆运算。
func (r *Rule) splitEA(ea uint64) (v4Suffix uint32, psid uint16) {
	psid = uint16(ea & ((1 << uint(r.PSIDLen)) - 1))
	suf := r.SuffixLen()
	if suf > 0 {
		v4Suffix = uint32(ea>>uint(r.PSIDLen)) & ((1 << uint(suf)) - 1)
	}
	return
}

func v4ToUint32(addr netip.Addr) uint32 {
	b := addr.As4()
	return binary.BigEndian.Uint32(b[:])
}

func uint32ToV4(v uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

// EncodeIPv6 按规则把（公网 IPv4, PSID）编码成户的 IPv6 地址。
func (r *Rule) EncodeIPv6(v4 netip.Addr, psid uint16) (netip.Addr, error) {
	if err := r.Validate(); err != nil {
		return netip.Addr{}, err
	}
	if int(psid) > (1<<r.PSIDLen)-1 {
		return netip.Addr{}, fmt.Errorf("PSID %d 超出范围", psid)
	}
	v := v4ToUint32(v4)
	if r.ChecksumNeutral {
		// 校验和中立布局：64:ff9b::/64 | IPv4(32) | PSID(16) | 0x0000
		var b [16]byte
		pfx := r.RuleIPv6Prefix.Addr().As16()
		copy(b[:8], pfx[:8])
		binary.BigEndian.PutUint32(b[8:12], v)
		binary.BigEndian.PutUint16(b[12:14], psid)
		return netip.AddrFrom16(b), nil
	}
	// 标准 MAP 布局：/64 前缀 + IID
	// IID = 0x00 | EA 位串（左对齐到字节 1） | 补零
	var b [16]byte
	pfx := r.RuleIPv6Prefix.Masked().Addr().As16()
	copy(b[:8], pfx[:8])
	ea := r.eaBits(v, psid)
	// EA 位串从 IID 的第 8 位（字节 1）开始放置
	eaShift := 64 - 8 - r.EALen
	iid := ea << uint(eaShift)
	binary.BigEndian.PutUint64(b[8:], iid)
	return netip.AddrFrom16(b), nil
}

// DecodeIPv6 是 EncodeIPv6 的逆运算，BR/对端 CE 凭它无状态反解。
// 返回 ok=false 表示该地址不匹配本规则。
func (r *Rule) DecodeIPv6(v6 netip.Addr) (v4 netip.Addr, psid uint16, ok bool) {
	if v6.BitLen() != 128 {
		return netip.Addr{}, 0, false
	}
	b := v6.As16()
	if r.ChecksumNeutral {
		pfx := r.RuleIPv6Prefix.Addr().As16()
		for i := 0; i < 8; i++ {
			if b[i] != pfx[i] {
				return netip.Addr{}, 0, false
			}
		}
		v := binary.BigEndian.Uint32(b[8:12])
		psid = binary.BigEndian.Uint16(b[12:14])
		if int(psid) > (1<<r.PSIDLen)-1 {
			return netip.Addr{}, 0, false
		}
		return uint32ToV4(v), psid, true
	}
	pfx := r.RuleIPv6Prefix.Masked().Addr().As16()
	for i := 0; i < 8; i++ {
		if b[i] != pfx[i] {
			return netip.Addr{}, 0, false
		}
	}
	iid := binary.BigEndian.Uint64(b[8:])
	eaShift := uint(64 - 8 - r.EALen)
	eaMask := uint64((1 << uint(r.EALen)) - 1)
	ea := (iid >> eaShift) & eaMask
	suffix, p := r.splitEA(ea)
	// 还原完整 IPv4：规则前缀部分 + 后缀部分
	pfxV4 := v4ToUint32(r.RuleIPv4Prefix.Masked().Addr())
	v := pfxV4 | suffix
	return uint32ToV4(v), p, true
}

// ResolveV4ToV6 供 BR 在 v4→v6 方向使用：凭目的 IPv4 和目的传输端口，
// 一条规则直接算出目的户的 IPv6，不查任何会话表。
func (r *Rule) ResolveV4ToV6(dstV4 netip.Addr, dstPort uint16) (netip.Addr, uint16, error) {
	psid, member := r.PSIDFromPort(dstPort)
	if !member {
		return netip.Addr{}, 0, fmt.Errorf("端口 %d 落在知名端口段，无法反解 PSID", dstPort)
	}
	addr, err := r.EncodeIPv6(dstV4, psid)
	return addr, psid, err
}

// PrefixContainsV4 判断 IPv4 地址是否落在规则的 IPv4 前缀内。
func (r *Rule) ContainsV4(v4 netip.Addr) bool { return r.RuleIPv4Prefix.Contains(v4) }

// Domain 是一个 MAP 域，内含若干规则。BR 上可同时挂多个域。
type Domain struct {
	ID    int
	Name  string
	Rules []*Rule
}

// MatchV4 找到覆盖该 IPv4 目的地址的规则。
func (d *Domain) MatchV4(v4 netip.Addr) *Rule {
	for _, r := range d.Rules {
		if r.ContainsV4(v4) {
			return r
		}
	}
	return nil
}

// MatchV6 找到能解码该 IPv6 地址的规则。
func (d *Domain) MatchV6(v6 netip.Addr) (*Rule, uint16, netip.Addr, bool) {
	for _, r := range d.Rules {
		if v4, psid, ok := r.DecodeIPv6(v6); ok {
			return r, psid, v4, true
		}
	}
	return nil, 0, netip.Addr{}, false
}

// Subscriber 表示一户：一个共享公网 IPv4 地址 + 一个端口集标识。
type Subscriber struct {
	Index int        // 户编号（域内唯一）
	V4    netip.Addr // 共享的公网 IPv4
	PSID  uint16     // 端口集标识
}

// EnumerateSubscribers 枚举规则覆盖的全部户。
// 地址数 * 每户端口集数，即一个公网段能承载的总户数。
func EnumerateSubscribers(r *Rule) ([]Subscriber, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	base := v4ToUint32(r.RuleIPv4Prefix.Masked().Addr())
	addrs := 1 << uint(r.SuffixLen())
	psids := r.PSIDCount()
	out := make([]Subscriber, 0, addrs*psids)
	idx := 0
	for ai := 0; ai < addrs; ai++ {
		v4 := uint32ToV4(base + uint32(ai))
		for p := 0; p < psids; p++ {
			out = append(out, Subscriber{Index: idx, V4: v4, PSID: uint16(p)})
			idx++
		}
	}
	return out, nil
}

// SubscribersPerIPv4 一个公网 IPv4 地址承载的户数。
func SubscribersPerIPv4(r *Rule) int { return r.PSIDCount() }

// PortsPerSubscriber 每户端口集中的传输层端口数。
func PortsPerSubscriber(r *Rule) int {
	set, err := r.Expand(0)
	if err != nil {
		return 0
	}
	return len(set)
}

// Explain 生成规则计算过程的可读解释，供 Web 页面展示位级推演。
type Step struct {
	Title  string
	Detail string
	Bits   string // 相关位串（可选）
}

// ExplainPortSet 解释端口集如何从 PSID 展开。
func ExplainPortSet(psid uint16, offset, psidLen int) ([]Step, []uint16, error) {
	set, err := ExpandPortSet(psid, offset, psidLen)
	if err != nil {
		return nil, nil, err
	}
	steps := []Step{
		{Title: "端口公式", Detail: fmt.Sprintf(
			"P = i·2^%d + %d，i 取 1..%d（受 65535 上界约束）；PSID 即端口低 %d 位",
			psidLen, psid, (1<<(16-uint(offset)))-1, psidLen)},
		{Title: "知名端口跳过", Detail: fmt.Sprintf(
			"所有 < %d 的知名端口不参与分配；offset=%d 时名义端口段从 2^%d 开始",
			WellKnownPortBoundary, offset, offset)},
		{Title: "PSID 位提取", Detail: fmt.Sprintf(
			"PSID = port & 0x%x，边界设备据此从端口反解户标识，不查表",
			(1<<uint(psidLen))-1),
			Bits: fmt.Sprintf("%0*b", psidLen, psid)},
	}
	return steps, set, nil
}

// LeadingZeros 辅助函数。
func LeadingZeros16(v uint16) int { return bits.LeadingZeros16(v) }
