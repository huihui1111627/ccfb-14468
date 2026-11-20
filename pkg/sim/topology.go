package sim

import (
	"fmt"
	"net/netip"

	"ivat/pkg/maprule"
	"ivat/pkg/stack"
	"ivat/pkg/translate"
)

// Topology 是一次完整仿真的接线结果。
type Topology struct {
	Mode   Mode
	Rule   *maprule.Rule
	Domain *maprule.Domain
	Cloud  *V6Cloud
	V4Net  *V4Net
	BR     *BR
	CEs    []*CE
	Hosts  map[string]*stack.Host // CE 名 → 主机（每户一台）
	Server *stack.Host
}

// Config 控制拓扑生成。
type Config struct {
	Mode            Mode
	SharedV4Count   int // 共享公网 v4 地址数
	CEPerV4         int // 每个 v4 地址挂多少户（必须等于规则 PSID 数时取子集可更少）
	PSIDLen         int
	PSIDOffset      int
	ChecksumNeutral bool
	V6LinkMTU       int
	V4LinkMTU       int
	HostsPerCE      int // 每户 LAN 内终端数（验证户内 NAPT44 多主机）
}

// DefaultRule 按配置生成一条 MAP 规则。
func DefaultRule(cfg Config) (*maprule.Rule, error) {
	v4pfx := netip.MustParsePrefix(fmt.Sprintf("192.0.2.0/%d", 32-log2ceil(cfg.SharedV4Count)))
	r := &maprule.Rule{
		RuleIPv4Prefix:  v4pfx,
		EALen:           (32 - v4pfx.Bits()) + cfg.PSIDLen,
		PSIDOffset:      cfg.PSIDOffset,
		PSIDLen:         cfg.PSIDLen,
		ChecksumNeutral: cfg.ChecksumNeutral,
		Forwarding:      false,
		DomainID:        1,
		Name:            "县广电 MAP 规则",
	}
	if cfg.ChecksumNeutral {
		r.RuleIPv6Prefix = netip.MustParsePrefix("64:ff9b::/64")
	} else {
		r.RuleIPv6Prefix = netip.MustParsePrefix("2001:db8:ffff::/64")
	}
	return r, r.Validate()
}

func log2ceil(n int) int {
	if n <= 1 {
		return 0
	}
	b := 0
	for v := n - 1; v > 0; v >>= 1 {
		b++
	}
	return b
}

// Build 按配置装配整个仿真网络。
func Build(cfg Config) (*Topology, error) {
	rule, err := DefaultRule(cfg)
	if err != nil {
		return nil, err
	}
	domain := &maprule.Domain{ID: 1, Name: "县广电域", Rules: []*maprule.Rule{rule}}

	brV6 := netip.MustParseAddr("2001:db8:ffff::1")
	routerV4 := netip.MustParseAddr("198.51.100.1")
	serverV4 := netip.MustParseAddr("198.51.100.10")

	// 先建云与外网，端口稍后绑定设备。
	cloud := NewV6Cloud(brV6, nil)
	cloud.LinkMTU = cfg.V6LinkMTU
	v4net := NewV4Net(routerV4, serverV4, nil, nil)
	v4net.LinkMTU = cfg.V4LinkMTU

	// 翻译器 MTU 与云链路 MTU 分开：翻译器按协议最小/配置值放行，
	// 云链路 MTU 是真实瓶颈，由云回 PTB 驱动端到端 PMTUD。
	tr := translate.New(translate.Config{
		V6MTU: 1500, V4MTU: cfg.V4LinkMTU,
		ChecksumNeutral: cfg.ChecksumNeutral,
	})
	br := NewBR("BR-1", domain, cfg.Mode, cloud, v4net, tr, brV6)
	cloud.brPort = br.V6Input
	cloud.brAddr = brV6

	// 公网服务器（仿真各类应用对端）。
	server := stack.NewHost("公网服务器", serverV4, func(pkt []byte) {
		v4net.DeliverToBR(pkt)
	})
	server.InterfaceMTU = cfg.V4LinkMTU
	v4net.serverPort = server.Deliver
	v4net.brPort = br.V4Input

	topo := &Topology{
		Mode: cfg.Mode, Rule: rule, Domain: domain, Cloud: cloud,
		V4Net: v4net, BR: br, Hosts: map[string]*stack.Host{}, Server: server,
	}

	// 枚举共享 v4 地址并在每个地址下挂 CEPerV4 户。
	subs, err := maprule.EnumerateSubscribers(rule)
	if err != nil {
		return nil, err
	}
	wanted := cfg.SharedV4Count * cfg.CEPerV4
	if wanted > len(subs) {
		return nil, fmt.Errorf("规则最多支持 %d 户，请求 %d 户", len(subs), wanted)
	}
	lanHosts := cfg.HostsPerCE
	if lanHosts < 1 {
		lanHosts = 1
	}
	for i := 0; i < wanted; i++ {
		s := subs[i]
		ceName := fmt.Sprintf("CE-%03d(PSID%d)", i, s.PSID)
		ce, err := NewCE(ceName, rule, s.V4, s.PSID, cfg.Mode, cloud, brV6, tr)
		if err != nil {
			return nil, err
		}
		// 户内 LAN 使用 10.0.0.0/24 私网段（每户独立）。
		for h := 0; h < lanHosts; h++ {
			lanIP := netip.AddrFrom4([4]byte{10, 0, byte(i + 1), byte(h + 1)})
			host := stack.NewHost(fmt.Sprintf("%s-主机%d", ceName, h+1), lanIP, ce.LANInput)
			ce.AttachHost(lanIP, host.Deliver)
			topo.Hosts[fmt.Sprintf("%s/h%d", ceName, h+1)] = host
			if h == 0 {
				topo.Hosts[ceName] = host
			}
		}
		topo.CEs = append(topo.CEs, ce)
	}
	return topo, nil
}

// FindCE 按共享 v4 与 PSID 定位 CE。
func (t *Topology) FindCE(v4 netip.Addr, psid uint16) *CE {
	for _, ce := range t.CEs {
		if ce.SharedV4 == v4 && ce.PSID == psid {
			return ce
		}
	}
	return nil
}
