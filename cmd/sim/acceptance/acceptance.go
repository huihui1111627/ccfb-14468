// Package acceptance 在仿真拓扑上编排应用流量并执行验收断言。
package acceptance

import (
	"fmt"
	"strings"
	"time"

	"ivat/pkg/maprule"
	"ivat/pkg/sim"
	"ivat/pkg/stack"
)

// Config 是验收运行参数（镜像 sim.Config 的可调部分）。
type Config struct {
	Mode            string
	SharedV4Count   int
	CEPerV4         int
	PSIDLen         int
	PSIDOffset      int
	ChecksumNeutral bool
	HostsPerCE      int
	V6LinkMTU       int
	V4LinkMTU       int
}

// Check 是一条验收结论。
type Check struct {
	Name   string
	Pass   bool
	Detail string
}

// Report 汇总一次运行的全部结论。
type Report struct {
	Mode       string
	Topo       *sim.Topology
	Checks     []Check
	Capacity   string // 一个公网 v4 带多少户
	BRStats    sim.BRStats
	CloudStats sim.CloudStats
}

// AllPassed 判断是否全部通过。
func (r *Report) AllPassed() bool {
	for _, c := range r.Checks {
		if !c.Pass {
			return false
		}
	}
	return true
}

func (r *Report) add(name string, pass bool, detail string) {
	r.Checks = append(r.Checks, Check{Name: name, Pass: pass, Detail: detail})
}

// String 渲染中文验收报告。
func (r *Report) String() string {
	var b strings.Builder
	b.WriteString(strings.Repeat("=", 78) + "\n")
	b.WriteString(fmt.Sprintf("验收模式：%s\n", r.Mode))
	b.WriteString(strings.Repeat("=", 78) + "\n")
	b.WriteString(r.Capacity + "\n\n")
	for _, c := range r.Checks {
		mark := "✅"
		if !c.Pass {
			mark = "❌"
		}
		b.WriteString(fmt.Sprintf("%s %s\n   %s\n", mark, c.Name, c.Detail))
	}
	b.WriteString("\n设备计数：\n")
	b.WriteString(fmt.Sprintf("  BR: v4入=%d v6入=%d 46翻译=%d 64翻译=%d 封装入=%d 封装出=%d 丢弃=%d 差错=%d\n",
		r.BRStats.V4In, r.BRStats.V6In, r.BRStats.Translated46, r.BRStats.Translated64,
		r.BRStats.EncapIn, r.BRStats.EncapOut, r.BRStats.Dropped, r.BRStats.ICMPErrors))
	b.WriteString(fmt.Sprintf("  骨干: 投递=%d 跳数超时=%d PTB=%d 丢弃=%d\n",
		r.CloudStats.Delivered, r.CloudStats.HopExpired, r.CloudStats.TooBig, r.CloudStats.Dropped))
	b.WriteString(strings.Repeat("=", 78) + "\n")
	return b.String()
}

// Run 执行完整验收。
func Run(cfg Config) (*Report, error) {
	// PMTU 探测单独构造小 MTU 拓扑，不影响主流量拓扑（见 checkPMTU）。
	mode := sim.ModeMAPT
	if cfg.Mode == "mape" {
		mode = sim.ModeMAPE
	}
	topo, err := sim.Build(sim.Config{
		Mode: mode, SharedV4Count: cfg.SharedV4Count, CEPerV4: cfg.CEPerV4,
		PSIDLen: cfg.PSIDLen, PSIDOffset: cfg.PSIDOffset,
		ChecksumNeutral: cfg.ChecksumNeutral,
		V6LinkMTU:       1500, V4LinkMTU: 1500,
		HostsPerCE: cfg.HostsPerCE,
	})
	if err != nil {
		return nil, err
	}
	r := &Report{Mode: mode.String(), Topo: topo}

	// 容量统计
	perV4 := maprule.SubscribersPerIPv4(topo.Rule)
	portsPer := maprule.PortsPerSubscriber(topo.Rule)
	r.Capacity = fmt.Sprintf(
		"容量：规则 %s，PSID %d 位 → 一个公网 v4 地址带 %d 户；每户端口集 %d 个端口（跳过 <1024 知名端口）；仿真实装 %d 户",
		topo.Rule.RuleIPv4Prefix, cfg.PSIDLen, perV4, portsPer, len(topo.CEs))

	installUDPEchoServer(topo.Server)
	installTCPServer(topo.Server)

	r.checkUDPContent(topo)
	r.checkMultiHostNAPT(topo)
	r.checkTCPContent(topo)
	r.checkPortSetMembership(topo)
	r.checkPortSetsDisjoint(topo)
	r.checkSameDomainDirect(topo)
	r.checkPingAcrossFamilies(topo)
	r.checkTraceroute(topo)
	r.checkPMTU(topo)
	r.checkICMPPortUnreachable(topo)

	r.BRStats = topo.BR.Stats()
	r.CloudStats = topo.Cloud.Stats()
	return r, nil
}

// hostA/hostB 取两台不同户的主机用于互访测试。
func (r *Report) hostPair(topo *sim.Topology) (*stack.Host, *sim.CE, *stack.Host, *sim.CE) {
	ce1, ce2 := topo.CEs[0], topo.CEs[1]
	h1 := topo.Hosts[ce1.Name]
	h2 := topo.Hosts[ce2.Name]
	return h1, ce1, h2, ce2
}

// sleep 让出执行权，使异步投递的报文（goroutine）完成处理。
func sleep() { time.Sleep(2 * time.Millisecond) }

// waitFor 轮询条件，最多等待约 500ms，消除异步处理的时序抖动。
func waitFor(cond func() bool) bool {
	deadline := 500
	for i := 0; i < deadline; i++ {
		if cond() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return cond()
}
