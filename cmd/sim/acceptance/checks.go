package acceptance

import (
	"bytes"
	"fmt"
	"net/netip"
	"sync"

	"ivat/pkg/headers"
	"ivat/pkg/maprule"
	"ivat/pkg/sim"
	"ivat/pkg/stack"
)

const (
	echoPort uint16 = 5005
	tcpPort  uint16 = 5006
	serverV4        = "198.51.100.10"
)

// ---------- 服务器侧应用 ----------

var echoState struct {
	sync.Mutex
	received [][]byte
}

func installUDPEchoServer(s *stack.Host) {
	conn := s.BindUDP(echoPort)
	// 用一个轮询 goroutine 不可行（栈是事件驱动的），改为服务器收到后
	// 通过 Host 的回环钩子回应：这里依赖 Host 记录的接收数据，由测试侧拉取。
	_ = conn
	echoState.received = nil
	// 注册"回显器"：测试每发一个包后调用 echoOnce。
}

// echoOnce 让服务器把最近收到、尚未回显的数据报原路发回。
func echoOnce(topo *sim.Topology) {
	s := topo.Server
	for _, c := range s.UDPSnapshot() {
		if c.Echoed {
			continue
		}
		// 回显：源端口即服务端口，目的为对端 NAPT 外部端口。
		s.SendUDP(c.From, c.FromPort, echoPort, c.Data)
		c.Echoed = true
	}
}

func installTCPServer(s *stack.Host) {
	lis := s.ListenTCP(tcpPort)
	// 持续 accept，保证被动连接被登记（连接对象由协议栈维护）。
	go func() {
		for {
			_ = lis.Accept()
		}
	}()
	// 数据到达即回显：按对端找到该连接，把新增字节原样写回。
	s.SetTCPDataHook(func(c *stack.TCPConn, data []byte) {
		c.Write(data)
	})
}

// ---------- 1. UDP 应用内容一致性 ----------

func (r *Report) checkUDPContent(topo *sim.Topology) {
	host, ce, _, _ := r.hostPair(topo)
	conn := host.BindUDP(33000)
	payloads := [][]byte{
		[]byte("机顶盒频道列表-1"),
		bytes.Repeat([]byte("视频分片"), 100), // 1200 字节，在 1400 骨干 MTU 之内
		[]byte("EPG 电子节目指南"),
	}
	srv := netip.MustParseAddr(serverV4)
	for i, p := range payloads {
		conn.SendTo(srv, echoPort, p)
		sleep()
		echoOnce(topo)
		sleep()
		_ = i
	}
	// 服务器侧收到的内容必须与发送一致
	got := topo.Server.UDPReceived(mappedAddr(ce), 0) // 源端口被 NAPT，按对端聚合见下
	_ = got
	ok, detail := verifyServerReceived(topo, payloads)
	r.add("UDP：两端应用内容逐字节一致", ok, detail)

	// 主机侧收到的回显也要一致
	ok2, detail2 := verifyEchoReceived(host, srv, echoPort, payloads)
	r.add("UDP：回显报文经回程翻译后内容一致", ok2, detail2)
}

// mappedAddr 取 CE 的共享 v4（服务器看到的源地址）。
func mappedAddr(ce *sim.CE) netip.Addr { return ce.SharedV4 }

func verifyServerReceived(topo *sim.Topology, want [][]byte) (bool, string) {
	// 服务器按"对端地址:外部端口"记录；外部端口动态分配，
	// 因此把所有来自共享 v4 段的数据报摊平比对。
	var got [][]byte
	for _, ce := range topo.CEs {
		for _, rec := range ce.PortLog() {
			from := netip.AddrFrom4(ce.SharedV4.As4())
			got = append(got, topo.Server.UDPReceived(from, rec.External)...)
		}
	}
	return comparePayloads(want, got)
}

func verifyEchoReceived(host *stack.Host, from netip.Addr, fromPort uint16, want [][]byte) (bool, string) {
	got := host.UDPReceived(from, fromPort)
	return comparePayloads(want, got)
}

func comparePayloads(want, got [][]byte) (bool, string) {
	if len(got) < len(want) {
		return false, fmt.Sprintf("收到 %d 个数据报，期望 %d", len(got), len(want))
	}
	// 仿真中多户共用服务器，got 可能含其它户流量；按内容匹配而非顺序。
	used := make([]bool, len(got))
	for _, w := range want {
		found := false
		for i, g := range got {
			if !used[i] && bytes.Equal(g, w) {
				used[i] = true
				found = true
				break
			}
		}
		if !found {
			return false, fmt.Sprintf("数据报 %q 未在对端重现（长度 %d）", truncate(string(w), 24), len(w))
		}
	}
	return true, fmt.Sprintf("%d 个数据报内容全部匹配", len(want))
}

// ---------- 2. 户内多主机 NAPT44 ----------

func (r *Report) checkMultiHostNAPT(topo *sim.Topology) {
	ce := topo.CEs[2%len(topo.CEs)]
	srv := netip.MustParseAddr(serverV4)
	keys := []string{}
	for key, h := range topo.Hosts {
		if !belongsToCE(key, ce.Name) {
			continue
		}
		keys = append(keys, key)
		c := h.BindUDP(40000)
		c.SendTo(srv, echoPort, []byte("户内主机-"+h.IP.String()))
		sleep()
		echoOnce(topo)
		sleep()
	}
	st := ce.NAPTStats()
	ok := st.Entries > 0 && st.Capacity == maprule.PortsPerSubscriber(topo.Rule)
	r.add("NAPT44：户内多主机共享端口集，表规模受限于本户", ok,
		fmt.Sprintf("NAPT 表项 %d / 端口集容量 %d（状态只存在于本户 CE）", st.Entries, st.Capacity))
}

func belongsToCE(hostKey, ceName string) bool {
	return len(hostKey) >= len(ceName) && hostKey[:len(ceName)] == ceName
}

// ---------- 3. TCP 应用内容一致性 ----------

func (r *Report) checkTCPContent(topo *sim.Topology) {
	host, ce, _, _ := r.hostPair(topo)
	srv := netip.MustParseAddr(serverV4)
	conn := host.DialTCP(srv, tcpPort)
	sleep()
	<-conn.Established()
	payload := bytes.Repeat([]byte("TCP-流媒体字节流-"), 60) // 1020 字节，单段可过 MTU
	conn.Write(payload)
	// 轮询等待回显数据到达（异步 goroutine 处理）。
	var got []byte
	waitFor(func() bool {
		got = host.TCPReceived(srv, tcpPort)
		return len(got) > 0
	})
	// 服务器按"共享 v4:外部端口"记录；从 CE 端口日志取该 TCP 连接的外部端口。
	var extPort uint16
	for _, rec := range ce.PortLog() {
		if rec.Proto == headers.ProtoTCP {
			extPort = rec.External
		}
	}
	ok := bytes.Equal(got, payload)
	detail := fmt.Sprintf("发送 %d 字节，回收 %d 字节（服务器外部端口=%d）",
		len(payload), len(got), extPort)
	if !ok {
		detail += "；服务器接收键=" + fmt.Sprint(topo.Server.DebugTCPRecvKeys()) +
			"；服务器连接=" + fmt.Sprint(topo.Server.DebugTCPConns()) +
			"；CE 统计=" + fmt.Sprint(ce.Stats()) +
			"；BR=" + fmt.Sprint(topo.BR.Stats())
	}
	if !ok && len(got) > 0 {
		detail += "，内容存在差异"
	}
	r.add("TCP：三次握手、数据与校验和跨地址族正确", ok, detail)
	conn.Close()
	sleep()
}

// ---------- 4. 端口集归属 ----------

func (r *Report) checkPortSetMembership(topo *sim.Topology) {
	bad := 0
	total := 0
	for _, ce := range topo.CEs {
		set, _ := topo.Rule.Expand(ce.PSID)
		allowed := map[uint16]bool{}
		for _, p := range set {
			allowed[p] = true
		}
		for _, rec := range ce.PortLog() {
			total++
			if !allowed[rec.External] {
				bad++
			}
			if rec.External < maprule.WellKnownPortBoundary {
				bad++
			}
		}
	}
	r.add("端口集：每户使用的外部端口全部落在本户端口集内", bad == 0,
		fmt.Sprintf("检查 %d 条端口分配记录，越界 %d 条，知名端口命中 %d 条",
			total, bad, countWellKnown(topo)))
}

func countWellKnown(topo *sim.Topology) int {
	n := 0
	for _, ce := range topo.CEs {
		for _, rec := range ce.PortLog() {
			if rec.External < maprule.WellKnownPortBoundary {
				n++
			}
		}
	}
	return n
}

// ---------- 5. 户与户端口集不相交 ----------

func (r *Report) checkPortSetsDisjoint(topo *sim.Topology) {
	owner := map[uint16]string{}
	clash := 0
	for _, ce := range topo.CEs {
		set, _ := topo.Rule.Expand(ce.PSID)
		for _, p := range set {
			if prev, ok := owner[p]; ok && prev != ce.Name {
				clash++
			}
			owner[p] = ce.Name
		}
	}
	// 同共享 v4 的各 PSID 必须不相交；不同 v4 地址的端口集允许相同（地址不同即不冲突）。
	perAddr := map[netip.Addr]map[uint16]uint16{}
	for _, ce := range topo.CEs {
		if perAddr[ce.SharedV4] == nil {
			perAddr[ce.SharedV4] = map[uint16]uint16{}
		}
		set, _ := topo.Rule.Expand(ce.PSID)
		for _, p := range set {
			if psid, ok := perAddr[ce.SharedV4][p]; ok && psid != ce.PSID {
				clash++
			}
			perAddr[ce.SharedV4][p] = ce.PSID
		}
	}
	r.add("端口集：同一公网 v4 下各户端口集两两不相交", clash == 0,
		fmt.Sprintf("按共享地址分组校验 %d 户，冲突 %d 处", len(topo.CEs), clash))
}

// ---------- 6. 同域两户互访不绕 BR ----------

func (r *Report) checkSameDomainDirect(topo *sim.Topology) {
	h1, ce1, h2, ce2 := r.hostPair(topo)
	beforeBR := topo.BR.Stats()
	beforeCloud := topo.Cloud.Stats()

	// 目的必须是对端户的共享 v4 + 其端口集内端口，CE 才能无状态反解 PSID。
	peerSet, _ := topo.Rule.Expand(ce2.PSID)
	peerPort := peerSet[0]
	c1 := h1.BindUDP(41000)
	c2 := h2.BindUDP(41001)

	// 预热：各发一包，在两台 CE 的户内 NAPT 上建立映射（真实部署中
	// 由应用首包自然建立）。
	c1.SendTo(ce2.SharedV4, peerPort, []byte("同域互访-预热1"))
	sleep()
	mySet, _ := topo.Rule.Expand(ce1.PSID)
	c2.SendTo(ce1.SharedV4, mySet[0], []byte("同域互访-预热2"))
	sleep()

	c1.SendTo(ce2.SharedV4, peerPort, []byte("同域互访-不绕边界"))
	sleep()
	sleep()

	afterBR := topo.BR.Stats()
	afterCloud := topo.Cloud.Stats()
	brTouched := afterBR.V6In != beforeBR.V6In || afterBR.V4In != beforeBR.V4In
	direct := ce1.Stats().DirectPeer > 0 && ce2.Stats().DirectPeer > 0
	// 骨干云有投递（CE→CE 经接入云），但 BR 计数不动即证明未绕边界。
	ok := direct && !brTouched && afterCloud.Delivered > beforeCloud.Delivered
	r.add("同域互访：两户流量直连，不绕边界设备", ok,
		fmt.Sprintf("两 CE 直连计数=(%d,%d)，云投递增量=%d，BR 收发增量=(v6:%d, v4:%d)",
			ce1.Stats().DirectPeer, ce2.Stats().DirectPeer,
			afterCloud.Delivered-beforeCloud.Delivered,
			afterBR.V6In-beforeBR.V6In, afterBR.V4In-beforeBR.V4In))
	_ = c2
}

// ---------- 7. ping 跨地址族 ----------

func (r *Report) checkPingAcrossFamilies(topo *sim.Topology) {
	host, _, _, _ := r.hostPair(topo)
	srv := netip.MustParseAddr(serverV4)
	id := host.Ping(srv, 1, 64)
	sleep()
	sleep()
	events := host.ICMPEvents()
	reply := false
	for _, e := range events {
		if e.Type == headers.ICMP4EchoReply {
			reply = true
		}
	}
	r.add("ICMP：ping 经 v4→v6→v4 翻译后收到应答", reply,
		fmt.Sprintf("Echo ID=%d，收到 ICMP 事件 %d 个（含类型/代码双向映射）", id, len(events)))
}

// ---------- 8. 路由跟踪（traceroute 语义） ----------

func (r *Report) checkTraceroute(topo *sim.Topology) {
	host, _, _, _ := r.hostPair(topo)
	srv := netip.MustParseAddr(serverV4)
	// 逐档 TTL 探测：TTL 耗尽时路径节点回 Time Exceeded，
	// 该差错在 v6 侧产生、经 BR 里外两层翻译回 v4。
	gotExceed := false
	for ttl := uint8(1); ttl <= 6; ttl++ {
		host.Ping(srv, uint16(ttl), ttl)
		sleep()
	}
	for _, e := range host.ICMPEvents() {
		if e.Type == headers.ICMP4TimeExceed {
			gotExceed = true
		}
	}
	r.add("差错报文：路径探测/路由跟踪获得跳数超时反馈", gotExceed,
		"ICMPv6 Hop-Limit-Exceeded 经嵌套翻译还原为 ICMPv4 Time-Exceeded")
}

// ---------- 9. PMTU 与 PTB ----------

func (r *Report) checkPMTU(topo *sim.Topology) {
	// 独立小 MTU 拓扑：骨干 1280，制造 v6/v4 头长差导致的 PMTU 收敛。
	small, err := sim.Build(sim.Config{
		Mode: topo.Mode, SharedV4Count: 1, CEPerV4: 2,
		PSIDLen: topo.Rule.PSIDLen, PSIDOffset: topo.Rule.PSIDOffset,
		ChecksumNeutral: topo.Rule.ChecksumNeutral,
		V6LinkMTU:       1280, V4LinkMTU: 1500, HostsPerCE: 1,
	})
	if err != nil {
		r.add("PMTU：对端不分片时正确回差错并收敛路径 MTU", false, "小 MTU 拓扑构造失败: "+err.Error())
		return
	}
	host := small.Hosts[small.CEs[0].Name]
	srv := netip.MustParseAddr(serverV4)
	// 需要翻译后 v6 报文 > 1280：v6 头 40 + UDP 头 8 + 负载，故负载 > 1232。
	// 取 1260 字节负载 → v6 报文 1308 > 1280，触发云侧 PTB。
	big := bytes.Repeat([]byte("P"), 1260)
	conn := host.BindUDP(42000)
	conn.SendTo(srv, echoPort, big)
	// 轮询等待 PTB 往返并收敛 PMTU。
	converged := waitFor(func() bool { return host.PMTU(srv) < host.InterfaceMTU })
	pmtu := host.PMTU(srv)
	r.add("PMTU：对端不分片时正确回差错并收敛路径 MTU", converged,
		fmt.Sprintf("接口 MTU=%d，收敛后 PMTU=%d（云 PTB=%d，v6/v4 头长差已折算）",
			host.InterfaceMTU, pmtu, small.Cloud.Stats().TooBig))
}

// ---------- 10. 端口不可达差错 ----------

func (r *Report) checkICMPPortUnreachable(topo *sim.Topology) {
	host, ce, _, _ := r.hostPair(topo)
	srv := netip.MustParseAddr(serverV4)
	// 服务器未监听 9999，协议栈回端口不可达，跨域翻译后主机应收到。
	conn := host.BindUDP(43000)
	conn.SendTo(srv, 9999, []byte("无人监听"))
	waitFor(func() bool {
		for _, e := range host.ICMPEvents() {
			if e.Type == headers.ICMP4DstUnreach && e.Code == headers.ICMP4PortUnreach {
				return true
			}
		}
		return false
	})
	got := false
	for _, e := range host.ICMPEvents() {
		if e.Type == headers.ICMP4DstUnreach && e.Code == headers.ICMP4PortUnreach {
			got = true
		}
	}
	if !got {
		r.add("差错报文：UDP 端口不可达端到端还原", false,
			fmt.Sprintf("未收到 port-unreach；主机全部 ICMP 事件=%+v；BR=%+v；CE 丢弃=%+v",
				host.ICMPEvents(), topo.BR.Stats(), ce.Stats()))
		return
	}
	r.add("差错报文：UDP 端口不可达端到端还原", got,
		"ICMPv6 Destination-Unreachable(Port) ↔ ICMPv4 type3/code3 双向映射")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
