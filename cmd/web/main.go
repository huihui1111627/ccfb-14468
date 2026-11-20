// Command web 提供规则计算页面：输入一户的规则参数与 PSID，
// 页面展示 IPv6 地址拼装、端口集公式展开、BR 无状态反算的完整过程。
package main

import (
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/netip"

	"ivat/pkg/maprule"
)

//go:embed web/*
var webFS embed.FS

// CalcRequest 是页面提交的一户参数。
type CalcRequest struct {
	V4Prefix        string `json:"v4Prefix"`
	V6Prefix        string `json:"v6Prefix"`
	PSIDLen         int    `json:"psidLen"`
	PSIDOffset      int    `json:"psidOffset"`
	PSID            int    `json:"psid"`
	SharedV4        string `json:"sharedV4"`
	ChecksumNeutral bool   `json:"checksumNeutral"`
}

// CalcResponse 是返回给页面的逐步推演结果。
type CalcResponse struct {
	OK               bool             `json:"ok"`
	Error            string           `json:"error,omitempty"`
	Rule             map[string]any   `json:"rule"`
	SubscriberV6     string           `json:"subscriberV6,omitempty"`
	PortSet          []uint16         `json:"portSet,omitempty"`
	PortSetCount     int              `json:"portSetCount,omitempty"`
	SubscribersPerV4 int              `json:"subscribersPerV4,omitempty"`
	Steps            []maprule.Step   `json:"steps,omitempty"`
	ResolveDemo      []ResolveExample `json:"resolveDemo,omitempty"`
	Disjoint         bool             `json:"disjoint"`
}

// ResolveExample 演示 BR 从 (v4, 端口) 反算户 v6 的无状态过程。
type ResolveExample struct {
	Port  uint16 `json:"port"`
	PSID  uint16 `json:"psid"`
	V6    string `json:"v6"`
	InSet bool   `json:"inSet"`
}

func handleCalc(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	var req CalcRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, "请求解析失败: "+err.Error())
		return
	}
	v4pfx, err := netip.ParsePrefix(req.V4Prefix)
	if err != nil {
		writeErr(w, "IPv4 前缀非法: "+err.Error())
		return
	}
	v6pfx, err := netip.ParsePrefix(req.V6Prefix)
	if err != nil {
		writeErr(w, "IPv6 前缀非法: "+err.Error())
		return
	}
	shared, err := netip.ParseAddr(req.SharedV4)
	if err != nil {
		writeErr(w, "共享 IPv4 非法: "+err.Error())
		return
	}
	rule := &maprule.Rule{
		RuleIPv4Prefix:  v4pfx,
		RuleIPv6Prefix:  v6pfx,
		EALen:           (32 - v4pfx.Bits()) + req.PSIDLen,
		PSIDOffset:      req.PSIDOffset,
		PSIDLen:         req.PSIDLen,
		ChecksumNeutral: req.ChecksumNeutral,
		DomainID:        1,
		Name:            "页面规则",
	}
	if err := rule.Validate(); err != nil {
		writeErr(w, err.Error())
		return
	}
	if req.PSID < 0 || req.PSID > int(rule.MaxPSID()) {
		writeErr(w, fmt.Sprintf("PSID 必须在 0..%d 之间", rule.MaxPSID()))
		return
	}
	if !rule.ContainsV4(shared) {
		writeErr(w, "共享 IPv4 不在规则前缀内")
		return
	}

	psid := uint16(req.PSID)
	v6, err := rule.EncodeIPv6(shared, psid)
	if err != nil {
		writeErr(w, err.Error())
		return
	}
	steps, set, err := maprule.ExplainPortSet(psid, req.PSIDOffset, req.PSIDLen)
	if err != nil {
		writeErr(w, err.Error())
		return
	}

	// BR 无状态反算演示：取端口集前若干端口，验证仅凭规则即可还原户 v6。
	demo := []ResolveExample{}
	for i, p := range set {
		if i >= 5 {
			break
		}
		gotPSID, _ := rule.PSIDFromPort(p)
		gotV6, _, _ := rule.ResolveV4ToV6(shared, p)
		demo = append(demo, ResolveExample{
			Port: p, PSID: gotPSID, V6: gotV6.String(), InSet: true,
		})
	}

	// 校验不同 PSID 的端口集不相交（取相邻两个集合抽样）。
	disjoint := true
	if psid > 0 {
		other, _ := rule.Expand(psid - 1)
		this := map[uint16]bool{}
		for _, p := range set {
			this[p] = true
		}
		for _, p := range other {
			if this[p] {
				disjoint = false
			}
		}
	}

	resp := CalcResponse{
		OK: true,
		Rule: map[string]any{
			"v4Prefix":        rule.RuleIPv4Prefix.String(),
			"v6Prefix":        rule.RuleIPv6Prefix.String(),
			"eaLen":           rule.EALen,
			"psidLen":         rule.PSIDLen,
			"psidOffset":      rule.PSIDOffset,
			"checksumNeutral": rule.ChecksumNeutral,
		},
		SubscriberV6:     v6.String(),
		PortSet:          set,
		PortSetCount:     len(set),
		SubscribersPerV4: maprule.SubscribersPerIPv4(rule),
		Steps:            steps,
		ResolveDemo:      demo,
		Disjoint:         disjoint,
	}
	json.NewEncoder(w).Encode(resp)
}

func writeErr(w http.ResponseWriter, msg string) {
	json.NewEncoder(w).Encode(CalcResponse{OK: false, Error: msg})
}

func main() {
	addr := flag.String("addr", ":8080", "HTTP 监听地址")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/calc", handleCalc)
	mux.Handle("/", http.FileServer(http.FS(webFS)))

	log.Printf("规则计算页面已启动: http://localhost%s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
