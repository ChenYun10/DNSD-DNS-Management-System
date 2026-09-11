package threatintel

import (
	"encoding/json"
	"net"
	"time"
)

// Alert 是广播到局域网的威胁告警消息（JSON）。
type Alert struct {
	Type      string `json:"type"`      // 固定 "dns_threat_alert"
	Domain    string `json:"domain"`    // 恶意域名
	ClientIP  string `json:"client_ip"` // 发起查询的客户端 IP
	Category  string `json:"category"`  // 恶意分类
	Severity  string `json:"severity"`  // 严重程度
	Source    string `json:"source"`    // 情报来源 api / blacklist
	Timestamp string `json:"timestamp"` // RFC3339
}

// Broadcaster 通过 UDP 向局域网广播威胁告警。局域网内的安全设备 / 主机可
// 监听同一端口，实时接收告警并联动处置。
type Broadcaster struct {
	conn *net.UDPConn
	addr *net.UDPAddr
}

// NewBroadcaster 构造广播器。addr 是广播地址（如 255.255.255.255），
// port 是广播端口。
func NewBroadcaster(addr string, port int) (*Broadcaster, error) {
	raddr := &net.UDPAddr{IP: net.ParseIP(addr), Port: port}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	return &Broadcaster{conn: conn, addr: raddr}, nil
}

// Broadcast 广播一条威胁告警。
func (b *Broadcaster) Broadcast(hit *ThreatInfo, clientIP string) error {
	if b == nil || b.conn == nil || hit == nil {
		return nil
	}
	alert := Alert{
		Type:      "dns_threat_alert",
		Domain:    hit.Domain,
		ClientIP:  clientIP,
		Category:  hit.Category,
		Severity:  hit.Severity,
		Source:    hit.Source,
		Timestamp: time.Now().Format(time.RFC3339),
	}
	data, err := json.Marshal(alert)
	if err != nil {
		return err
	}
	_, err = b.conn.WriteToUDP(data, b.addr)
	return err
}

// Close 关闭广播 socket。
func (b *Broadcaster) Close() {
	if b != nil && b.conn != nil {
		_ = b.conn.Close()
	}
}
