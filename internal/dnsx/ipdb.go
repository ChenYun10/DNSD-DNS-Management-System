package dnsx

// IP 归属地/运营商数据库（用于 IPv6 ↔ IPv4 一致性校验）。
//
// 设计为一个可插拔的 IPDB 接口 + 两个具体实现：
//   - qqwryDB: 纯真 IP 库 qqwry.dat（经典二进制格式，IPv4，含归属地+运营商）
//   - ipv6CSVDB: IPv6 归属地 CSV（最长前缀匹配，字段显式）
//
// Verifier 组合一个 IPv4 库与一个 IPv6 库，判断两者是否指向同一物理
// 归属地/运营商。任何一侧缺失或不一致都视为校验失败（fail-closed）。

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"strings"

	"golang.org/x/text/encoding/simplifiedchinese"
)

// GeoISP is the result of one IP geolocation/ISP lookup.
type GeoISP struct {
	Location string // 原始/综合归属地（如 "浙江省杭州市"）
	Province string // 省（显式或从 Location 提取）
	City     string // 市（可选）
	ISP      string // 运营商（如 "电信" / "联通" / "移动"）
}

// IPDB looks up geolocation + ISP for an IP address.
type IPDB interface {
	Lookup(ip net.IP) (GeoISP, bool)
}

// ---------------------------------------------------------------------------
// 纯真 IP 库 qqwry.dat（IPv4）
// ---------------------------------------------------------------------------

// qqwryDB is a reader for the classic 纯真 IP 库 (qqwry.dat).
//
// 文件结构：
//
//	文件头(8B)      first_index(4B LE) last_index(4B LE)
//	索引区(7B/条)   起始IP(4B LE) 记录偏移(3B LE)，按起始IP升序
//	数据区          国家/地区字符串(GBK, NUL 结尾) + 重定向标记
type qqwryDB struct {
	data     []byte
	firstIdx uint32
	lastIdx  uint32
	indexN   int
}

// NewQQwry loads a 纯真 qqwry.dat file into memory. The whole file is kept
// in memory (typically 10-50 MB) for fast binary-search lookups.
func NewQQwry(path string) (*qqwryDB, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < 8 {
		return nil, errShortQQwry
	}
	db := &qqwryDB{
		data:     data,
		firstIdx: binary.LittleEndian.Uint32(data[0:4]),
		lastIdx:  binary.LittleEndian.Uint32(data[4:8]),
	}
	if db.firstIdx > db.lastIdx || int(db.lastIdx) >= len(data) {
		return nil, errShortQQwry
	}
	db.indexN = int(db.lastIdx-db.firstIdx)/7 + 1
	return db, nil
}

var errShortQQwry = &qqwryError{"qqwry.dat too short or corrupt"}

type qqwryError struct{ s string }

func (e *qqwryError) Error() string { return e.s }

// Lookup finds the country/region + ISP for an IPv4 address.
func (q *qqwryDB) Lookup(ip net.IP) (GeoISP, bool) {
	ip4 := ip.To4()
	if ip4 == nil || q == nil {
		return GeoISP{}, false
	}
	// IP 的数值序 = 网络字节序 uint32；索引内存储为小端 uint32，两者数值一致。
	target := binary.BigEndian.Uint32(ip4)

	lo, hi := 0, q.indexN-1
	pos := -1
	for lo <= hi {
		mid := (lo + hi) / 2
		start := q.indexStart(mid)
		if start <= target {
			pos = mid
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	if pos < 0 {
		return GeoISP{}, false
	}
	off := q.indexOffset(pos)
	country, area := q.readRecord(off)
	loc := gbkToUTF8(country)
	isp := gbkToUTF8(area)
	return GeoISP{Location: loc, Province: extractProvince(loc), ISP: normalizeISP(isp)}, true
}

func (q *qqwryDB) indexStart(i int) uint32 {
	p := int(q.firstIdx) + i*7
	return binary.LittleEndian.Uint32(q.data[p : p+4])
}

func (q *qqwryDB) indexOffset(i int) uint32 {
	p := int(q.firstIdx) + i*7
	return le24(q.data[p+4 : p+7])
}

// readRecord parses the country + area strings at the given data offset,
// following 0x01/0x02 redirect modes.
func (q *qqwryDB) readRecord(offset uint32) (country, area []byte) {
	if int(offset) >= len(q.data) {
		return nil, nil
	}
	switch q.data[offset] {
	case 0x01, 0x02:
		// 重定向：后 3 字节为国家字符串偏移；地区字符串紧随其后。
		countryOff := le24(q.data[offset+1 : offset+4])
		country = q.readCString(countryOff)
		area = q.readArea(offset + 4)
	default:
		country = q.readCString(offset)
		area = q.readArea(offset + uint32(len(country)) + 1)
	}
	return country, area
}

// readArea reads the area (ISP) string, following redirect modes.
func (q *qqwryDB) readArea(offset uint32) []byte {
	if int(offset) >= len(q.data) {
		return nil
	}
	switch q.data[offset] {
	case 0x01, 0x02:
		off := le24(q.data[offset+1 : offset+4])
		if off == 0 {
			return nil
		}
		return q.readCString(off)
	default:
		return q.readCString(offset)
	}
}

// readCString reads a NUL-terminated byte string at offset (raw, no decode).
func (q *qqwryDB) readCString(offset uint32) []byte {
	if int(offset) >= len(q.data) {
		return nil
	}
	end := bytes.IndexByte(q.data[offset:], 0)
	if end < 0 {
		return q.data[offset:]
	}
	return q.data[offset : offset+uint32(end)]
}

func le24(b []byte) uint32 {
	if len(b) < 3 {
		return 0
	}
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16
}

func gbkToUTF8(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	out, err := simplifiedchinese.GBK.NewDecoder().Bytes(b)
	if err != nil {
		return string(b)
	}
	return string(out)
}

// ---------------------------------------------------------------------------
// IPv6 归属地 CSV（最长前缀匹配）
// ---------------------------------------------------------------------------

// ipv6CSVDB loads IPv6 subnet → (country,province,city,isp) from a CSV file.
// 每行：ipv6_subnet,country,province,city,isp（# 开头为注释）。
type ipv6CSVDB struct {
	entries []ipv6GeoEntry
}

type ipv6GeoEntry struct {
	net *net.IPNet
	geo GeoISP
}

// NewIPv6CSV loads the IPv6 geolocation CSV.
func NewIPv6CSV(path string) (*ipv6CSVDB, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	db := &ipv6CSVDB{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			continue
		}
		_, ipnet, err := net.ParseCIDR(strings.TrimSpace(parts[0]))
		if err != nil || ipnet == nil {
			continue
		}
		g := GeoISP{}
		get := func(idx int) string {
			if idx < len(parts) {
				return strings.TrimSpace(parts[idx])
			}
			return ""
		}
		g.Location = get(1)
		g.Province = get(2)
		g.City = get(3)
		g.ISP = normalizeISP(get(4))
		if g.Province == "" {
			g.Province = extractProvince(g.Location)
		}
		db.entries = append(db.entries, ipv6GeoEntry{net: ipnet, geo: g})
	}
	return db, nil
}

// Lookup returns the entry whose subnet is the longest prefix matching ip.
func (d *ipv6CSVDB) Lookup(ip net.IP) (GeoISP, bool) {
	if d == nil || ip == nil {
		return GeoISP{}, false
	}
	best := -1
	bestLen := -1
	for i, e := range d.entries {
		if e.net.Contains(ip) {
			ones, _ := e.net.Mask.Size()
			if ones > bestLen {
				best, bestLen = i, ones
			}
		}
	}
	if best < 0 {
		return GeoISP{}, false
	}
	return d.entries[best].geo, true
}

// ---------------------------------------------------------------------------
// Verifier: IPv6 ↔ IPv4 归属地/运营商一致性
// ---------------------------------------------------------------------------

// Verifier 组合一个 IPv4 库和一个 IPv6 库，用于校验两个地址是否指向同一
// 物理归属地/运营商。
type Verifier struct {
	v4     IPDB
	v6     IPDB
	strict bool // true 时额外要求城市一致
}

// NewVerifier 构造校验器。v4/v6 任一为 nil 即无法校验。
func NewVerifier(v4, v6 IPDB, strict bool) *Verifier {
	return &Verifier{v4: v4, v6: v6, strict: strict}
}

// Verify 判断 ip6 与 ip4 是否同一归属地/运营商。返回 ok 与失败原因。
func (v *Verifier) Verify(ip6, ip4 net.IP) (bool, string) {
	if v == nil || v.v4 == nil || v.v6 == nil {
		return false, "geo db not configured"
	}
	g6, ok6 := v.v6.Lookup(ip6)
	g4, ok4 := v.v4.Lookup(ip4)
	if !ok6 || !ok4 {
		return false, "geo lookup missing"
	}
	if g6.ISP == "" || g4.ISP == "" {
		return false, "isp missing"
	}
	if g6.ISP != g4.ISP {
		return false, "isp mismatch"
	}
	p6, p4 := provinceKey(g6.Province), provinceKey(g4.Province)
	if p6 == "" || p4 == "" || p6 != p4 {
		return false, "province mismatch"
	}
	if v.strict {
		c6, c4 := normalizeLoc(g6.City), normalizeLoc(g4.City)
		if c6 != "" && c4 != "" && c6 != c4 {
			return false, "city mismatch"
		}
	}
	return true, ""
}

// --- 归一化辅助 ---

// normalizeISP 归一化运营商字符串：去空白、转小写、剥掉 "中国"/"China" 前缀，
// 使 "电信" / "中国电信" / "ChinaTelecom" 可比较。
func normalizeISP(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "中国")
	s = strings.TrimPrefix(s, "china")
	return strings.TrimSpace(s)
}

// normalizeLoc 去掉空白并转小写。
func normalizeLoc(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// provinceKey 归一化省份，便于比较（"浙江省" 与 "浙江" 视为不同，需一致）。
func provinceKey(s string) string {
	return normalizeLoc(s)
}

// extractProvince 从 "浙江省杭州市" 之类的组合串中提取省份。
func extractProvince(loc string) string {
	loc = strings.TrimSpace(loc)
	if loc == "" {
		return ""
	}
	for _, m := range []string{"北京市", "上海市", "天津市", "重庆市"} {
		if strings.HasPrefix(loc, m) {
			return m
		}
	}
	if i := strings.Index(loc, "自治区"); i >= 0 {
		return loc[:i+len("自治区")]
	}
	if i := strings.Index(loc, "省"); i >= 0 {
		return loc[:i+len("省")]
	}
	return loc
}
