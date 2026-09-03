package dnsx

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// buildQQwryMode0 构造一个 mode-0（无重定向）的 qqwry.dat 夹具：
//
//	index0: 1.2.3.0 -> "CityA"/"ISP1"
//	index1: 5.6.7.0 -> "CityB"/"ISP2"
func buildQQwryMode0() []byte {
	rec1 := []byte("CityA\x00ISP1\x00")
	rec2 := []byte("CityB\x00ISP2\x00")

	const headerLen = 8
	const entryLen = 7
	n := 2
	firstIdx := uint32(headerLen)
	off1 := firstIdx + uint32(n*entryLen)
	off2 := off1 + uint32(len(rec1))

	buf := make([]byte, 0, int(off2)+len(rec2))
	hdr := make([]byte, headerLen)
	binary.LittleEndian.PutUint32(hdr[0:4], firstIdx)
	binary.LittleEndian.PutUint32(hdr[4:8], firstIdx+uint32((n-1)*entryLen))
	buf = append(buf, hdr...)

	idx := make([]byte, n*entryLen)
	binary.LittleEndian.PutUint32(idx[0:4], ipv4Uint32(1, 2, 3, 0))
	putLe24(idx[4:7], off1)
	binary.LittleEndian.PutUint32(idx[7:11], ipv4Uint32(5, 6, 7, 0))
	putLe24(idx[11:14], off2)
	buf = append(buf, idx...)

	buf = append(buf, rec1...)
	buf = append(buf, rec2...)
	return buf
}

// buildQQwryMode1 构造一个 mode-1（重定向）的 qqwry.dat 夹具：
//
//	index0: 1.2.3.0 -> 记录[0x01][off_country][area] -> "CityC"/"ISP3"
func buildQQwryMode1() []byte {
	const headerLen = 8
	const entryLen = 7
	firstIdx := uint32(headerLen)
	recordOff := firstIdx + uint32(entryLen) // 1 条索引

	// 记录 = [0x01][3B country 偏移]["ISP3\x00"]，随后是 "CityC\x00"
	record := []byte{0x01, 0, 0, 0, 'I', 'S', 'P', '3', 0}
	countryStr := []byte("CityC\x00")
	countryOff := recordOff + uint32(len(record))
	putLe24(record[1:4], countryOff)

	buf := make([]byte, 0, 64)
	hdr := make([]byte, headerLen)
	binary.LittleEndian.PutUint32(hdr[0:4], firstIdx)
	binary.LittleEndian.PutUint32(hdr[4:8], firstIdx)
	buf = append(buf, hdr...)

	idx := make([]byte, entryLen)
	binary.LittleEndian.PutUint32(idx[0:4], ipv4Uint32(1, 2, 3, 0))
	putLe24(idx[4:7], recordOff)
	buf = append(buf, idx...)

	buf = append(buf, record...)
	buf = append(buf, countryStr...)
	return buf
}

func ipv4Uint32(a, b, c, d byte) uint32 {
	return uint32(a)<<24 | uint32(b)<<16 | uint32(c)<<8 | uint32(d)
}

func putLe24(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
}

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	return p
}

func TestQQwryMode0(t *testing.T) {
	p := writeTemp(t, "mode0.dat", buildQQwryMode0())
	db, err := NewQQwry(p)
	if err != nil {
		t.Fatalf("NewQQwry: %v", err)
	}

	g, ok := db.Lookup(net.IPv4(1, 2, 3, 4))
	if !ok {
		t.Fatal("lookup 1.2.3.4 not found")
	}
	if g.Location != "CityA" || g.ISP != "isp1" {
		t.Fatalf("1.2.3.4 => %+v, want CityA/isp1", g)
	}

	g2, ok := db.Lookup(net.IPv4(5, 6, 7, 8))
	if !ok {
		t.Fatal("lookup 5.6.7.8 not found")
	}
	if g2.Location != "CityB" || g2.ISP != "isp2" {
		t.Fatalf("5.6.7.8 => %+v, want CityB/isp2", g2)
	}
}

func TestQQwryMode1Redirect(t *testing.T) {
	p := writeTemp(t, "mode1.dat", buildQQwryMode1())
	db, err := NewQQwry(p)
	if err != nil {
		t.Fatalf("NewQQwry: %v", err)
	}

	g, ok := db.Lookup(net.IPv4(1, 2, 3, 9))
	if !ok {
		t.Fatal("lookup not found")
	}
	if g.Location != "CityC" || g.ISP != "isp3" {
		t.Fatalf("mode1 => %+v, want CityC/isp3", g)
	}
}

func TestQQwryIPv6NotSupported(t *testing.T) {
	p := writeTemp(t, "mode0.dat", buildQQwryMode0())
	db, _ := NewQQwry(p)
	if _, ok := db.Lookup(net.ParseIP("2001:db8::1")); ok {
		t.Fatal("qqwry should not resolve IPv6")
	}
}

func TestIPv6CSVLookup(t *testing.T) {
	csv := "# comment\n" +
		"64:ff9b::/96,CN,Zhejiang,Hangzhou,Telecom\n" +
		"2001:db8:100::/48,CN,Zhejiang,Ningbo,Unicom\n"
	p := writeTemp(t, "ipv6.csv", []byte(csv))
	db, err := NewIPv6CSV(p)
	if err != nil {
		t.Fatalf("NewIPv6CSV: %v", err)
	}

	g, ok := db.Lookup(net.ParseIP("64:ff9b::1.2.3.4"))
	if !ok {
		t.Fatal("no match for 64:ff9b")
	}
	if g.Province != "Zhejiang" || g.ISP != "telecom" {
		t.Fatalf("64:ff9b => %+v", g)
	}

	g2, ok := db.Lookup(net.ParseIP("2001:db8:100:abcd::1"))
	if !ok {
		t.Fatal("no match for 2001:db8:100::/48")
	}
	if g2.ISP != "unicom" {
		t.Fatalf("2001:db8 => %+v", g2)
	}

	if _, ok := db.Lookup(net.ParseIP("2001:db8:9999::1")); ok {
		t.Fatal("unexpected match")
	}
}

type fakeDB struct{ m map[string]GeoISP }

func (f *fakeDB) Lookup(ip net.IP) (GeoISP, bool) {
	g, ok := f.m[ip.String()]
	return g, ok
}

func TestVerifier(t *testing.T) {
	v4 := &fakeDB{m: map[string]GeoISP{
		"1.2.3.4": {Province: "Zhejiang", City: "Hangzhou", ISP: "telecom"},
	}}

	cases := []struct {
		name  string
		v6ip  string
		v6geo GeoISP
		v4ip  string
		want  bool
	}{
		{"match", "64:ff9b::1.2.3.4", GeoISP{Province: "Zhejiang", City: "Hangzhou", ISP: "telecom"}, "1.2.3.4", true},
		{"isp-mismatch", "64:ff9b::1.2.3.4", GeoISP{Province: "Zhejiang", City: "Hangzhou", ISP: "unicom"}, "1.2.3.4", false},
		{"province-mismatch", "64:ff9b::1.2.3.4", GeoISP{Province: "Jiangsu", City: "Hangzhou", ISP: "telecom"}, "1.2.3.4", false},
		{"v6-missing", "64:ff9b::9.9.9.9", GeoISP{}, "1.2.3.4", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			key := net.ParseIP(c.v6ip).String()
			v6 := &fakeDB{m: map[string]GeoISP{key: c.v6geo}}
			v := NewVerifier(v4, v6, false)
			got, _ := v.Verify(net.ParseIP(c.v6ip), net.ParseIP(c.v4ip))
			if got != c.want {
				t.Fatalf("Verify(%s,%s) = %v, want %v", c.v6ip, c.v4ip, got, c.want)
			}
		})
	}

	// strict city
	v6strict := &fakeDB{m: map[string]GeoISP{
		net.ParseIP("64:ff9b::1.2.3.4").String(): {Province: "Zhejiang", City: "Ningbo", ISP: "telecom"},
	}}
	if ok, _ := NewVerifier(v4, v6strict, true).Verify(net.ParseIP("64:ff9b::1.2.3.4"), net.ParseIP("1.2.3.4")); ok {
		t.Fatal("strict city check should fail for Hangzhou vs Ningbo")
	}
	if ok, _ := NewVerifier(v4, v6strict, false).Verify(net.ParseIP("64:ff9b::1.2.3.4"), net.ParseIP("1.2.3.4")); !ok {
		t.Fatal("non-strict check should pass with same province+isp")
	}
}

func TestExtractProvince(t *testing.T) {
	cases := map[string]string{
		"浙江省杭州市":      "浙江省",
		"广东省深圳市":      "广东省",
		"北京市":         "北京市",
		"内蒙古自治区呼和浩特市": "内蒙古自治区",
		"Unknown":     "Unknown",
	}
	for in, want := range cases {
		if got := extractProvince(in); got != want {
			t.Fatalf("extractProvince(%q)=%q, want %q", in, got, want)
		}
	}
}
