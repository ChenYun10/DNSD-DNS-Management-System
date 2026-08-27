package store

import "testing"

func TestValidPrefix(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"xnoa-gov", true},
		{"xnoa-test", true},
		{"my-dns", true},
		{"gov-01", true},
		{"a1", false},            // 太短
		{"XNOA", false},          // 大写
		{"xnoa_gov", false},      // 下划线
		{"xnoa.gov", false},      // 点号
		{"xnoa gov", false},      // 空格
		{"dns", false},           // 保留词
		{"www", false},           // 保留词
		{"vip", false},           // 保留词
		{"admin", false},         // 保留词
		{"-abc", false},          // 首字符不能是连字符
		{"abc-", true},           // 尾连字符允许（规则内）
		{"abcdefghijklmnopqrstuvwxyz012345", true},   // 32 位（26 字母 + 6 数字）
		{"abcdefghijklmnopqrstuvwxyz0123456", false}, // 33 位
		{"这是一个很长前缀", false},                        // 非 ASCII
	}
	for _, c := range cases {
		if got := ValidPrefix(c.in); got != c.want {
			t.Errorf("ValidPrefix(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
