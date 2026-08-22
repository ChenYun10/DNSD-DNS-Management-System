// dnsbench — DNS 数据面压测工具(UDP/TCP)
//
// 用法:
//   go run ./tools/dnsbench -server 127.0.0.1:53 -qps 10000 -dur 20s -qname www.example.com
//   dnsbench -server 203.0.113.1:53 -qps 2000 -dur 10s -threads 8
//
// 输出:实际 QPS、成功率、avg / p50 / p95 / p99 延迟。
// 注意:对生产 DNS 压测会触发限流与告警(ai-detect),先调小 qps 或在对端关闭限流。
package main

import (
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"os/signal"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

var (
	server  = flag.String("server", "127.0.0.1:53", "target resolver addr")
	qps     = flag.Int("qps", 5000, "target queries per second")
	dur     = flag.Duration("dur", 10*time.Second, "benchmark duration")
	threads = flag.Int("threads", 4, "concurrent workers (UDP sockets)")
	qname   = flag.String("qname", "www.baidu.com", "query name")
	qtype   = flag.String("type", "A", "query type")
	mode    = flag.String("mode", "udp", "transport: udp | tcp")
	timeout = flag.Duration("timeout", 2*time.Second, "per-query timeout")
	verbose = flag.Bool("v", false, "verbose errors")
)

func main() {
	flag.Parse()

	interval := time.Second / time.Duration(*qps)
	if interval <= 0 {
		interval = time.Nanosecond
	}

	// 构造查询
	m := new(dns.Msg)
	qt, ok := dns.StringToType[*qtype]
	if !ok {
		qt = dns.TypeA
	}
	m.SetQuestion(dns.Fqdn(*qname), qt)
	m.SetEdns0(1232, false)
	raw, err := m.Pack()
	if err != nil {
		fmt.Fprintln(os.Stderr, "pack:", err)
		os.Exit(1)
	}

	var sent, okCount, errCount atomic.Int64
	var latMu sync.Mutex
	var lats []float64
	record := func(d time.Duration, ok bool) {
		latMu.Lock()
		lats = append(lats, float64(d.Microseconds()))
		latMu.Unlock()
		if ok {
			okCount.Add(1)
		} else {
			errCount.Add(1)
		}
	}

	// worker:独立 socket 循环收发
	worker := func(id int) {
		if *mode == "udp" {
			conn, err := net.DialTimeout("udp", *server, 2*time.Second)
			if err != nil {
				fmt.Fprintln(os.Stderr, "dial:", err)
				os.Exit(1)
			}
			defer conn.Close()
			buf := make([]byte, 4096)
			for {
				start := time.Now()
				if _, err := conn.Write(raw); err != nil {
					record(time.Since(start), false)
					continue
				}
				_ = conn.SetReadDeadline(time.Now().Add(*timeout))
				_, err := conn.Read(buf)
				record(time.Since(start), err == nil)
			}
		} else {
			// TCP:复用连接(miekg/dns dns.Conn 自带长度帧),断线重连
			var co *dns.Conn
			connect := func() bool {
				conn, err := net.DialTimeout("tcp", *server, 2*time.Second)
				if err != nil {
					co = nil
					return false
				}
				co = &dns.Conn{Conn: conn}
				return true
			}
			if !connect() {
				time.Sleep(50 * time.Millisecond)
			}
			defer func() {
				if co != nil {
					co.Close()
				}
			}()
			for {
				if co == nil && !connect() {
					time.Sleep(50 * time.Millisecond)
					continue
				}
				start := time.Now()
				_ = co.SetWriteDeadline(time.Now().Add(*timeout))
				if err := co.WriteMsg(m); err != nil {
					record(time.Since(start), false)
					co.Close()
					co = nil
					continue
				}
				_ = co.SetReadDeadline(time.Now().Add(*timeout))
				_, err := co.ReadMsg()
				if err != nil {
					record(time.Since(start), false)
					co.Close()
					co = nil
					continue
				}
				record(time.Since(start), true)
			}
		}
	}

	// 定时器按目标 QPS 派发(每个 tick 唤醒一个 worker)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	done := time.After(*dur)
	stop := make(chan struct{})

	var wg sync.WaitGroup
	_ = wg
	for i := 0; i < *threads; i++ {
		go worker(i)
	}

	// 每秒打印进度
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				fmt.Printf("\r  sent=%d ok=%d err=%d", sent.Load(), okCount.Load(), errCount.Load())
			case <-stop:
				return
			}
		}
	}()

	fmt.Printf("bench: %s %s -> %s  qps=%d dur=%s threads=%d\n", *mode, *qtype, *server, *qps, *dur, *threads)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

loop:
	for {
		select {
		case <-ticker.C:
			sent.Add(1)
		case <-done:
			break loop
		case <-sig:
			break loop
		}
	}
	close(stop)
	time.Sleep(1000 * time.Millisecond) // 等 in-flight 回来(worker 随进程退出)
	ticker.Stop()

	total := okCount.Load() + errCount.Load()
	_ = total
	latMu.Lock()
	sort.Float64s(lats)
	latMu.Unlock()

	pct := func(p float64) float64 {
		if len(lats) == 0 {
			return 0
		}
		idx := int(math.Ceil(p/100*float64(len(lats)))) - 1
		if idx < 0 {
			idx = 0
		}
		if idx >= len(lats) {
			idx = len(lats) - 1
		}
		return lats[idx] / 1000 // ms
	}
	avg := 0.0
	if len(lats) > 0 {
		s := 0.0
		for _, v := range lats {
			s += v
		}
		avg = s / float64(len(lats)) / 1000
	}

	fmt.Printf("\n==== result ====\n")
	fmt.Printf("sent=%d ok=%d err=%d success=%.2f%%\n", sent.Load(), okCount.Load(), errCount.Load(), float64(okCount.Load())/float64(sent.Load())*100)
	fmt.Printf("latency(ms): avg=%.2f p50=%.2f p95=%.2f p99=%.2f\n", avg, pct(50), pct(95), pct(99))
}
