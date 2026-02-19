//go:build linux

package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// SystemMetrics periodically collects system-level metrics from /proc.
type SystemMetrics struct {
	cpuPercent int64 // atomic: CPU usage × 100 (1550 = 15.50%)
	memAvailKB int64 // atomic: available memory in KB
	memTotalKB int64 // atomic: total memory in KB
	netUpBPS   int64 // atomic: upload bytes per second
	netDownBPS int64 // atomic: download bytes per second
}

type cpuSample struct {
	idle  uint64
	total uint64
}

type netSample struct {
	rxBytes uint64
	txBytes uint64
	ts      int64 // UnixMilli
}

// NewSystemMetrics creates and starts the metrics collector.
func NewSystemMetrics() *SystemMetrics {
	m := &SystemMetrics{}
	total, avail := readMemInfo()
	atomic.StoreInt64(&m.memTotalKB, total)
	atomic.StoreInt64(&m.memAvailKB, avail)
	go m.collectLoop()
	return m
}

func (m *SystemMetrics) CpuPercent() float64 {
	return float64(atomic.LoadInt64(&m.cpuPercent)) / 100.0
}

func (m *SystemMetrics) MemAvailMB() float64 {
	return float64(atomic.LoadInt64(&m.memAvailKB)) / 1024.0
}

func (m *SystemMetrics) MemTotalMB() float64 {
	return float64(atomic.LoadInt64(&m.memTotalKB)) / 1024.0
}

func (m *SystemMetrics) NetUpBPS() int64 {
	return atomic.LoadInt64(&m.netUpBPS)
}

func (m *SystemMetrics) NetDownBPS() int64 {
	return atomic.LoadInt64(&m.netDownBPS)
}

func (m *SystemMetrics) collectLoop() {
	prevCPU := readCPUSample()
	prevNet := readNetSample()
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// CPU
		curCPU := readCPUSample()
		totalDiff := curCPU.total - prevCPU.total
		if totalDiff > 0 {
			idleDiff := curCPU.idle - prevCPU.idle
			usage := float64(totalDiff-idleDiff) / float64(totalDiff) * 10000
			atomic.StoreInt64(&m.cpuPercent, int64(usage))
		}
		prevCPU = curCPU

		// Memory
		total, avail := readMemInfo()
		atomic.StoreInt64(&m.memTotalKB, total)
		atomic.StoreInt64(&m.memAvailKB, avail)

		// Network
		curNet := readNetSample()
		elapsedMs := curNet.ts - prevNet.ts
		if elapsedMs > 0 {
			up := float64(curNet.txBytes-prevNet.txBytes) * 1000 / float64(elapsedMs)
			down := float64(curNet.rxBytes-prevNet.rxBytes) * 1000 / float64(elapsedMs)
			atomic.StoreInt64(&m.netUpBPS, int64(up))
			atomic.StoreInt64(&m.netDownBPS, int64(down))
		}
		prevNet = curNet
	}
}

// readCPUSample reads aggregate CPU times from /proc/stat.
// Format: cpu  user nice system idle iowait irq softirq steal guest guest_nice
func readCPUSample() cpuSample {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return cpuSample{}
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return cpuSample{}
	}
	line := scanner.Text()
	if !strings.HasPrefix(line, "cpu ") {
		return cpuSample{}
	}

	fields := strings.Fields(line)
	if len(fields) < 5 {
		return cpuSample{}
	}

	var total, idle uint64
	for i := 1; i < len(fields); i++ {
		v, _ := strconv.ParseUint(fields[i], 10, 64)
		total += v
		if i == 4 { // idle field
			idle = v
		}
	}
	return cpuSample{idle: idle, total: total}
}

// readMemInfo reads MemTotal and MemAvailable from /proc/meminfo.
func readMemInfo() (totalKB, availKB int64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	got := 0
	for scanner.Scan() && got < 2 {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			totalKB = parseMemLine(line)
			got++
		} else if strings.HasPrefix(line, "MemAvailable:") {
			availKB = parseMemLine(line)
			got++
		}
	}
	return
}

func parseMemLine(line string) int64 {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	v, _ := strconv.ParseInt(fields[1], 10, 64)
	return v
}

// readNetSample reads aggregate rx/tx bytes from /proc/net/dev (excluding lo).
func readNetSample() netSample {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return netSample{ts: time.Now().UnixMilli()}
	}
	defer f.Close()

	var rxTotal, txTotal uint64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		iface := strings.TrimSpace(line[:idx])
		if iface == "lo" {
			continue
		}
		// Fields after colon: rx_bytes rx_packets ... tx_bytes tx_packets ...
		fields := strings.Fields(line[idx+1:])
		if len(fields) < 10 {
			continue
		}
		rx, _ := strconv.ParseUint(fields[0], 10, 64)
		tx, _ := strconv.ParseUint(fields[8], 10, 64)
		rxTotal += rx
		txTotal += tx
	}
	return netSample{rxBytes: rxTotal, txBytes: txTotal, ts: time.Now().UnixMilli()}
}

// readSomaxconn reads net.core.somaxconn from /proc/sys.
func readSomaxconn() int {
	data, err := os.ReadFile("/proc/sys/net/core/somaxconn")
	if err != nil {
		return -1
	}
	v, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	return v
}

// formatBytesRate formats bytes/sec into human-readable string.
func formatBytesRate(bps int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)
	switch {
	case bps >= GB:
		return fmt.Sprintf("%.1f GB", float64(bps)/float64(GB))
	case bps >= MB:
		return fmt.Sprintf("%.1f MB", float64(bps)/float64(MB))
	case bps >= KB:
		return fmt.Sprintf("%.1f KB", float64(bps)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bps)
	}
}
