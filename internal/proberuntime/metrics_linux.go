//go:build linux

package proberuntime

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type procMetricsReader struct{}

func (procMetricsReader) Read(pid int) (processMetrics, error) {
	statusPath := filepath.Join("/proc", strconv.Itoa(pid), "status")
	file, err := os.Open(statusPath)
	if err != nil {
		return processMetrics{}, err
	}
	defer file.Close()

	var rssBytes int64 = -1
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 || fields[0] != "VmRSS:" {
			continue
		}
		rssKiB, parseErr := strconv.ParseInt(fields[1], 10, 64)
		if parseErr != nil {
			return processMetrics{}, fmt.Errorf("parse VmRSS: %w", parseErr)
		}
		rssBytes = rssKiB * 1024
		break
	}
	if err := scanner.Err(); err != nil {
		return processMetrics{}, err
	}
	if rssBytes < 0 {
		return processMetrics{}, errors.New("VmRSS missing from process status")
	}
	entries, err := os.ReadDir(filepath.Join("/proc", strconv.Itoa(pid), "fd"))
	if err != nil {
		return processMetrics{}, err
	}
	return processMetrics{rssBytes: rssBytes, fdCount: len(entries)}, nil
}
