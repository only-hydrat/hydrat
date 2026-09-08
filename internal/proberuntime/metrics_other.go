//go:build !linux

package proberuntime

type procMetricsReader struct{}

func (procMetricsReader) Read(int) (processMetrics, error) {
	return processMetrics{}, ErrMetricsUnsupported
}
