package onion

import (
	"context"
	"testing"
)

func TestMapAddressRejectsInputBeforeConnecting(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "198.18.0.1\r\nSIGNAL HALT"} {
		if err := (Control{}).Map(context.Background(), value, testHost(1)); err == nil {
			t.Fatal("accepted invalid address")
		}
	}
}
