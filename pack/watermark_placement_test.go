package pack

import (
	"strings"
	"testing"
)

func TestWatermarkSlotLabelsRandomizeOffsetsWithoutDeduplication(t *testing.T) {
	a, b := make([]byte, 32), make([]byte, 32)
	for i := 24; i < 32; i++ {
		b[i] = 16
	}
	first, second := 0, 0
	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		x, y := watermarkSlotLabel(a, i), watermarkSlotLabel(b, i)
		if x == y || len(x) == len(y) || !strings.HasPrefix(x, "wm") || !strings.HasSuffix(x, ":") {
			t.Fatal("slot positions were fixed or invalid")
		}
		if seen[x] {
			t.Fatal("slot constants can be merged")
		}
		seen[x] = true
		first += len(x) + 96
		second += len(y) + 96
		if first == second {
			t.Fatal("all later slot offsets remained identical")
		}
	}
}
