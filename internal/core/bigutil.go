// internal/core/bigutil.go
package core

import "math/big"

// ParseBigIntAuto parses s as a big integer.
// Supports "0x..." (hex) and plain decimal strings.
func ParseBigIntAuto(s string) *big.Int {
	z := new(big.Int)
	if _, ok := z.SetString(s, 0); ok { // base=0 → 0x..., 0..., 10진 자동
		return z
	}
	return nil
}
