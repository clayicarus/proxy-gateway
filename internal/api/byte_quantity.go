package api

import (
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

var byteQuantityPattern = regexp.MustCompile(`^([0-9]+(\.[0-9]*)?|\.[0-9]+)$`)

// Missing units preserve the byte-only forms served by older versions.
func parseByteQuantity(value, unit string) (uint64, error) {
	var multiplier int64
	switch unit {
	case "", "B":
		multiplier = 1
	case "KB":
		multiplier = 1 << 10
	case "MB":
		multiplier = 1 << 20
	case "GB":
		multiplier = 1 << 30
	default:
		return 0, fmt.Errorf("请选择 GB、MB、KB 或 B 单位")
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	if len(value) > 64 || !byteQuantityPattern.MatchString(value) {
		return 0, fmt.Errorf("请输入非负整数或小数")
	}
	quantity, ok := new(big.Rat).SetString(value)
	if !ok {
		return 0, fmt.Errorf("请输入非负整数或小数")
	}
	quantity.Mul(quantity, big.NewRat(multiplier, 1))
	whole, remainder := new(big.Int), new(big.Int)
	whole.QuoRem(quantity.Num(), quantity.Denom(), remainder)
	// Round partial bytes up so a positive limit never becomes 0 (unlimited).
	if remainder.Sign() != 0 {
		whole.Add(whole, big.NewInt(1))
	}
	// SQLite INTEGER is signed, even though the runtime fields are uint64.
	if !whole.IsInt64() {
		return 0, fmt.Errorf("换算后的值不能超过 9223372036854775807 字节")
	}
	return whole.Uint64(), nil
}

// 2^20 has a terminating decimal with at most 20 fractional digits. Preserve
// every byte when an existing user is displayed in MB and saved unchanged.
func formatMegabytes(value uint64) string {
	quantity := new(big.Rat).SetInt(new(big.Int).SetUint64(value))
	quantity.Quo(quantity, big.NewRat(1<<20, 1))
	return strings.TrimRight(strings.TrimRight(quantity.FloatString(20), "0"), ".")
}
