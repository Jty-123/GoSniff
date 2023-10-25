package sniffer

import (
	"encoding/hex"
	"fmt"
)

func BytesToMACString(b []byte) string {
	macString := hex.EncodeToString(b)
	for i := 2; i < len(macString); i += 3 {
		macString = macString[:i] + ":" + macString[i:]
	}
	return macString
}
func BytesToIPString(b []byte) string {
	ipString := fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
	return ipString
}
func BytesToHex(b []byte) string {
	res := hex.EncodeToString(b)
	count := 0
	for i := 2; i < len(res); i += 3 {
		if count%10 == 0 && count != 0 {
			res = res[:i] + "\n" + res[i:]
		} else {
			res = res[:i] + " " + res[i:]
		}
		count++
	}
	return res
}
func BytesToAscii(b []byte) string {
	res := ""
	for _, v := range b {
		if v < 32 || v > 126 {
			res += "."
		} else {
			res += string(v)
		}
	}
	for i := 0; i < len(res); i++ {
		if i%40 == 0 && i != 0 {
			res = res[:i] + "\n" + res[i:]
		}
	}
	return res
}
