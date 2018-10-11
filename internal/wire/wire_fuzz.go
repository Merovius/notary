// +build gofuzz

package wire

import (
	"errors"
	"sort"
	"unsafe"
)

func Fuzz(data []byte) int {
	var vals [][]byte
	dec := func(st *DecodeState) {
		var t Tag
		first := true
		for ; st.i < st.n; st.i++ {
			tag, val := st.field(st.i)
			if !first && tag <= t {
				st.Abort(errors.New("unordered tags"))
			}
			vals = append(vals, val)
		}
	}
	if err := Decode(data, dec); err != nil {
		return 0
	}
	checkOverlap(vals)
	return 1
}

func checkOverlap(vals [][]byte) {
	sort.Slice(vals, func(i, j int) bool {
		a, b := vals[i], vals[j]
		if len(a) == 0 || len(b) == 0 {
			return len(a) < len(b)
		}
		return uintptr(unsafe.Pointer(&a[0])) < uintptr(unsafe.Pointer(&b[0]))
	})
	var found bool
	for i := 0; i < len(vals); i++ {
		if len(vals[i]) > 0 {
			found = true
			vals = vals[i:]
			break
		}
	}
	if !found {
		return
	}
	for i := 1; i < len(vals); i++ {
		a := vals[i-1]
		b := vals[i]
		if uintptr(unsafe.Pointer(&a[0]))+uintptr(len(a)) >= uintptr(unsafe.Pointer(&b[0])) {
			panic("overlapping values")
		}
	}
}
