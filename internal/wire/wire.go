package wire

import (
	"encoding/binary"
	"strconv"
)

// Tag represents a wire-format tag.
type Tag uint32

// String implements fmt.Stringer
func (t Tag) String() string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(t))
	s := strconv.Quote(string(b[:]))
	return s[1 : len(s)-1]
}
