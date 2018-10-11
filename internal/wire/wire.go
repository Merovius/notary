// Copyright 2018 Axel Wagner
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
