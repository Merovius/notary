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
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestDecode(t *testing.T) {
	tcs := []struct {
		in        string
		wantTags  []string
		wantBytes []string
		wantErr   bool
	}{
		// No data
		{"", nil, nil, true},
		// Data too short
		{"010203", nil, nil, true},
		// No fields
		{"00000000", nil, nil, false},
		// Missing tags
		{"01000000", nil, nil, true},
		// Empty field
		{"0100000054455354", []string{"TEST"}, []string{""}, false},
		// Field length not multiple of 4
		{"0100000054455354464f4f", nil, nil, true},
		// Single field
		{"0100000054455354464f4f0a", []string{"TEST"}, []string{"FOO\n"}, false},
		// Wrong order of tags
		{"0200000004000000454747535350414d464f4f0a4241520a", nil, nil, true},
		// Two fields
		{"02000000040000005350414d45474753464f4f0a4241520a", []string{"SPAM", "EGGS"}, []string{"FOO\n", "BAR\n"}, false},
		// Wrong order of offsets
		{"0300000008000000040000005350414d4547475354455354464f4f0a4241520a", nil, nil, true},
		// Three fields
		{"0300000004000000080000005350414d4547475354455354464f4f0a4241520a", []string{"SPAM", "EGGS", "TEST"}, []string{"FOO\n", "BAR\n", ""}, false},
	}
	for _, tc := range tcs {
		check := func(st *DecodeState) {
			for i, stag := range tc.wantTags {
				var content []byte
				tag := makeTag(stag)
				st.Bytes(tag, &content)
				if bytes.Compare(content, []byte(tc.wantBytes[i])) != 0 {
					t.Errorf("st.Bytes(%v) = %x, want %x", tag, content, tc.wantBytes[i])
				}
			}
			for ; st.i < st.n; st.i++ {
				tag, value := st.field(st.i)
				t.Errorf("unused field %v with content %x in test input", tag, value)
			}
		}
		err := Decode(hexBytes(tc.in), check)
		if err != nil && !tc.wantErr {
			t.Errorf("Decode(%q) = %v, want nil", tc.in, err)
		}
		if err == nil && tc.wantErr {
			t.Errorf("Decode(%q) = <nil>, want error", tc.in)
		}
	}
}

func TestEncode(t *testing.T) {
	tcs := []struct {
		inTags  []string
		inBytes []string
		want    string
	}{
		{nil, nil, "00000000"},
		{[]string{"TEST"}, []string{""}, "0100000054455354"},
		{[]string{"TEST"}, []string{"FOO\n"}, "0100000054455354464f4f0a"},
		{[]string{"SPAM", "EGGS"}, []string{"FOO\n", "BAR\n"}, "02000000040000005350414d45474753464f4f0a4241520a"},
		{[]string{"SPAM", "EGGS", "TEST"}, []string{"FOO\n", "BAR\n", ""}, "0300000004000000080000005350414d4547475354455354464f4f0a4241520a"},
	}
	for _, tc := range tcs {
		enc := func(st *EncodeState) {
			st.NTags(uint32(len(tc.inTags)))
			for i, stag := range tc.inTags {
				tag := makeTag(stag)
				content := st.Bytes(tag, len(tc.inBytes[i]))
				copy(content, tc.inBytes[i])
			}
		}
		msg := Encode(enc)
		if want := hexBytes(tc.want); bytes.Compare(msg, want) != 0 {
			t.Errorf("Encode(%v) = %x, want %x", tc.inTags, msg, want)
		}
	}
}

func hexBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func makeTag(s string) Tag {
	if len(s) != 4 {
		panic("invalid tag")
	}
	return Tag(binary.LittleEndian.Uint32([]byte(s)))
}
