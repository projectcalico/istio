// Copyright 2017 Istio Authors
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

package pki

import (
	"reflect"
	"testing"
)

func TestBuildAndExtractClaimsExtension(t *testing.T) {
	claims := SecurityClaims{
		Labels: map[string]string{
			"app":   "test",
			"color": "blue",
		},
	}
	extn := BuildClaimsExtension(claims)
	extractedClaims, err := ExtractClaimsFromExtn(extn)
	if err != nil {
		t.Errorf("Unexpected error decoding claims extension: %v", err)
	}
	if !reflect.DeepEqual(claims, extractedClaims) {
		t.Errorf("Decoded claims do not match.  Expected %v, got %v", claims, extractedClaims)
	}
}

func TestEmptyClaims(t *testing.T) {
	notEmpty := SecurityClaims{
		Labels: map[string]string{
			"app":   "test",
			"color": "blue",
		},
	}
	if ret := EmptyClaims(notEmpty); ret {
		t.Errorf("EmptyClaims(%v): expected false got %v", notEmpty, ret)
	}
	empty := SecurityClaims{
		Labels: map[string]string{},
	}
	if ret := EmptyClaims(empty); !ret {
		t.Errorf("EmptyClaims(%v): expected true got %v", empty, ret)
	}
}
