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
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/golang/glog"
)

type SecurityClaims struct {
	Labels map[string]string
}

const (
	// A set of labels claims for the subject of the certificate.
	tagClaimLabel = 1
)

// The OID for the claims extension.
// TODO: Change to the real OID for Tigera
// 1.3.6.1.4.1 = IANA Private Enterprise Numbers
// 94567 = Tigera, Inc.
// 1 = Experimental
// 1 = x509 Extensions
// 1 = claims
var oidClaimsExtension = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 49111, 1, 1, 1}

// Returns true if the Security claims are empty.  False otherwise.  We generally
// don't want to include the claims extension if it is empty.
func EmptyClaims(c SecurityClaims) bool {
	return len(c.Labels) == 0
}

// BuildClaimsExtension builds a `pkix.Extension` which contains additional
// security claims to be carried by the certificate.  It is a nonstandard extension.
func BuildClaimsExtension(claims SecurityClaims) *pkix.Extension {
	rawLabels := []asn1.RawValue{}
	for k, v := range claims.Labels {
		rl := buildRawLabel(k, v)
		rawLabels = append(rawLabels, rl)
	}
	bs, err := asn1.Marshal(rawLabels)
	if err != nil {
		// We should never hit this.
		glog.Errorf("Failed to marshall Claims Extension %v", rawLabels)
	}
	return &pkix.Extension{Id: oidClaimsExtension, Value: bs}
}

func buildRawLabel(key, value string) asn1.RawValue {
	seq := []string{key, value}
	bs, err := asn1.Marshal(seq)
	if err != nil {
		// We should never hit this.
		glog.Errorf("Failed to marshal string sequence %v", seq)
	}
	return asn1.RawValue{
		Class: asn1.ClassContextSpecific,
		Tag:   tagClaimLabel,
		Bytes: bs,
	}
}

func ExtractClaimsFromExtn(claimsExtn *pkix.Extension) (SecurityClaims, error) {
	if !claimsExtn.Id.Equal(oidClaimsExtension) {
		return SecurityClaims{}, fmt.Errorf("The input is not a Claims extension")
	}

	var sequence asn1.RawValue
	if rest, err := asn1.Unmarshal(claimsExtn.Value, &sequence); err != nil {
		return SecurityClaims{}, err
	} else if len(rest) != 0 {
		return SecurityClaims{}, fmt.Errorf("The Claims extension is incorrectly encoded")
	}

	// Check the rawValue is a sequence.
	if !sequence.IsCompound || sequence.Tag != asn1.TagSequence || sequence.Class != asn1.ClassUniversal {
		return SecurityClaims{}, fmt.Errorf("The Claims extension is incorrectly encoded")
	}

	labels := make(map[string]string)
	for bytes := sequence.Bytes; len(bytes) > 0; {
		var rawClaim asn1.RawValue
		var err error

		bytes, err = asn1.Unmarshal(bytes, &rawClaim)
		if err != nil {
			return SecurityClaims{}, err
		}

		if rawClaim.Class != asn1.ClassContextSpecific {
			return SecurityClaims{}, fmt.Errorf("The Claims extension is incorrectly encoded")
		}
		switch rawClaim.Tag {
		case tagClaimLabel:
			var strings []string
			if rest, err := asn1.Unmarshal(rawClaim.Bytes, &strings); err != nil {
				return SecurityClaims{}, err
			} else if len(rest) != 0 {
				return SecurityClaims{}, fmt.Errorf("The Claims extension is incorrectly encoded.")
			}
			// Should be encoded as [key, value]
			if len(strings) != 2 {
				return SecurityClaims{}, fmt.Errorf("The Claims extension is incorrectly encoded.")
			}
			labels[strings[0]] = strings[1]
		default:
			return SecurityClaims{}, fmt.Errorf("Unrecognized Claim extension type %v", rawClaim.Tag)
		}
	}
	return SecurityClaims{labels}, nil
}
