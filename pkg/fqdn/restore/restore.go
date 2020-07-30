// Copyright 2020 Authors of Cilium
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

package restore

import (
	"regexp"
)

// DNS proxy restored rules in a separate package to avoid import loop between pkg/endpoint and pkg/fqd/endpoint

type DNSRules map[uint16]RuleIPs
type RuleIPs map[RuleRegex]IPSet
type IPSet map[string]struct{} // IPs, nil set is wildcard and allows all IPs!
type RuleRegex struct {
	*regexp.Regexp
}

// UnmarshalText unmarshals json into a RuleRegex
// This must have a pointer receiver, otherwise the RuleRegex remains empty.
func (r *RuleRegex) UnmarshalText(b []byte) error {
	regex, err := regexp.Compile(string(b))
	if err != nil {
		return err
	}
	r.Regexp = regex
	return nil
}

// MarshalText marshals RuleRegex as string
func (r RuleRegex) MarshalText() ([]byte, error) {
	if r.Regexp != nil {
		return []byte(r.Regexp.String()), nil
	}
	return nil, nil
}
