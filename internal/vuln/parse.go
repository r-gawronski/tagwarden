/*
Copyright 2026 The Tagwarden Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package vuln judges Trivy scan reports for the vulnerability gate. It does
// no I/O: callers hand it a report reader, the policy and the exceptions.
package vuln

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// ReportTemplate is the Trivy --format template that keeps the report small
// (1.67 MB for 13,642 findings, against 59 MB of full JSON).
//
//go:embed report.tpl
var ReportTemplate string

// MaxReportBytes is the largest report Parse accepts.
const MaxReportBytes = 32 << 20

const maxIDLength = 128

var (
	// ErrTooLarge means the report is over MaxReportBytes.
	ErrTooLarge = errors.New("scan report too large")
	// ErrMalformed means the report is not the output of ReportTemplate.
	ErrMalformed = errors.New("malformed scan report")
)

// Severity is a Trivy severity name.
type Severity string

// Trivy severities.
const (
	Unknown  Severity = "UNKNOWN"
	Low      Severity = "LOW"
	Medium   Severity = "MEDIUM"
	High     Severity = "HIGH"
	Critical Severity = "CRITICAL"
)

// rank orders severities; an invalid value is -1.
func (s Severity) rank() int {
	switch s {
	case Unknown:
		return 0
	case Low:
		return 1
	case Medium:
		return 2
	case High:
		return 3
	case Critical:
		return 4
	}
	return -1
}

// ParseSeverity maps a policy threshold (Critical, High, Medium, Low, any
// case) to a Severity. UNKNOWN is not a threshold.
func ParseSeverity(s string) (Severity, error) {
	v := Severity(strings.ToUpper(s))
	if v == Unknown || v.rank() < 0 {
		return "", fmt.Errorf("invalid severity %q", s)
	}
	return v, nil
}

// Finding is one vulnerability entry of the report.
type Finding struct {
	ID       string   `json:"id"`
	Pkg      string   `json:"pkg"`
	Version  string   `json:"ver"`
	Fix      string   `json:"fix"`
	Severity Severity `json:"sev"`
	Status   string   `json:"status"`
}

// Parse reads a report produced with ReportTemplate. Input over
// MaxReportBytes fails with ErrTooLarge before any parsing; anything that is
// not a JSON array of valid findings fails with ErrMalformed.
func Parse(r io.Reader) ([]Finding, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxReportBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read scan report: %w", err)
	}
	if len(b) > MaxReportBytes {
		return nil, ErrTooLarge
	}
	var out []Finding
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing data", ErrMalformed)
	}
	if out == nil {
		return nil, fmt.Errorf("%w: not an array", ErrMalformed)
	}
	for i, f := range out {
		if f.ID == "" || len(f.ID) > maxIDLength || f.Severity.rank() < 0 {
			return nil, fmt.Errorf("%w: invalid finding %d", ErrMalformed, i)
		}
	}
	return out, nil
}
