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

package sync

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/r-gawronski/tagwarden/internal/syncspec"
	"github.com/r-gawronski/tagwarden/internal/vuln"
)

var hexDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

const defaultPoll = 200 * time.Millisecond

// scanManifest hands one manifest of the layout to the sidecar and parses
// its report. The sidecar is untrusted: every file is read through the scan
// root, must be a regular file and has a size cap. It returns the findings,
// or a scan error reason and a short detail.
func (g *gateState) scanManifest(ctx context.Context, d v1.Hash) ([]vuln.Finding, string, string) {
	if d.Algorithm != "sha256" || !hexDigest.MatchString(d.Hex) {
		return nil, syncspec.GateScanFailed, "unsupported digest"
	}
	ready := syncspec.ScanReqDir + "/" + d.Hex + ".ready"
	out := syncspec.ScanOutDir + "/" + d.Hex
	for _, f := range []string{out + ".json", out + ".exit", ready} {
		if err := g.root.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, syncspec.GateScanFailed, "scan volume not writable"
		}
	}
	defer func() {
		_ = g.root.Remove(out + ".json")
		_ = g.root.Remove(out + ".exit")
	}()
	f, err := g.root.OpenFile(ready, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, syncspec.GateScannerUnavailable, "scan request not writable"
	}
	_ = f.Close()

	var exit []byte
	err = g.wait(ctx, g.Timeout+g.Timeout/4, func() (bool, error) {
		var err error
		exit, err = readSmall(g.root, out+".exit", 16)
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return true, err
	})
	switch {
	case errors.Is(err, errWaitTimeout):
		// A request the sidecar never picked up means it is not running.
		if _, serr := g.root.Lstat(ready); serr == nil {
			_ = g.root.Remove(ready)
			return nil, syncspec.GateScannerUnavailable, "scanner sidecar did not answer"
		}
		return nil, syncspec.GateScanFailed, "scan timed out"
	case err != nil:
		return nil, syncspec.GateScanFailed, "invalid scanner exit file"
	}
	if code := strings.TrimSpace(string(exit)); code != "0" {
		return nil, syncspec.GateScanFailed, "scanner exited with an error"
	}
	rf, err := openRegular(g.root, out+".json")
	if err != nil {
		return nil, syncspec.GateScanFailed, "scan report missing"
	}
	defer func() { _ = rf.Close() }()
	findings, err := vuln.Parse(rf)
	switch {
	case errors.Is(err, vuln.ErrTooLarge):
		return nil, syncspec.GateScanFailed, "scan report too large"
	case err != nil:
		return nil, syncspec.GateScanFailed, "invalid scan report"
	}
	return findings, "", ""
}

var errWaitTimeout = errors.New("timed out")

// wait polls done until it reports true, the timeout passes or ctx ends.
func (g *gateState) wait(ctx context.Context, timeout time.Duration, done func() (bool, error)) error {
	poll := g.Poll
	if poll <= 0 {
		poll = defaultPoll
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(poll)
	defer tick.Stop()
	for {
		if ok, err := done(); ok || err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errWaitTimeout
		case <-tick.C:
		}
	}
}

// openRegular opens name in root without blocking on a FIFO and refuses
// anything but a regular file.
func openRegular(root *os.Root, name string) (*os.File, error) {
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	return f, nil
}

// readSmall reads a regular file of at most limit bytes.
func readSmall(root *os.Root, name string, limit int64) ([]byte, error) {
	f, err := openRegular(root, name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err == nil && int64(len(b)) > limit {
		err = fmt.Errorf("%s is larger than %d bytes", name, limit)
	}
	return b, err
}
