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
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
)

// extractTar writes the files of a tar stream into root. Only regular files
// named in allowed are accepted, each once, at most maxFiles of them and
// maxBytes in total; a leading "./" is ignored and a "./" directory entry
// is skipped. Anything else fails the extraction: absolute or parent paths,
// other names, directories, links, devices and FIFOs. root confines every
// write, and files are created exclusively, so nothing is overwritten or
// followed.
func extractTar(r io.Reader, root *os.Root, allowed []string, maxFiles int, maxBytes int64) error {
	tr := tar.NewReader(r)
	files := 0
	left := maxBytes
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}
		name := strings.TrimPrefix(h.Name, "./")
		if h.Typeflag == tar.TypeDir && (name == "" || name == ".") {
			continue
		}
		if h.Typeflag != tar.TypeReg || !slices.Contains(allowed, name) {
			return fmt.Errorf("tar: unexpected entry %.64q", h.Name)
		}
		if files++; files > maxFiles {
			return fmt.Errorf("tar: more than %d files", maxFiles)
		}
		if h.Size > left {
			return fmt.Errorf("tar: more than %d bytes", maxBytes)
		}
		f, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}
		n, err := io.Copy(f, io.LimitReader(tr, left))
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}
		left -= n
	}
}
