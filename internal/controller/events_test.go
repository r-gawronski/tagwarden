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

package controller

import (
	"strings"
	"testing"
	"unicode/utf8"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/events"
)

func TestCapNotes(t *testing.T) {
	fake := events.NewFakeRecorder(2)
	r := CapNotes(fake)
	long := strings.Repeat("ż", noteLimit)
	r.Eventf(nil, nil, corev1.EventTypeWarning, "R", "A", "%s: %s", "tag", long)
	r.Eventf(nil, nil, corev1.EventTypeWarning, "R", "A", "100%% %s", "done")

	note := strings.TrimPrefix(<-fake.Events, "Warning R ")
	if len(note) > noteLimit || !utf8.ValidString(note) || !strings.HasPrefix(note, "tag: ") || !strings.HasSuffix(note, "...") {
		t.Errorf("long note: %d bytes, valid %v, %.20q", len(note), utf8.ValidString(note), note)
	}
	if got := <-fake.Events; got != "Warning R 100% done" {
		t.Errorf("short note = %q", got)
	}
}
