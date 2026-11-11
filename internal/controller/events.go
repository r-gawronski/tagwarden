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
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
)

// noteLimit is the events.k8s.io/v1 limit for an Event note. The API server
// rejects a longer note, and the Event is lost.
const noteLimit = 1024

type cappedRecorder struct{ events.EventRecorder }

// CapNotes cuts every Event note to noteLimit bytes, so a long condition
// message relayed as an Event still arrives.
func CapNotes(r events.EventRecorder) events.EventRecorder { return cappedRecorder{r} }

func (r cappedRecorder) Eventf(regarding, related runtime.Object, eventtype, reason, action, note string, args ...any) {
	if note = fmt.Sprintf(note, args...); len(note) > noteLimit {
		note = cut(note, noteLimit-3) + "..."
	}
	r.EventRecorder.Eventf(regarding, related, eventtype, reason, action, "%s", note)
}
