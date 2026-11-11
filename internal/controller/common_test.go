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
	"context"
	"errors"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// A status conflict requeues without an error; other status errors are returned.
func TestStatusUpdateConflictRequeues(t *testing.T) {
	boom := errors.New("boom")
	for name, tc := range map[string]struct {
		updateErr error
		want      ctrl.Result
		wantErr   error
	}{
		"conflict": {
			updateErr: apierrors.NewConflict(schema.GroupResource{Group: "mirror.tagwarden.dev", Resource: "vulnerabilityexceptions"}, "e", errors.New("modified")),
			want:      ctrl.Result{RequeueAfter: conflictRequeue},
		},
		"other error": {updateErr: boom, wantErr: boom},
	} {
		t.Run(name, func(t *testing.T) {
			e := validException("missing", time.Now().Add(time.Hour))
			c := fake.NewClientBuilder().WithScheme(goldenScheme(t)).WithObjects(e).WithStatusSubresource(e).
				WithInterceptorFuncs(interceptor.Funcs{
					SubResourceUpdate: func(context.Context, client.Client, string, client.Object, ...client.SubResourceUpdateOption) error {
						return tc.updateErr
					},
				}).Build()
			r := &VulnerabilityExceptionReconciler{Client: c}

			got, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: e.Name}})
			if !errors.Is(err, tc.wantErr) || got != tc.want {
				t.Fatalf("Reconcile() = %+v, %v; want %+v, %v", got, err, tc.want, tc.wantErr)
			}
		})
	}
}
