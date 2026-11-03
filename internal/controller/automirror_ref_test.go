package controller

import (
	"testing"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
)

func TestParseImage(t *testing.T) {
	tgt := &mirrorv1alpha1.ClusterMirrorTarget{Spec: mirrorv1alpha1.ClusterMirrorTargetSpec{
		Registry:       "registry.example.internal:8443",
		AllowedSources: []mirrorv1alpha1.RegistryHost{"docker.io", "ghcr.io", "reg.example.com:5000"},
		AutoMirror:     &mirrorv1alpha1.AutoMirror{Project: "shared"},
	}}
	dig := "@sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	tests := []struct {
		ref     string
		want    imageSource
		wantErr bool
	}{
		{"nginx:1.27", imageSource{"docker.io", "library/nginx", "1.27"}, false},
		{"nginx", imageSource{"docker.io", "library/nginx", "latest"}, false},
		{"ghcr.io/org/app:v1" + dig, imageSource{"ghcr.io", "org/app", "v1"}, false},
		{"ghcr.io/org/app" + dig, imageSource{}, true},
		{"registry.example.internal:8443/shared/docker.io/library/nginx:1.27", imageSource{"docker.io", "library/nginx", "1.27"}, false},
		{"registry.example.internal:8443/shared/reg.example.com-5000/a/b:2", imageSource{"reg.example.com:5000", "a/b", "2"}, false},
		{"registry.example.internal:8443/shared/quay.io/a/b:2", imageSource{}, true},
		{"registry.example.internal:8443/other/app:2", imageSource{"registry.example.internal:8443", "other/app", "2"}, false},
		{"UPPER/case:1", imageSource{}, true},
	}
	for _, tc := range tests {
		got, err := parseImage(tc.ref, tgt)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("parseImage(%q) = %+v, %v; want %+v, err=%v", tc.ref, got, err, tc.want, tc.wantErr)
		}
	}
}
