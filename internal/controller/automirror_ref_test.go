package controller

import (
	"testing"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
)

const (
	tag127       = "1.27"
	libraryNginx = "library/nginx"
	repoAB       = "a/b"
)

func TestParseImage(t *testing.T) {
	tgt := &mirrorv1alpha1.ClusterMirrorTarget{Spec: mirrorv1alpha1.ClusterMirrorTargetSpec{
		Registry:       targetRegistry,
		AllowedSources: []mirrorv1alpha1.RegistryHost{dockerHubHost, ghcrRegistry, "reg.example.com:5000"},
		AutoMirror:     &mirrorv1alpha1.AutoMirror{Project: sharedProject},
	}}
	dig := "@sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	tests := []struct {
		ref     string
		want    imageSource
		wantErr bool
	}{
		{"nginx:" + tag127, imageSource{dockerHubHost, libraryNginx, tag127}, false},
		{"nginx", imageSource{dockerHubHost, libraryNginx, "latest"}, false},
		{"ghcr.io/org/app:v1" + dig, imageSource{ghcrRegistry, "org/app", "v1"}, false},
		{"ghcr.io/org/app" + dig, imageSource{}, true},
		{targetRegistry + "/shared/docker.io/library/nginx:" + tag127, imageSource{dockerHubHost, libraryNginx, tag127}, false},
		{targetRegistry + "/shared/reg.example.com-5000/a/b:2", imageSource{"reg.example.com:5000", repoAB, "2"}, false},
		{targetRegistry + "/shared/quay.io/a/b:2", imageSource{}, true},
		{targetRegistry + "/other/app:2", imageSource{targetRegistry, "other/app", "2"}, false},
		{"UPPER/case:1", imageSource{}, true},
	}
	for _, tc := range tests {
		got, err := parseImage(tc.ref, tgt)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("parseImage(%q) = %+v, %v; want %+v, err=%v", tc.ref, got, err, tc.want, tc.wantErr)
		}
	}
}
