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
		{"nginx", imageSource{}, true},
		{"ghcr.io/org/app:v1" + dig, imageSource{ghcrRegistry, "org/app", "v1"}, false},
		{"ghcr.io/org/app" + dig, imageSource{}, true},
		{targetRegistry + "/shared/docker.io/library/nginx:" + tag127, imageSource{dockerHubHost, libraryNginx, tag127}, false},
		{targetRegistry + "/shared/docker.io/nginx:" + tag127, imageSource{dockerHubHost, libraryNginx, tag127}, false},
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

// TestGeneratedNameMatchesIsGenerated checks that the mirror auto-mirror
// creates for a ref counts as generated, whatever form the ref takes.
func TestGeneratedNameMatchesIsGenerated(t *testing.T) {
	tgt := &mirrorv1alpha1.ClusterMirrorTarget{Spec: mirrorv1alpha1.ClusterMirrorTargetSpec{
		Registry:       targetRegistry,
		AllowedSources: []mirrorv1alpha1.RegistryHost{dockerHubHost, ghcrRegistry},
		AutoMirror:     &mirrorv1alpha1.AutoMirror{Project: sharedProject},
	}}
	tgt.Name = "t"
	for _, ref := range []string{
		"nginx:1",
		"docker.io/library/nginx:1",
		"index.docker.io/nginx:1",
		targetRegistry + "/shared/docker.io/nginx:1",
		targetRegistry + "/shared/docker.io/library/nginx:1",
		"GHCR.io/org/app:1",
	} {
		s, err := parseImage(ref, tgt)
		if err != nil {
			t.Fatalf("parseImage(%q): %v", ref, err)
		}
		m := &mirrorv1alpha1.ArtifactMirror{}
		m.Name = generatedName(s)
		m.Labels = map[string]string{mirrorv1alpha1.LabelGenerated: trueValue, mirrorv1alpha1.LabelAutoTarget: "t"}
		m.Spec = mirrorv1alpha1.ArtifactMirrorSpec{TargetRef: "t", Type: mirrorv1alpha1.ArtifactTypeImage,
			Source: mirrorv1alpha1.Source{Registry: mirrorv1alpha1.RegistryHost(s.Registry), Repository: s.Repository},
			Target: mirrorv1alpha1.Target{Project: sharedProject}}
		if !isGenerated(tgt, m) {
			t.Errorf("mirror generated for %q (%+v) is not isGenerated", ref, s)
		}
	}
}
