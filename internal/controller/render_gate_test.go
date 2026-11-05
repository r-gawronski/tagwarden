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
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/syncspec"
	"github.com/r-gawronski/tagwarden/internal/tags"
	"github.com/r-gawronski/tagwarden/internal/vuln"
)

const (
	testTokenSecret = "tagwarden-trivy-token" //nolint:gosec // Secret name, not a credential
	testCVE         = "CVE-2026-12345"
	externalScanner = "https://trivy.scanners.example.internal:4954"
	externalToken   = "external-token" //nolint:gosec // Secret name, not a credential
)

// inChartURL is the in-chart Trivy server of the controller tests.
const inChartURL = "http://tagwarden-trivy.tagwarden-system.svc:4954"

// testScanner is the manager scanner configuration of the unit tests.
var testScanner = ScannerConfig{URL: inChartURL, Image: trivyImage, Version: trivyVersion, TokenSecret: testTokenSecret}

// suiteScanner is the manager scanner configuration of the envtest
// suite: no in-chart server, so a gated target needs scanner.url and one
// without it is not configured.
var suiteScanner = ScannerConfig{Image: trivyImage, Version: trivyVersion, TokenSecret: testTokenSecret}

// gatedFixture is a generated mirror of a gated target with the given gate.
func gatedFixture(g mirrorv1alpha1.VulnerabilityGate) (*mirrorv1alpha1.ClusterMirrorTarget, *mirrorv1alpha1.ArtifactMirror) {
	t := validTarget("gated")
	t.Spec.AutoMirror = &mirrorv1alpha1.AutoMirror{Enabled: true, Project: teamA, VulnerabilityGate: &g}
	m := validMirror("x")
	m.Namespace = teamA
	m.Spec.TargetRef = t.Name
	m.Spec.Tags = mirrorv1alpha1.TagSelector{Tags: []string{v310}}
	m.Spec.RequiredPlatforms = nil
	m.Spec.Target = mirrorv1alpha1.Target{Project: teamA}
	m.Name = generatedNameOf(canonicalSource(m.Spec.Source))
	m.Labels = map[string]string{mirrorv1alpha1.LabelGenerated: trueValue, mirrorv1alpha1.LabelAutoTarget: t.Name}
	return t, m
}

func exception(name string, mutate func(*mirrorv1alpha1.VulnerabilityException)) mirrorv1alpha1.VulnerabilityException {
	e := mirrorv1alpha1.VulnerabilityException{
		ObjectMeta: metav1.ObjectMeta{Name: name, CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour))},
		Spec: mirrorv1alpha1.VulnerabilityExceptionSpec{
			TargetRef: "gated", Namespaces: []string{teamA}, Repository: k8sHost + "/pause",
			Vulnerabilities: []string{testCVE}, Expires: metav1.NewTime(time.Now().Add(24 * time.Hour)),
			ApprovedBy: "security@example.com", Reason: "not reachable in this image",
		},
	}
	if mutate != nil {
		mutate(&e)
	}
	return e
}

// renderGated runs the gate resolution and renders the CronJob.
func renderGated(t *testing.T, r *ArtifactMirrorReconciler, tg *mirrorv1alpha1.ClusterMirrorTarget, m *mirrorv1alpha1.ArtifactMirror) (*batchv1.CronJob, syncspec.Spec) {
	t.Helper()
	s := syncSpec(tg, m, []string{deniedCIDR})
	sc, msg, err := r.gate(context.Background(), tg, m, &s)
	if err != nil || msg != "" || sc == nil {
		t.Fatalf("gate: %v %q %v", err, msg, sc)
	}
	spec, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := syncspec.Decode(bytes.NewReader(spec))
	if err != nil {
		t.Fatalf("the Job would refuse the spec: %v", err)
	}
	cj := &batchv1.CronJob{}
	cj.Name = objectName(m)
	renderCronJob(cj, tg, m, syncImage, spec, sc, nil, nil)
	return cj, decoded
}

func reconcilerWith(t *testing.T, excs ...mirrorv1alpha1.VulnerabilityException) *ArtifactMirrorReconciler {
	c := fake.NewClientBuilder().WithScheme(goldenScheme(t))
	for i := range excs {
		c = c.WithObjects(&excs[i])
	}
	return &ArtifactMirrorReconciler{Client: c.Build(), Scanner: testScanner}
}

func TestGatedRender(t *testing.T) {
	tg, m := gatedFixture(mirrorv1alpha1.VulnerabilityGate{Enabled: true, Action: mirrorv1alpha1.GateActionBlock})
	cj, spec := renderGated(t, reconcilerWith(t), tg, m)
	pod := cj.Spec.JobTemplate.Spec.Template

	if got := pod.Labels[LabelScanner]; got != ScannerTrivy {
		t.Errorf("pod label %s = %q", LabelScanner, got)
	}
	if spec.Gate == nil || spec.Gate.Scanner.URL != "http://tagwarden-trivy.tagwarden-system.svc.cluster.local.:4954" {
		t.Fatalf("spec gate = %+v", spec.Gate)
	}
	if len(pod.Spec.InitContainers) != 1 {
		t.Fatalf("init containers = %d", len(pod.Spec.InitContainers))
	}
	sc, sync := pod.Spec.InitContainers[0], pod.Spec.Containers[0]
	if sc.Name != scannerContainer || sc.Image != trivyImage || ptr.Deref(sc.RestartPolicy, "") != corev1.ContainerRestartPolicyAlways {
		t.Errorf("sidecar = %s %s %v", sc.Name, sc.Image, sc.RestartPolicy)
	}
	if !slices.Equal(sc.Command, []string{"/bin/sh", "-c", syncspec.SidecarScript}) || sc.Args != nil {
		t.Errorf("sidecar command = %q args %q", sc.Command, sc.Args)
	}
	if !equality.Semantic.DeepEqual(sc.SecurityContext, sync.SecurityContext) {
		t.Errorf("sidecar security context %+v differs from sync %+v", sc.SecurityContext, sync.SecurityContext)
	}
	if want := resource.MustParse("2Gi"); !sc.Resources.Limits.Memory().Equal(want) {
		t.Errorf("sidecar memory limit = %s", sc.Resources.Limits.Memory())
	}

	checkSidecarEnv(t, sc, sync, spec.Gate.Scanner.URL)
	checkGatedVolumes(t, pod.Spec, sc, sync)
	if ptr.Deref(pod.Spec.AutomountServiceAccountToken, true) {
		t.Error("the gated pod mounts a ServiceAccount token")
	}
}

// checkSidecarEnv checks the sidecar env: the gate settings, and the token
// as its only Secret, which the sync container does not get.
func checkSidecarEnv(t *testing.T, sc, sync corev1.Container, url string) {
	t.Helper()
	env := map[string]corev1.EnvVar{}
	for _, e := range sc.Env {
		env[e.Name] = e
	}
	for k, v := range map[string]string{
		syncspec.ScannerURLEnv:      url,
		syncspec.ScannerTimeoutEnv:  "10m0s",
		syncspec.ScannerJavaDBEnv:   string(mirrorv1alpha1.JavaDBDisabled),
		syncspec.ScannerTemplateEnv: vuln.ReportTemplate,
		"HOME":                      syncspec.ScanDir,
		"TMPDIR":                    syncspec.ScanDir,
		"NO_PROXY":                  "*",
	} {
		if env[k].Value != v {
			t.Errorf("sidecar env %s = %q, want %q", k, env[k].Value, v)
		}
	}
	// The token is the only Secret of the sidecar, and only the sidecar has it.
	var secretEnv []string
	for _, e := range sc.Env {
		if e.ValueFrom != nil {
			secretEnv = append(secretEnv, e.Name)
		}
	}
	tok := env[trivyTokenEnv].ValueFrom
	if !slices.Equal(secretEnv, []string{trivyTokenEnv}) || tok.SecretKeyRef.Name != testTokenSecret || tok.SecretKeyRef.Key != defaultTokenKey {
		t.Errorf("sidecar secret env = %v, token %+v", secretEnv, tok)
	}
	for _, e := range sync.Env {
		if e.Name == trivyTokenEnv || e.ValueFrom != nil && e.ValueFrom.SecretKeyRef.Name == testTokenSecret {
			t.Errorf("sync container gets the scanner token: %+v", e)
		}
	}
	// No proxy and no registry Secrets in the sidecar.
	for _, e := range sc.Env {
		if strings.EqualFold(e.Name, "HTTPS_PROXY") || strings.HasPrefix(e.Name, "TAGWARDEN_PROXY") {
			t.Errorf("sidecar gets proxy env %s", e.Name)
		}
	}
}

// checkGatedVolumes checks the work and scan volumes and their mounts.
func checkGatedVolumes(t *testing.T, pod corev1.PodSpec, sc, sync corev1.Container) {
	t.Helper()
	mounts := func(c corev1.Container) map[string]corev1.VolumeMount {
		out := map[string]corev1.VolumeMount{}
		for _, v := range c.VolumeMounts {
			out[v.Name] = v
		}
		return out
	}
	scm, syncm := mounts(sc), mounts(sync)
	if len(scm) != 2 || !scm["work"].ReadOnly || scm["work"].MountPath != "/work" || scm["scan"].ReadOnly || scm["scan"].MountPath != "/scan" {
		t.Errorf("sidecar mounts = %+v", sc.VolumeMounts)
	}
	if syncm["work"].ReadOnly || syncm["scan"].ReadOnly || syncm["work"].MountPath != "/work" {
		t.Errorf("sync mounts = %+v", sync.VolumeMounts)
	}
	vols := map[string]corev1.Volume{}
	for _, v := range pod.Volumes {
		vols[v.Name] = v
	}
	if q := vols["work"].EmptyDir.SizeLimit; q == nil || q.String() != "20Gi" {
		t.Errorf("work size = %v", q)
	}
	if q := vols["scan"].EmptyDir.SizeLimit; q == nil || q.String() != "64Mi" {
		t.Errorf("scan size = %v", q)
	}
}

func TestGatedRenderTargetScanner(t *testing.T) {
	storage := resource.MustParse("40Gi")
	limits := corev1.ResourceRequirements{Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("4Gi")}}
	tg, m := gatedFixture(mirrorv1alpha1.VulnerabilityGate{Enabled: true, Scanner: &mirrorv1alpha1.ScannerSpec{
		URL:               externalScanner,
		CABundleSecretRef: &mirrorv1alpha1.SecretKeyRef{Name: "external-ca", Key: "ca.pem"},
		TokenSecretRef:    &mirrorv1alpha1.TokenSecretKeyRef{Name: externalToken, Key: "t"},
		Image:             "registry.example.internal/trivy" + trivyDigest, Version: "0.76.2",
		JavaDB: mirrorv1alpha1.JavaDBPerJob, JavaDBRepository: "registry.example.internal:8443/platform/trivy-java-db:1",
		Timeout: duration(5 * time.Minute), Storage: &storage, Resources: &limits,
	}})
	cj, spec := renderGated(t, reconcilerWith(t), tg, m)
	pod := cj.Spec.JobTemplate.Spec.Template.Spec
	sc, sync := pod.InitContainers[0], pod.Containers[0]
	if sc.Image != "registry.example.internal/trivy"+trivyDigest || spec.Gate.Scanner.Version != "0.76.2" {
		t.Errorf("image %s version %s", sc.Image, spec.Gate.Scanner.Version)
	}
	if spec.Gate.Scanner.URL != "https://trivy.scanners.example.internal.:4954" {
		t.Errorf("url = %s", spec.Gate.Scanner.URL)
	}
	if !equality.Semantic.DeepEqual(sc.Resources, limits) {
		t.Errorf("resources = %+v", sc.Resources)
	}
	var tok *corev1.SecretKeySelector
	for _, e := range sc.Env {
		switch e.Name {
		case trivyTokenEnv:
			tok = e.ValueFrom.SecretKeyRef
		case syncspec.ScannerTimeoutEnv:
			if e.Value != "5m0s" {
				t.Errorf("timeout = %s", e.Value)
			}
		case syncspec.ScannerJavaDBEnv:
			if e.Value != "PerJob" {
				t.Errorf("javaDB = %s", e.Value)
			}
		}
	}
	if tok == nil || tok.Name != externalToken || tok.Key != "t" {
		t.Errorf("token = %+v", tok)
	}
	vols := map[string]corev1.Volume{}
	for _, v := range pod.Volumes {
		vols[v.Name] = v
	}
	if q := vols["work"].EmptyDir.SizeLimit; q.String() != "40Gi" {
		t.Errorf("work size = %v", q)
	}
	if q := vols["scan"].EmptyDir.SizeLimit; q.String() != "3Gi" {
		t.Errorf("scan size = %v", q)
	}
	ca := vols["scanner-ca"].Secret
	if ca == nil || ca.SecretName != "external-ca" || ca.Items[0].Key != "ca.pem" || ca.Items[0].Path != "ca.crt" {
		t.Errorf("scanner-ca volume = %+v", ca)
	}
	for _, c := range []corev1.Container{sc, sync} {
		if !slices.ContainsFunc(c.VolumeMounts, func(v corev1.VolumeMount) bool {
			return v.Name == "scanner-ca" && v.ReadOnly && v.MountPath+"/ca.crt" == syncspec.ScannerCAFile
		}) {
			t.Errorf("%s does not mount the scanner CA at %s", c.Name, syncspec.ScannerCAFile)
		}
	}
}

func TestGateResolution(t *testing.T) {
	block := mirrorv1alpha1.VulnerabilityGate{Enabled: true, OnScanError: mirrorv1alpha1.GateActionBlock}
	report := mirrorv1alpha1.VulnerabilityGate{Enabled: true}
	for _, tc := range []struct {
		name    string
		gate    mirrorv1alpha1.VulnerabilityGate
		scanner ScannerConfig
		mutate  func(*mirrorv1alpha1.ArtifactMirror)
		gated   bool
		refused bool
	}{
		{name: "generated mirror", gate: report, scanner: testScanner, gated: true},
		{name: "gate off", gate: mirrorv1alpha1.VulnerabilityGate{OnScanError: mirrorv1alpha1.GateActionBlock}, scanner: testScanner},
		{name: "label removed", gate: block, scanner: testScanner, mutate: func(m *mirrorv1alpha1.ArtifactMirror) {
			delete(m.Labels, mirrorv1alpha1.LabelGenerated)
		}},
		{name: "not configured, Report", gate: report},
		{name: "not configured, Block", gate: block, refused: true},
		{name: "no image, Block", gate: block, scanner: ScannerConfig{URL: testScanner.URL}, refused: true},
		{name: "invalid URL, Block", gate: block, scanner: ScannerConfig{URL: "http://", Image: trivyImage, Version: trivyVersion}, refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tg, m := gatedFixture(tc.gate)
			if tc.mutate != nil {
				tc.mutate(m)
			}
			r := reconcilerWith(t)
			r.Scanner = tc.scanner
			s := syncSpec(tg, m, nil)
			sc, msg, err := r.gate(context.Background(), tg, m, &s)
			if err != nil {
				t.Fatal(err)
			}
			if (sc != nil) != tc.gated || (s.Gate != nil) != tc.gated || (msg != "") != tc.refused {
				t.Errorf("sidecar %v, gate %v, message %q", sc != nil, s.Gate != nil, msg)
			}
		})
	}
}

func TestGateSpecExceptionsAndJudged(t *testing.T) {
	tg, m := gatedFixture(mirrorv1alpha1.VulnerabilityGate{Enabled: true, MaxExceptionDuration: duration(48 * time.Hour)})
	judgedAt := metav1.NewTime(time.Date(2026, 11, 4, 9, 0, 0, 0, time.FixedZone("x", 3600)))
	m.Status.Gate = &mirrorv1alpha1.GateStatus{
		JudgedFingerprint: strings.Repeat("a", 64),
		Judged:            []mirrorv1alpha1.JudgedTag{{Tag: v310, Digest: "sha256:" + strings.Repeat("b", 64), JudgedAt: &judgedAt}},
	}
	r := reconcilerWith(t,
		exception("b-active", nil),
		exception("a-active", nil),
		exception("expired", func(e *mirrorv1alpha1.VulnerabilityException) {
			e.Spec.Expires = metav1.NewTime(time.Now().Add(-time.Minute))
		}),
		exception("too-long", func(e *mirrorv1alpha1.VulnerabilityException) {
			e.Spec.Expires = metav1.NewTime(time.Now().Add(72 * time.Hour))
		}),
		exception("other-namespace", func(e *mirrorv1alpha1.VulnerabilityException) { e.Spec.Namespaces = []string{teamB} }),
		exception("other-target", func(e *mirrorv1alpha1.VulnerabilityException) { e.Spec.TargetRef = "other-target" }),
		exception("other-repository", func(e *mirrorv1alpha1.VulnerabilityException) { e.Spec.Repository = k8sHost + "/coredns" }),
	)
	_, spec := renderGated(t, r, tg, m)
	names := make([]string, 0, len(spec.Gate.Exceptions))
	for _, e := range spec.Gate.Exceptions {
		names = append(names, e.Name)
	}
	if !slices.Equal(names, []string{"a-active", "b-active"}) {
		t.Errorf("exceptions = %v", names)
	}
	if spec.Gate.JudgedFingerprint != strings.Repeat("a", 64) ||
		!slices.Equal(spec.Gate.Judged, []syncspec.JudgedTag{{Tag: v310, Digest: "sha256:" + strings.Repeat("b", 64), JudgedAt: judgedAt.UTC()}}) {
		t.Errorf("judged = %q %v", spec.Gate.JudgedFingerprint, spec.Gate.Judged)
	}
}

func TestSecurityDriftSidecar(t *testing.T) {
	tg, m := gatedFixture(mirrorv1alpha1.VulnerabilityGate{Enabled: true})
	cj, _ := renderGated(t, reconcilerWith(t), tg, m)
	want := &cj.Spec.JobTemplate.Spec.Template
	for name, edit := range map[string]func(*corev1.Container){
		"image":   func(c *corev1.Container) { c.Image = "registry.example.internal/evil:1" },
		"command": func(c *corev1.Container) { c.Command = []string{"/bin/sh", "-c", "exit 0"} },
		"args":    func(c *corev1.Container) { c.Args = []string{"x"} },
		"env": func(c *corev1.Container) {
			c.Env = append(c.Env, corev1.EnvVar{Name: "HTTPS_PROXY", Value: "http://x"})
		},
		"envFrom":        func(c *corev1.Container) { c.EnvFrom = []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{}}} },
		"security":       func(c *corev1.Container) { c.SecurityContext.ReadOnlyRootFilesystem = new(false) },
		"mounts":         func(c *corev1.Container) { c.VolumeMounts[0].ReadOnly = false },
		"restart policy": func(c *corev1.Container) { c.RestartPolicy = nil },
	} {
		live := want.DeepCopy()
		edit(&live.Spec.InitContainers[0])
		if !securityDrift(live, want) {
			t.Errorf("an edit of the sidecar %s is not drift", name)
		}
	}
	live := want.DeepCopy()
	live.Spec.InitContainers[0].ImagePullPolicy = corev1.PullIfNotPresent
	live.Spec.InitContainers[0].TerminationMessagePath = corev1.TerminationMessagePathDefault
	if securityDrift(live, want) {
		t.Error("server defaults on the sidecar count as drift")
	}
	live = want.DeepCopy()
	delete(live.Labels, LabelScanner)
	if !securityDrift(live, want) {
		t.Error("removing the scanner label is not drift")
	}
}

// TestGateTokenDefault checks that the in-chart token goes only to the
// in-chart server: an external scanner.url without tokenSecretRef gets no
// token (threat model T33).
func TestGateTokenDefault(t *testing.T) {
	for _, tc := range []struct {
		name    string
		scanner *mirrorv1alpha1.ScannerSpec
		want    string
	}{
		{name: "in-chart server", want: testTokenSecret},
		{name: "in-chart server, own image", scanner: &mirrorv1alpha1.ScannerSpec{Image: trivyImage, Version: trivyVersion}, want: testTokenSecret},
		{name: "external server", scanner: &mirrorv1alpha1.ScannerSpec{URL: externalScanner}},
		{name: "external server with token", want: externalToken, scanner: &mirrorv1alpha1.ScannerSpec{
			URL: externalScanner, TokenSecretRef: &mirrorv1alpha1.TokenSecretKeyRef{Name: externalToken}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tg, m := gatedFixture(mirrorv1alpha1.VulnerabilityGate{Enabled: true, Scanner: tc.scanner})
			s := syncSpec(tg, m, nil)
			sc, _, err := reconcilerWith(t).gate(context.Background(), tg, m, &s)
			if err != nil || sc == nil {
				t.Fatal(err)
			}
			got := ""
			if sc.token != nil {
				got = sc.token.Name
			}
			if got != tc.want {
				t.Errorf("token Secret %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSyncSpecMaxListedTags(t *testing.T) {
	tg, m := gatedFixture(mirrorv1alpha1.VulnerabilityGate{})
	if got := syncSpec(tg, m, nil).MaxTags; got != tags.MaxTags {
		t.Errorf("default MaxTags = %d, want %d", got, tags.MaxTags)
	}
	tg.Spec.Limits = &mirrorv1alpha1.TargetLimits{MaxListedTags: ptr.To[int32](50000)}
	if got := syncSpec(tg, m, nil).MaxTags; got != 50000 {
		t.Errorf("MaxTags = %d, want 50000", got)
	}
}
