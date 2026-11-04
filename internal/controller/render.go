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
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"path/filepath"
	"regexp"
	"strings"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/utils/ptr"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/syncspec"
	"github.com/r-gawronski/tagwarden/internal/tags"
	"github.com/r-gawronski/tagwarden/internal/vuln"
)

// Labels and annotations on the objects rendered for a mirror. Names may be
// longer than a label value, so the label holds a hash and the annotations
// hold the full names.
const (
	LabelMirror               = "tagwarden.dev/mirror"
	AnnotationMirrorNamespace = "tagwarden.dev/mirror-namespace"
	AnnotationMirrorName      = "tagwarden.dev/mirror-name"
	annotationSpecChecksum    = "tagwarden.dev/spec-checksum"
	annotationCronJobChecksum = "tagwarden.dev/cronjob-checksum"

	// LabelTarget names the ClusterMirrorTarget of a sync CronJob, Job and
	// pod: the name, or "h-" and the first 20 hex characters of its sha256
	// when the name is not a valid label value.
	LabelTarget = "tagwarden.dev/target"
	// LabelEgress is EgressProxy when the target sets a proxy, else
	// EgressDirect. NetworkPolicies select sync pods by it.
	LabelEgress  = "tagwarden.dev/egress"
	EgressProxy  = "proxy"
	EgressDirect = "direct"
	// LabelScanner is ScannerTrivy on gated sync pods, so the Trivy
	// server's NetworkPolicy admits them.
	LabelScanner = "tagwarden.dev/scanner"
	ScannerTrivy = "trivy"

	// SyncServiceAccount runs the sync pods unless a pod uses cloud auth
	// with spec.workloadIdentity.serviceAccountName. It has no RBAC bindings.
	SyncServiceAccount = "tagwarden-sync"
	syncContainer      = "sync"
	scannerContainer   = "scanner"
	workVolume         = "work"
	scanVolume         = "scan"
	trivyTokenEnv      = "TRIVY_TOKEN" //nolint:gosec // env var name, not a credential
	// defaultTokenKey is the key of the scanner token in its Secret.
	defaultTokenKey = "token"
	specKey         = "spec.json"
)

// mirrorHash is the first 20 hex characters of sha256(namespace/name).
// Objects also carry the full names in annotations, and the controller
// never touches an object whose annotations name another mirror.
func mirrorHash(namespace, name string) string {
	sum := sha256.Sum256([]byte(namespace + "/" + name))
	return hex.EncodeToString(sum[:])[:20]
}

// targetLabel is the LabelTarget value of a target name.
func targetLabel(name string) string {
	if len(validation.IsValidLabelValue(name)) == 0 {
		return name
	}
	sum := sha256.Sum256([]byte(name))
	return "h-" + hex.EncodeToString(sum[:])[:20]
}

// maxObjectName is the CronJob name limit (52) that leaves room for the
// Job suffix the CronJob controller appends.
const maxObjectName = 52

var (
	unsafeName = regexp.MustCompile(`[^a-z0-9-]+`)
	dashRun    = regexp.MustCompile(`-{2,}`)
)

// objectName names the CronJob and ConfigMap of a mirror:
// <namespace>-<mirror>-<hash8>, with the readable part sanitised to
// DNS-1123 and cut so the whole name fits maxObjectName. The hash of
// "namespace/name" keeps names unique when the readable parts collide.
func objectName(m *mirrorv1alpha1.ArtifactMirror) string {
	return boundedName(m, maxObjectName)
}

// boundedName is objectName cut to at most limit characters.
func boundedName(m *mirrorv1alpha1.ArtifactMirror, limit int) string {
	sum := sha256.Sum256([]byte(m.Namespace + "/" + m.Name))
	hash := hex.EncodeToString(sum[:])[:8]
	readable := strings.ToLower(m.Namespace + "-" + m.Name)
	readable = dashRun.ReplaceAllString(unsafeName.ReplaceAllString(readable, "-"), "-")
	readable = strings.Trim(readable, "-")
	if n := limit - len(hash) - 1; len(readable) > n {
		readable = strings.TrimRight(readable[:n], "-")
	}
	if readable == "" {
		return hash
	}
	return readable + "-" + hash
}

// canonicalSource is the source as registry/repository with the Docker Hub
// names folded to docker.io and the implicit library/ prefix added, so two
// spellings of one source compare equal.
func canonicalSource(s mirrorv1alpha1.Source) string {
	reg := syncspec.CanonicalRegistry(string(s.Registry))
	repo := s.Repository
	if reg == "docker.io" && !strings.Contains(repo, "/") {
		repo = "library/" + repo
	}
	return reg + "/" + repo
}

// pathSafe turns the port separator and IPv6 brackets of a registry host
// into characters a repository path allows.
var pathSafe = strings.NewReplacer("[", "", "]", "", ":", "-")

// registrySegment is the path segment of a source registry in the default
// target path.
func registrySegment(host mirrorv1alpha1.RegistryHost) string {
	return pathSafe.Replace(syncspec.CanonicalRegistry(string(host)))
}

// defaultTargetPath is the canonical source made path-safe.
func defaultTargetPath(m *mirrorv1alpha1.ArtifactMirror) string {
	return pathSafe.Replace(canonicalSource(m.Spec.Source))
}

// targetPath is the repository inside the project: the override, or the
// default path.
func targetPath(m *mirrorv1alpha1.ArtifactMirror) string {
	if m.Spec.Target.Repository != "" {
		return m.Spec.Target.Repository
	}
	return defaultTargetPath(m)
}

// targetKey identifies the target repository of a mirror within the
// ClusterMirrorTarget it names, for the collision index.
func targetKey(m *mirrorv1alpha1.ArtifactMirror) string {
	return m.Spec.TargetRef + "/" + string(m.Spec.Target.Project) + "/" + targetPath(m)
}

// targetRepo is the full target repository reference.
func targetRepo(t *mirrorv1alpha1.ClusterMirrorTarget, m *mirrorv1alpha1.ArtifactMirror) string {
	return string(t.Spec.Registry) + "/" + string(m.Spec.Target.Project) + "/" + targetPath(m)
}

// targetAuth names the cloud provider of the target push, or "".
func targetAuth(t *mirrorv1alpha1.ClusterMirrorTarget) string {
	switch a := t.Spec.Auth; {
	case a == nil:
		return ""
	case a.AzureWorkloadIdentity != nil:
		return syncspec.AuthAzureWorkloadIdentity
	case a.AWSWorkloadIdentity != nil:
		return syncspec.AuthAWSWorkloadIdentity
	case a.GCPWorkloadIdentity != nil:
		return syncspec.AuthGCPWorkloadIdentity
	}
	return ""
}

// sourceAuth names the cloud provider of a source entry, or "".
func sourceAuth(c *mirrorv1alpha1.SourceCredential) string {
	switch {
	case c == nil:
		return ""
	case c.AzureWorkloadIdentity != nil:
		return syncspec.AuthAzureWorkloadIdentity
	case c.AWSWorkloadIdentity != nil:
		return syncspec.AuthAWSWorkloadIdentity
	case c.GCPWorkloadIdentity != nil:
		return syncspec.AuthGCPWorkloadIdentity
	}
	return ""
}

// cloudAuth names the cloud providers of the target push and of the
// mirror's source pull, "" for none.
func cloudAuth(t *mirrorv1alpha1.ClusterMirrorTarget, m *mirrorv1alpha1.ArtifactMirror) (target, source string) {
	cred, _ := sourceRefs(t, string(m.Spec.Source.Registry))
	return targetAuth(t), sourceAuth(cred)
}

// syncSpec renders the spec the sync Job reads. It holds no secret values.
func syncSpec(t *mirrorv1alpha1.ClusterMirrorTarget, m *mirrorv1alpha1.ArtifactMirror, denied []string) syncspec.Spec {
	mutation := t.Spec.Policy.OnTagMutation
	if mutation == "" {
		mutation = mirrorv1alpha1.OnTagMutationFail
	}
	allowed := make([]string, 0, len(t.Spec.AllowedSources))
	for _, a := range t.Spec.AllowedSources {
		allowed = append(allowed, string(a))
	}
	var maxSize int64
	if l := t.Spec.Limits; l != nil && l.MaxArtifactSize != nil {
		maxSize = l.MaxArtifactSize.Value()
	}
	s := syncspec.Spec{
		Mirror:            syncspec.Mirror{Namespace: m.Namespace, Name: m.Name},
		Source:            canonicalSource(m.Spec.Source),
		Target:            targetRepo(t, m),
		Tags:              tagPolicy(m.Spec.Tags),
		RequiredPlatforms: m.Spec.RequiredPlatforms,
		OnTagMutation:     mutation,
		MaxTags:           int(limitOr(limitsOf(t).MaxListedTags, tags.MaxTags)),
		MaxArtifactSize:   maxSize,
		AllowedSources:    allowed,
		DeniedCIDRs:       denied,
	}
	s.TargetAuth, s.SourceAuth = cloudAuth(t, m)
	uses := func(p string) bool { return s.TargetAuth == p || s.SourceAuth == p }
	// A target that uses cloud auth without its identity is not Ready.
	wi := t.Spec.WorkloadIdentity
	if wi != nil && wi.Azure != nil && uses(syncspec.AuthAzureWorkloadIdentity) {
		s.Azure = &syncspec.Azure{
			ClientID:      wi.Azure.ClientID,
			TenantID:      wi.Azure.TenantID,
			AuthorityHost: cmp.Or(wi.Azure.AuthorityHost, syncspec.DefaultAzureAuthorityHost),
		}
	}
	if wi != nil && wi.AWS != nil && uses(syncspec.AuthAWSWorkloadIdentity) {
		s.AWS = &syncspec.AWS{RoleARN: wi.AWS.RoleARN, Region: wi.AWS.Region}
	}
	if wi != nil && wi.GCP != nil && uses(syncspec.AuthGCPWorkloadIdentity) {
		s.GCP = &syncspec.GCP{Audience: wi.GCP.Audience, ServiceAccountEmail: wi.GCP.ServiceAccountEmail}
	}
	return s
}

func tagPolicy(sel mirrorv1alpha1.TagSelector) tags.Policy {
	p := tags.Policy{
		Include: sel.Include, Exclude: sel.Exclude, SemverRange: sel.SemverRange,
		AllowPrerelease: sel.AllowPrerelease, Tags: sel.Tags,
	}
	if sel.KeepLatest != nil {
		p.KeepLatest = int(*sel.KeepLatest)
	}
	return p
}

func mirrorMeta(m *mirrorv1alpha1.ArtifactMirror) (labels, annotations map[string]string) {
	return map[string]string{
			LabelMirror:                    mirrorHash(m.Namespace, m.Name),
			"app.kubernetes.io/managed-by": "tagwarden",
		}, map[string]string{
			AnnotationMirrorNamespace: m.Namespace,
			AnnotationMirrorName:      m.Name,
		}
}

// renderConfigMap sets the spec ConfigMap content.
func renderConfigMap(cm *corev1.ConfigMap, m *mirrorv1alpha1.ArtifactMirror, spec []byte) {
	cm.Labels, cm.Annotations = mirrorMeta(m)
	cm.Data = map[string]string{specKey: string(spec)}
}

// sidecar is the scanner sidecar of a gated sync pod.
type sidecar struct {
	// gate is the resolved gate of the spec: scanner URL, image, timeout
	// and javaDB mode.
	gate *syncspec.Gate
	// scanner is the target's scanner spec, nil for the defaults.
	scanner *mirrorv1alpha1.ScannerSpec
	// token is the Secret with the server token, nil for none.
	token *mirrorv1alpha1.TokenSecretKeyRef
}

// Scan volume sizes: TMPDIR and reports need little, the Java DB of
// javaDB PerJob needs its tarball and the unpacked DB.
var (
	scanVolumeSize       = resource.MustParse("64Mi")
	scanVolumeSizePerJob = resource.MustParse("3Gi")
	defaultWorkSize      = resource.MustParse("20Gi")
)

// sidecarResources are the scanner resources unless the target sets them.
func sidecarResources(s *mirrorv1alpha1.ScannerSpec) corev1.ResourceRequirements {
	if s != nil && s.Resources != nil {
		return *s.Resources
	}
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("256Mi")},
		Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("2"), corev1.ResourceMemory: resource.MustParse("2Gi")},
	}
}

// renderCronJob sets the CronJob spec. Only fixed paths, the sync image and
// Secret references go into the pod; tenant fields reach the Job only
// through the spec file. sc adds the scanner sidecar of a gated Job; nil
// renders the Job without it.
func renderCronJob(cj *batchv1.CronJob, t *mirrorv1alpha1.ClusterMirrorTarget, m *mirrorv1alpha1.ArtifactMirror, image string, spec []byte, sc *sidecar, trackLabels, trackAnnotations map[string]string) {
	labels, annotations := mirrorMeta(m)
	labels[LabelTarget] = targetLabel(t.Name)
	if sc != nil {
		labels[LabelScanner] = ScannerTrivy
	}
	labels[LabelEgress] = EgressDirect
	if t.Spec.Proxy != nil && t.Spec.Proxy.HTTPSProxy != "" {
		labels[LabelEgress] = EgressProxy
	}
	// Argo CD tracking goes on the CronJob only, not on Jobs and pods.
	cj.Labels, cj.Annotations = maps.Clone(labels), maps.Clone(annotations)
	maps.Copy(cj.Labels, trackLabels)
	maps.Copy(cj.Annotations, trackAnnotations)
	sum := sha256.Sum256(spec)
	podAnnotations := map[string]string{
		AnnotationMirrorNamespace: m.Namespace,
		AnnotationMirrorName:      m.Name,
		annotationSpecChecksum:    hex.EncodeToString(sum[:]),
	}

	readOnly := func(name, path string) corev1.VolumeMount {
		return corev1.VolumeMount{Name: name, MountPath: path, ReadOnly: true}
	}
	secretVolume := func(name, secret string, items ...corev1.KeyToPath) corev1.Volume {
		return corev1.Volume{Name: name, VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
			SecretName: secret, Items: items, DefaultMode: ptr.To[int32](0o440),
		}}}
	}
	volumes := []corev1.Volume{
		{Name: "spec", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
			LocalObjectReference: corev1.LocalObjectReference{Name: cj.Name},
			Items:                []corev1.KeyToPath{{Key: specKey, Path: filepath.Base(syncspec.SpecFile)}},
			DefaultMode:          ptr.To[int32](0o440),
		}}},
	}
	mounts := []corev1.VolumeMount{readOnly("spec", filepath.Dir(syncspec.SpecFile))}
	if ref := t.Spec.CredentialsSecretRef; ref != nil {
		volumes = append(volumes, secretVolume("target-auth", ref.Name,
			corev1.KeyToPath{Key: corev1.DockerConfigJsonKey, Path: filepath.Base(syncspec.TargetAuthFile)}))
		mounts = append(mounts, readOnly("target-auth", filepath.Dir(syncspec.TargetAuthFile)))
	}
	volumes = append(volumes, corev1.Volume{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}})
	mounts = append(mounts, corev1.VolumeMount{Name: "tmp", MountPath: "/tmp"})
	addCA := func(name string, ref *mirrorv1alpha1.SecretKeyRef, file string) {
		if ref == nil {
			return
		}
		volumes = append(volumes, secretVolume(name, ref.Name, corev1.KeyToPath{Key: ref.Key, Path: filepath.Base(file)}))
		mounts = append(mounts, readOnly(name, filepath.Dir(file)))
	}
	addCA("target-ca", t.Spec.CABundleSecretRef, syncspec.TargetCAFile)
	if ref := t.Spec.ClientCertSecretRef; ref != nil {
		volumes = append(volumes, secretVolume("client-cert", ref.Name,
			corev1.KeyToPath{Key: corev1.TLSCertKey, Path: corev1.TLSCertKey},
			corev1.KeyToPath{Key: corev1.TLSPrivateKeyKey, Path: corev1.TLSPrivateKeyKey}))
		mounts = append(mounts, readOnly("client-cert", syncspec.ClientCertDir))
	}
	// Only the Secrets of this mirror's source go into its pod.
	srcCred, srcCA := sourceRefs(t, string(m.Spec.Source.Registry))
	if srcCred != nil && srcCred.SecretRef != nil {
		volumes = append(volumes, secretVolume("source-auth", srcCred.SecretRef.Name,
			corev1.KeyToPath{Key: corev1.DockerConfigJsonKey, Path: filepath.Base(syncspec.SourceAuthFile)}))
		mounts = append(mounts, readOnly("source-auth", filepath.Dir(syncspec.SourceAuthFile)))
	}
	addCA("source-ca", srcCA, syncspec.SourceCAFile)
	// Cloud auth gets a projected token for the cloud audience only, never
	// a Kubernetes API token.
	serviceAccount := SyncServiceAccount
	tokens := []struct{ provider, volume, audience, file string }{
		{syncspec.AuthAzureWorkloadIdentity, "azure-token", syncspec.AzureTokenAudience, syncspec.AzureTokenFile},
		{syncspec.AuthAWSWorkloadIdentity, "aws-token", syncspec.AWSTokenAudience, syncspec.AWSTokenFile},
	}
	// An empty audience would mint a Kubernetes API token: without the
	// GCP identity the target is not Ready and the pod gets no GCP token.
	if wi := t.Spec.WorkloadIdentity; wi != nil && wi.GCP != nil {
		tokens = append(tokens, struct{ provider, volume, audience, file string }{
			syncspec.AuthGCPWorkloadIdentity, "gcp-token", (&syncspec.GCP{Audience: wi.GCP.Audience}).TokenAudience(), syncspec.GCPTokenFile,
		})
	}
	target, source := cloudAuth(t, m)
	for _, tok := range tokens {
		if target != tok.provider && source != tok.provider {
			continue
		}
		if wi := t.Spec.WorkloadIdentity; wi != nil && wi.ServiceAccountName != "" {
			serviceAccount = wi.ServiceAccountName
		}
		volumes = append(volumes, corev1.Volume{Name: tok.volume, VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
			Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
				Audience:          tok.audience,
				ExpirationSeconds: ptr.To[int64](3600),
				Path:              filepath.Base(tok.file),
			}}},
			DefaultMode: ptr.To[int32](0o440),
		}}})
		mounts = append(mounts, readOnly(tok.volume, filepath.Dir(tok.file)))
	}
	var env []corev1.EnvVar
	if p := t.Spec.Proxy; p != nil {
		addCA("proxy-ca", p.CABundleSecretRef, syncspec.ProxyCAFile)
		env = append(env, corev1.EnvVar{Name: "HTTPS_PROXY", Value: p.HTTPSProxy})
		if len(p.NoProxy) > 0 {
			env = append(env, corev1.EnvVar{Name: "NO_PROXY", Value: strings.Join(p.NoProxy, ",")})
		}
		if ref := p.CredentialsSecretRef; ref != nil {
			fromSecret := func(name, key string) corev1.EnvVar {
				return corev1.EnvVar{Name: name, ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: ref.Name}, Key: key,
				}}}
			}
			env = append(env,
				fromSecret(syncspec.ProxyUserEnv, corev1.BasicAuthUsernameKey),
				fromSecret(syncspec.ProxyPasswordEnv, corev1.BasicAuthPasswordKey))
		}
	}

	syncSecurity := &corev1.SecurityContext{
		ReadOnlyRootFilesystem:   new(true),
		AllowPrivilegeEscalation: new(false),
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
	}
	var initContainers []corev1.Container
	if sc != nil {
		var c corev1.Container
		volumes, mounts, c = scannerSidecar(sc, volumes, mounts)
		c.SecurityContext = syncSecurity.DeepCopy()
		initContainers = []corev1.Container{c}
	}

	cj.Spec = batchv1.CronJobSpec{
		Schedule:                   m.Spec.Schedule,
		Suspend:                    new(m.Spec.Suspend),
		ConcurrencyPolicy:          batchv1.ForbidConcurrent,
		StartingDeadlineSeconds:    ptr.To[int64](300),
		SuccessfulJobsHistoryLimit: ptr.To[int32](3),
		FailedJobsHistoryLimit:     ptr.To[int32](3),
		JobTemplate: batchv1.JobTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{Labels: labels, Annotations: annotations},
			Spec: batchv1.JobSpec{
				BackoffLimit:            ptr.To[int32](2),
				ActiveDeadlineSeconds:   ptr.To[int64](3600),
				TTLSecondsAfterFinished: ptr.To[int32](86400),
				// A config error fails again until the config changes.
				PodFailurePolicy: &batchv1.PodFailurePolicy{Rules: []batchv1.PodFailurePolicyRule{{
					Action: batchv1.PodFailurePolicyActionFailJob,
					OnExitCodes: &batchv1.PodFailurePolicyOnExitCodesRequirement{
						ContainerName: new(syncContainer),
						Operator:      batchv1.PodFailurePolicyOnExitCodesOpIn,
						Values:        []int32{syncspec.ExitConfig},
					},
				}}},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: labels, Annotations: podAnnotations},
					Spec: corev1.PodSpec{
						ServiceAccountName:           serviceAccount,
						AutomountServiceAccountToken: new(false),
						EnableServiceLinks:           new(false),
						RestartPolicy:                corev1.RestartPolicyNever,
						SecurityContext: &corev1.PodSecurityContext{
							RunAsNonRoot:   new(true),
							RunAsUser:      ptr.To[int64](65532),
							RunAsGroup:     ptr.To[int64](65532),
							FSGroup:        ptr.To[int64](65532),
							SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
						},
						InitContainers: initContainers,
						Containers: []corev1.Container{{
							Name:            syncContainer,
							Image:           image,
							Args:            []string{"sync", "--spec", syncspec.SpecFile},
							Env:             env,
							SecurityContext: syncSecurity,
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("50m"),
									corev1.ResourceMemory: resource.MustParse("64Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("1"),
									corev1.ResourceMemory: resource.MustParse("512Mi"),
								},
							},
							TerminationMessagePolicy: corev1.TerminationMessageReadFile,
							VolumeMounts:             mounts,
						}},
						Volumes: volumes,
					},
				},
			},
		},
	}
	// The checksum covers everything rendered, so an unchanged checksum
	// means nothing to update.
	rendered, _ := json.Marshal([]any{cj.Labels, cj.Annotations, cj.Spec})
	sum = sha256.Sum256(rendered)
	cj.Annotations[annotationCronJobChecksum] = hex.EncodeToString(sum[:])
}

// scannerSidecar adds the gate volumes to the sync pod and returns the
// scanner container, a native sidecar that runs syncspec.SidecarScript. It
// gets the token and the scanner CA only: no registry Secrets, no proxy,
// the layout read-only. The security context is set by the caller.
func scannerSidecar(sc *sidecar, volumes []corev1.Volume, mounts []corev1.VolumeMount) ([]corev1.Volume, []corev1.VolumeMount, corev1.Container) {
	work, scan := defaultWorkSize, scanVolumeSize
	if sc.gate.Scanner.JavaDB == mirrorv1alpha1.JavaDBPerJob {
		scan = scanVolumeSizePerJob
	}
	if s := sc.scanner; s != nil && s.Storage != nil {
		work = *s.Storage
	}
	workDir := filepath.Dir(syncspec.LayoutDir)
	volumes = append(volumes,
		corev1.Volume{Name: workVolume, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: &work}}},
		corev1.Volume{Name: scanVolume, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: &scan}}})
	mounts = append(mounts,
		corev1.VolumeMount{Name: workVolume, MountPath: workDir},
		corev1.VolumeMount{Name: scanVolume, MountPath: syncspec.ScanDir})
	scannerMounts := []corev1.VolumeMount{
		{Name: workVolume, MountPath: workDir, ReadOnly: true},
		{Name: scanVolume, MountPath: syncspec.ScanDir},
	}
	// sync reads the server's /version itself, so both containers get the CA.
	if s := sc.scanner; s != nil && s.CABundleSecretRef != nil {
		volumes = append(volumes, corev1.Volume{Name: "scanner-ca", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
			SecretName:  s.CABundleSecretRef.Name,
			Items:       []corev1.KeyToPath{{Key: s.CABundleSecretRef.Key, Path: filepath.Base(syncspec.ScannerCAFile)}},
			DefaultMode: ptr.To[int32](0o440),
		}}})
		ca := corev1.VolumeMount{Name: "scanner-ca", MountPath: filepath.Dir(syncspec.ScannerCAFile), ReadOnly: true}
		mounts = append(mounts, ca)
		scannerMounts = append(scannerMounts, ca)
	}
	env := []corev1.EnvVar{
		{Name: syncspec.ScannerURLEnv, Value: sc.gate.Scanner.URL},
		{Name: syncspec.ScannerTimeoutEnv, Value: sc.gate.Scanner.Timeout.Duration.String()},
		{Name: syncspec.ScannerJavaDBEnv, Value: string(sc.gate.Scanner.JavaDB)},
		{Name: syncspec.ScannerTemplateEnv, Value: vuln.ReportTemplate},
		{Name: "HOME", Value: syncspec.ScanDir},
		{Name: "TMPDIR", Value: syncspec.ScanDir},
		{Name: "NO_PROXY", Value: "*"},
	}
	if tok := sc.token; tok != nil {
		// Optional: without the Secret the sidecar still starts, the server
		// refuses its scans and onScanError applies, instead of a pod that
		// never starts its sync container.
		env = append(env, corev1.EnvVar{Name: trivyTokenEnv, ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: tok.Name}, Key: cmp.Or(tok.Key, defaultTokenKey), Optional: new(true),
		}}})
	}
	return volumes, mounts, corev1.Container{
		Name:                     scannerContainer,
		Image:                    sc.gate.Scanner.Image,
		Command:                  []string{"/bin/sh", "-c", syncspec.SidecarScript},
		Env:                      env,
		RestartPolicy:            ptr.To(corev1.ContainerRestartPolicyAlways),
		Resources:                sidecarResources(sc.scanner),
		TerminationMessagePolicy: corev1.TerminationMessageReadFile,
		VolumeMounts:             scannerMounts,
	}
}

// securityDrift reports whether the tagwarden.dev/ labels or security-relevant
// fields of a live sync pod template differ from the desired ones. A hand edit
// keeps the checksum annotation, so the checksum alone would let it persist.
// Labels count because NetworkPolicies select sync pods by them; other labels,
// such as from mutating webhooks, are left alone. Every compared
// field is either set by renderCronJob or left empty and not defaulted by the
// server, so server defaulting causes no drift. DNSPolicy is defaulted and
// left out.
func securityDrift(live, want *corev1.PodTemplateSpec) bool {
	fields := func(t *corev1.PodTemplateSpec) []any {
		p := &t.Spec
		f := make([]any, 0, 19+8*len(p.Containers)+9*len(p.InitContainers))
		own := map[string]string{}
		for k, v := range t.Labels {
			if strings.HasPrefix(k, "tagwarden.dev/") {
				own[k] = v
			}
		}
		f = append(f, own, p.ServiceAccountName, p.AutomountServiceAccountToken, p.SecurityContext,
			p.HostNetwork, p.HostPID, p.HostIPC, p.HostUsers, p.ShareProcessNamespace,
			p.EnableServiceLinks, p.HostAliases, p.DNSConfig, p.NodeName, p.RuntimeClassName,
			p.ImagePullSecrets, p.Volumes, len(p.InitContainers), len(p.Containers))
		for _, c := range p.Containers {
			f = append(f, c.Name, c.Image, c.Command, c.Args, c.Env, c.EnvFrom, c.SecurityContext, c.VolumeMounts)
		}
		for _, c := range p.InitContainers {
			f = append(f, c.Name, c.Image, c.Command, c.Args, c.Env, c.EnvFrom, c.SecurityContext, c.VolumeMounts, c.RestartPolicy)
		}
		return f
	}
	return !equality.Semantic.DeepEqual(fields(live), fields(want))
}
