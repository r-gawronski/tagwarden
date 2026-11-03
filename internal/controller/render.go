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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
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

	// SyncServiceAccount runs the sync pods. It has no RBAC bindings.
	SyncServiceAccount = "tagwarden-sync"
	syncContainer      = "sync"
	specKey            = "spec.json"
	// maxListedTags caps the upstream tag listing of a sync run.
	maxListedTags = tags.MaxTags
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

// objectName names the CronJob and ConfigMap of a mirror.
func objectName(m *mirrorv1alpha1.ArtifactMirror) string {
	return "tagwarden-" + mirrorHash(m.Namespace, m.Name)
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

// targetPath is the repository inside the project: the override, or the
// canonical source with the port separator and IPv6 brackets turned into
// characters a repository path allows.
func targetPath(m *mirrorv1alpha1.ArtifactMirror) string {
	if m.Spec.Target.Repository != "" {
		return m.Spec.Target.Repository
	}
	return strings.NewReplacer("[", "", "]", "", ":", "-").Replace(canonicalSource(m.Spec.Source))
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
	return syncspec.Spec{
		Mirror:            syncspec.Mirror{Namespace: m.Namespace, Name: m.Name},
		Source:            canonicalSource(m.Spec.Source),
		Target:            targetRepo(t, m),
		Tags:              tagPolicy(m.Spec.Tags),
		RequiredPlatforms: m.Spec.RequiredPlatforms,
		OnTagMutation:     mutation,
		MaxTags:           maxListedTags,
		AllowedSources:    allowed,
		DeniedCIDRs:       denied,
	}
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

// renderCronJob sets the CronJob spec. Only fixed paths, the sync image and
// Secret references go into the pod; tenant fields reach the Job only
// through the spec file.
func renderCronJob(cj *batchv1.CronJob, t *mirrorv1alpha1.ClusterMirrorTarget, m *mirrorv1alpha1.ArtifactMirror, image string, spec []byte) {
	labels, annotations := mirrorMeta(m)
	labels[LabelTarget] = targetLabel(t.Name)
	labels[LabelEgress] = EgressDirect
	if t.Spec.Proxy != nil && t.Spec.Proxy.HTTPSProxy != "" {
		labels[LabelEgress] = EgressProxy
	}
	cj.Labels, cj.Annotations = labels, annotations
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
		secretVolume("target-auth", t.Spec.CredentialsSecretRef.Name,
			corev1.KeyToPath{Key: corev1.DockerConfigJsonKey, Path: filepath.Base(syncspec.TargetAuthFile)}),
		{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
	}
	mounts := []corev1.VolumeMount{
		readOnly("spec", filepath.Dir(syncspec.SpecFile)),
		readOnly("target-auth", filepath.Dir(syncspec.TargetAuthFile)),
		{Name: "tmp", MountPath: "/tmp"},
	}
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
						ServiceAccountName:           SyncServiceAccount,
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
						Containers: []corev1.Container{{
							Name:  syncContainer,
							Image: image,
							Args:  []string{"sync", "--spec", syncspec.SpecFile},
							Env:   env,
							SecurityContext: &corev1.SecurityContext{
								ReadOnlyRootFilesystem:   new(true),
								AllowPrivilegeEscalation: new(false),
								Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
							},
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
		f := make([]any, 0, 19+8*len(p.Containers))
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
		return f
	}
	return !equality.Semantic.DeepEqual(fields(live), fields(want))
}
