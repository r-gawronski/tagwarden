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
	"errors"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/syncspec"
)

// Reasons of pod Events that have no mirror condition behind them.
const (
	reasonDigestOnly   = "DigestOnlyNotSupported"
	reasonInvalidImage = "InvalidImage"
)

var errDigestOnly = errors.New("image is pinned by digest only, which auto-mirror does not support yet")

// imageSource is the upstream repository and tag of a container image.
type imageSource struct {
	Registry, Repository, Tag string
}

var errImplicitLatest = errors.New("image has no tag, so it would mean latest, which auto-mirror does not support; use an explicit tag")

func (s imageSource) key() string { return s.Registry + "/" + s.Repository }

// parseImage reads repo:tag and repo:tag@digest. A ref that points at the
// target registry under project is mapped back to the upstream source:
// <registry>/<project>/<source-registry-segment>/<repo>:<tag>. The digest of
// repo:tag@digest is dropped; the tag is mirrored by the digest it resolves
// to at sync time.
func parseImage(ref string, t *mirrorv1alpha1.ClusterMirrorTarget) (imageSource, error) {
	base, _, hasDigest := strings.Cut(ref, "@")
	last := base[strings.LastIndex(base, "/")+1:]
	if hasDigest && !strings.Contains(last, ":") {
		return imageSource{}, errDigestOnly
	}
	if !hasDigest && !strings.Contains(last, ":") {
		return imageSource{}, errImplicitLatest
	}
	tag, err := name.NewTag(base, name.WeakValidation)
	if err != nil {
		return imageSource{}, err
	}
	s := imageSource{
		Registry:   syncspec.CanonicalRegistry(tag.RegistryStr()),
		Repository: tag.RepositoryStr(),
		Tag:        tag.TagStr(),
	}
	if s.Registry != syncspec.CanonicalRegistry(string(t.Spec.Registry)) {
		return s, nil
	}
	rest, ok := strings.CutPrefix(s.Repository, string(t.Spec.AutoMirror.Project)+"/")
	if !ok {
		return s, nil
	}
	seg, repo, ok := strings.Cut(rest, "/")
	if !ok {
		return imageSource{}, errors.New("image points at the target registry but not at a mirrored repository")
	}
	for _, a := range t.Spec.AllowedSources {
		if registrySegment(a) == seg {
			return imageSource{Registry: syncspec.CanonicalRegistry(string(a)), Repository: repo, Tag: s.Tag}, nil
		}
	}
	return imageSource{}, errors.New("image points at the target registry, but its source registry is not in allowedSources")
}
