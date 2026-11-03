//go:build e2e

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

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/r-gawronski/tagwarden/test/utils"
)

var (
	// managerImage is the manager image to be built and loaded for testing.
	managerImage = "example.com/tagwarden:v0.0.1"
	// helmRelease is the release name of the operator chart.
	helmRelease = "tagwarden"
)

// TestE2E runs the e2e test suite to validate the solution in an isolated environment.
// The default setup requires Kind and Helm.
//
// To enable kubectl kuberc (use custom kubectl configurations), set: KUBECTL_KUBERC=true
// By default, kuberc is disabled to ensure consistent test behavior across different environments.
func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	_, _ = fmt.Fprintf(GinkgoWriter, "Starting tagwarden e2e test suite\n")
	RunSpecs(t, "e2e suite")
}

var _ = BeforeSuite(func() {
	// CI builds the image with a layer cache before the suite starts.
	if os.Getenv("E2E_SKIP_IMAGE_BUILD") != "1" {
		By("building the manager image")
		cmd := exec.Command("make", "docker-build", fmt.Sprintf("IMG=%s", managerImage))
		_, err := utils.Run(cmd)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to build the manager image")
	}

	// TODO(user): If you want to change the e2e test vendor from Kind,
	// ensure the image is built and available, then remove the following block.
	By("loading the manager image on Kind")
	err := utils.LoadImageToKindClusterWithName(managerImage)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to load the manager image into Kind")

	configureKubectlKubeRC()
	installOperator()
})

// deniedCIDRs are the kind pod and service CIDRs.
var deniedCIDRs = []string{"10.244.0.0/16", "10.96.0.0/16"}

// installOperator installs the chart in dist/chart with the image loaded
// into kind, in a namespace that enforces the restricted Pod Security level.
func installOperator() {
	By("creating the operator namespace with the restricted security policy")
	kubectlApply([]byte(fmt.Sprintf(`{"apiVersion":"v1","kind":"Namespace","metadata":{"name":%q,`+
		`"labels":{"pod-security.kubernetes.io/enforce":"restricted"}}}`, namespace)))

	By("installing the operator with the Helm chart")
	repo, tag, _ := strings.Cut(managerImage, ":")
	cidrs, err := json.Marshal(deniedCIDRs)
	Expect(err).NotTo(HaveOccurred())
	_, err = utils.Run(exec.Command("helm", "upgrade", "--install", helmRelease, "dist/chart",
		"--namespace", namespace,
		"--set", "manager.image.repository="+repo,
		"--set", "manager.image.tag="+tag,
		"--set-json", "deniedCIDRs="+string(cidrs),
		"--wait", "--timeout", "5m"))
	Expect(err).NotTo(HaveOccurred(), "Failed to install the chart")
}

// Disable kubectl kuberc by default for test isolation.
// This prevents local kubectl configurations from affecting test behavior.
// To enable kuberc, set: KUBECTL_KUBERC=true
func configureKubectlKubeRC() {
	if os.Getenv("KUBECTL_KUBERC") != "true" {
		By("disabling kubectl kuberc for test isolation")
		err := os.Setenv("KUBECTL_KUBERC", "false")
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to disable kubectl kuberc")
		_, _ = fmt.Fprintf(GinkgoWriter,
			"kubectl kuberc disabled for consistent test behavior (override with KUBECTL_KUBERC=true)\n")
	} else {
		_, _ = fmt.Fprintf(GinkgoWriter, "kubectl kuberc enabled (KUBECTL_KUBERC=true)\n")
	}
}
