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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
	// +kubebuilder:scaffold:imports
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

const (
	// operatorNamespace holds the Secrets, CronJobs and Jobs in the tests.
	operatorNamespace = "tagwarden-system"
	syncImage         = "registry.example.internal/tagwarden:test"
	deniedCIDR        = "10.96.0.0/12"
)

// writes counts the manager's update and patch calls on CronJobs and
// ConfigMaps.
var writes atomic.Int64

func countingClient(cfg *rest.Config, opts client.Options) (client.Client, error) {
	c, err := client.NewWithWatch(cfg, opts)
	if err != nil {
		return nil, err
	}
	count := func(obj client.Object) {
		switch obj.(type) {
		case *batchv1.CronJob, *corev1.ConfigMap:
			writes.Add(1)
		}
	}
	return interceptor.NewClient(c, interceptor.Funcs{
		Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			count(obj)
			return c.Update(ctx, obj, opts...)
		},
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, p client.Patch, opts ...client.PatchOption) error {
			count(obj)
			return c.Patch(ctx, obj, p, opts...)
		},
	}), nil
}

// recorder keeps the Events of the mirror controller.
var recorder = &testRecorder{}

type testRecorder struct {
	mu     sync.Mutex
	events []string
}

// Eventf records "namespace/name type reason note".
func (t *testRecorder) Eventf(regarding, _ runtime.Object, eventtype, reason, _, note string, args ...any) {
	o := regarding.(client.Object)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.events = append(t.events, fmt.Sprintf("%s/%s %s %s %s", o.GetNamespace(), o.GetName(), eventtype, reason, fmt.Sprintf(note, args...)))
}

// Events returns the recorded Events for a mirror.
func (t *testRecorder) Events(namespace, name string) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []string
	for _, e := range t.events {
		if strings.HasPrefix(e, namespace+"/"+name+" ") {
			out = append(out, e)
		}
	}
	return out
}

var (
	ctx       context.Context
	cancel    context.CancelFunc
	testEnv   *envtest.Environment
	cfg       *rest.Config
	k8sClient client.Client
)

func TestControllers(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t, "Controller Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	ctx, cancel = context.WithCancel(context.TODO())
	SetDefaultEventuallyTimeout(10 * time.Second)

	var err error
	err = mirrorv1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	// +kubebuilder:scaffold:scheme

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}

	// Retrieve the first found binary directory to allow running tests from IDEs
	if getFirstFoundEnvTestBinaryDir() != "" {
		testEnv.BinaryAssetsDirectory = getFirstFoundEnvTestBinaryDir()
	}

	// cfg is defined in this file globally.
	cfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	Expect(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: operatorNamespace}})).To(Succeed())

	By("starting the manager")
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		NewClient: countingClient,
		Scheme:    scheme.Scheme,
		Metrics:   metricsserver.Options{BindAddress: "0"},
		Cache:     CacheOptions(operatorNamespace),
	})
	Expect(err).NotTo(HaveOccurred())
	Expect((&ClusterMirrorTargetReconciler{
		Recorder:  recorder,
		Client:    mgr.GetClient(),
		Scheme:    mgr.GetScheme(),
		Namespace: operatorNamespace,
	}).SetupWithManager(mgr)).To(Succeed())
	Expect((&ArtifactMirrorReconciler{
		Client:      mgr.GetClient(),
		APIReader:   mgr.GetAPIReader(),
		Scheme:      mgr.GetScheme(),
		Recorder:    recorder,
		Namespace:   operatorNamespace,
		SyncImage:   syncImage,
		DeniedCIDRs: []string{deniedCIDR},
	}).SetupWithManager(mgr)).To(Succeed())
	go func() {
		defer GinkgoRecover()
		Expect(mgr.Start(ctx)).To(Succeed())
	}()
	createMirrorFixtures()
})

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	cancel()
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})

// getFirstFoundEnvTestBinaryDir locates the first binary in the specified path.
// ENVTEST-based tests depend on specific binaries, usually located in paths set by
// controller-runtime. When running tests directly (e.g., via an IDE) without using
// Makefile targets, the 'BinaryAssetsDirectory' must be explicitly configured.
//
// This function streamlines the process by finding the required binaries, similar to
// setting the 'KUBEBUILDER_ASSETS' environment variable. To ensure the binaries are
// properly set up, run 'make setup-envtest' beforehand.
func getFirstFoundEnvTestBinaryDir() string {
	basePath := filepath.Join("..", "..", "bin", "k8s")
	entries, err := os.ReadDir(basePath)
	if err != nil {
		logf.Log.Error(err, "Failed to read directory", "path", basePath)
		return ""
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return filepath.Join(basePath, entry.Name())
		}
	}
	return ""
}
