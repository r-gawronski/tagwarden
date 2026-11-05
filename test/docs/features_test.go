package docs

import (
	"bytes"
	"context"
	"io"
	"os"
	"regexp"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// TestFeatureExamples applies every object in docs/features.md with a
// server-side dry run, so CRD schema and CEL changes cannot leave a broken
// example behind.
func TestFeatureExamples(t *testing.T) {
	env := &envtest.Environment{CRDDirectoryPaths: []string{"../../config/crd/bases"}, ErrorIfCRDPathMissing: true}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = env.Stop() }()
	c, err := client.New(cfg, client.Options{Scheme: scheme.Scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, ns := range []string{"team-web", "team-net", "team-obs"} {
		if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
			t.Fatal(err)
		}
	}
	md, err := os.ReadFile("../../docs/features.md")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, m := range regexp.MustCompile("(?s)```yaml\n(.*?)```").FindAllSubmatch(md, -1) {
		d := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(m[1]), 4096)
		for {
			var u unstructured.Unstructured
			if err := d.Decode(&u.Object); err == io.EOF {
				break
			} else if err != nil {
				t.Fatal(err)
			}
			if u.GetKind() == "" {
				continue // chart values
			}
			n++
			if err := c.Create(ctx, &u, client.DryRunAll); err != nil {
				t.Errorf("%s %s: %v", u.GetKind(), u.GetName(), err)
			}
		}
	}
	t.Logf("checked %d objects", n)
}
