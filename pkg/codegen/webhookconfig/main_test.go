package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/admissionregistration/v1"
	"sigs.k8s.io/yaml"
)

const chartDir = "../../../charts/rancher-webhook"

func TestCABundleTemplateIsConditional(t *testing.T) {
	in := "  clientConfig:\n    caBundle: Y29kZWdlbg==\n    service:\n      name: x\n"
	want := "  clientConfig:\n    {{- with .Values.caBundle }}\n    caBundle: {{ . }}\n    {{- end }}\n    service:\n      name: x\n"
	assert.Equal(t, want, caBundleLine.ReplaceAllString(in, caBundleTemplate))
}

// A bare `caBundle:` line in the template makes Helm server-side apply claim
// ownership of the field and blank the CA injected at runtime by needacert.
func TestGeneratedTemplateNeverRendersBareCABundle(t *testing.T) {
	b, err := os.ReadFile(chartDir + "/templates/webhook.yaml")
	require.NoError(t, err)

	lines := strings.Split(string(b), "\n")
	found := 0
	for i, l := range lines {
		if !strings.Contains(l, "caBundle:") {
			continue
		}
		found++
		require.Greater(t, i, 0)
		assert.Contains(t, lines[i-1], "{{- with .Values.caBundle }}", "line %d: caBundle must be conditional", i+1)
		assert.Contains(t, lines[i+1], "{{- end }}", "line %d: missing end", i+1)
	}
	assert.Equal(t, strings.Count(string(b), "clientConfig:"), found, "every clientConfig needs a conditional caBundle")
}

func renderChart(t *testing.T, args ...string) []v1.WebhookClientConfig {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not found in PATH")
	}
	out, err := exec.Command("helm", append([]string{"template", "rancher-webhook", chartDir, "-n", "cattle-system"}, args...)...).CombinedOutput()
	require.NoError(t, err, string(out))

	var configs []v1.WebhookClientConfig
	for _, doc := range strings.Split(string(out), "\n---") {
		if !strings.Contains(doc, "WebhookConfiguration") {
			continue
		}
		var cfg struct {
			Kind     string `json:"kind"`
			Webhooks []struct {
				ClientConfig v1.WebhookClientConfig `json:"clientConfig"`
			} `json:"webhooks"`
		}
		require.NoError(t, yaml.Unmarshal([]byte(doc), &cfg), doc)
		if cfg.Kind != "ValidatingWebhookConfiguration" && cfg.Kind != "MutatingWebhookConfiguration" {
			continue
		}
		for _, w := range cfg.Webhooks {
			configs = append(configs, w.ClientConfig)
		}
	}
	require.NotEmpty(t, configs)
	return configs
}

func TestChartOmitsCABundleByDefault(t *testing.T) {
	for _, c := range renderChart(t) {
		assert.Empty(t, c.CABundle)
	}
	// The raw output must not contain the field at all, not even as "".
	out, err := exec.Command("helm", "template", "rancher-webhook", chartDir, "-n", "cattle-system").CombinedOutput()
	require.NoError(t, err)
	assert.NotContains(t, string(out), "caBundle")
}

func TestChartRendersCABundleWhenSet(t *testing.T) {
	for _, c := range renderChart(t, "--set", "caBundle=Zm9v") {
		assert.Equal(t, []byte("foo"), c.CABundle)
	}
}
