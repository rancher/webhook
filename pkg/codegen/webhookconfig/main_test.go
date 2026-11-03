package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"text/template"

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

// renderWebhookTemplate renders templates/webhook.yaml with Go's text/template.
// The file only uses if/with/end, so no Helm engine is needed.
func renderWebhookTemplate(t *testing.T, caBundle string, mcmEnabled bool) (string, []v1.WebhookClientConfig) {
	t.Helper()
	b, err := os.ReadFile(chartDir + "/templates/webhook.yaml")
	require.NoError(t, err)
	tpl, err := template.New("webhook.yaml").Option("missingkey=error").Parse(string(b))
	require.NoError(t, err)

	var buf bytes.Buffer
	values := map[string]any{
		"caBundle": caBundle,
		"mcm":      map[string]any{"enabled": mcmEnabled},
	}
	require.NoError(t, tpl.Execute(&buf, map[string]any{"Values": values}))

	var configs []v1.WebhookClientConfig
	for _, doc := range strings.Split(buf.String(), "\n---") {
		var cfg struct {
			Kind     string `json:"kind"`
			Webhooks []struct {
				ClientConfig v1.WebhookClientConfig `json:"clientConfig"`
			} `json:"webhooks"`
		}
		require.NoError(t, yaml.Unmarshal([]byte(doc), &cfg), doc)
		for _, w := range cfg.Webhooks {
			configs = append(configs, w.ClientConfig)
		}
	}
	require.NotEmpty(t, configs)
	return buf.String(), configs
}

func TestTemplateOmitsCABundleByDefault(t *testing.T) {
	for _, mcm := range []bool{true, false} {
		out, configs := renderWebhookTemplate(t, "", mcm)
		assert.NotContains(t, out, "caBundle", "mcm=%v: the field must not be rendered at all, not even as empty", mcm)
		for _, c := range configs {
			assert.Empty(t, c.CABundle)
		}
	}
}

func TestTemplateRendersCABundleWhenSet(t *testing.T) {
	for _, mcm := range []bool{true, false} {
		_, configs := renderWebhookTemplate(t, "Zm9v", mcm)
		for _, c := range configs {
			assert.Equal(t, []byte("foo"), c.CABundle)
		}
	}
}
