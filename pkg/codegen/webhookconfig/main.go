// Command webhookconfig generates charts/rancher-webhook/templates/webhook.yaml
// from the ValidatingWebhook/MutatingWebhook definitions registered in
// pkg/server, so the chart's admission webhook config never drifts from the
// handlers actually wired up in the binary.
//
// It builds the handler list twice - once with MCM enabled, once without -
// and diffs the two by webhook name to decide which entries are unconditional
// vs gated behind {{ .Values.mcm.enabled }}. It never talks to a real
// cluster: Validation()/Mutation() only wire up caches, they don't list/watch,
// so clients.Options.StartCache=false is enough to build them against a
// throwaway rest.Config.
package main

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/clients"
	"github.com/rancher/webhook/pkg/server"
	v1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/yaml"
)

const (
	webhookNamespace   = "cattle-system"
	webhookServiceName = "rancher-webhook"
	webhookClientPort  = int32(443)
	validationPath     = "/v1/webhook/validation"
	mutationPath       = "/v1/webhook/mutation"

	outputPath = "charts/rancher-webhook/templates/webhook.yaml"

	// caBundlePlaceholder is swapped for the Helm template expression after
	// marshaling, since CABundle is a []byte field and would otherwise be
	// rendered as an opaque base64 blob.
	caBundlePlaceholder  = "codegen-cabundle-placeholder"
	caBundleTemplateExpr = `{{ .Values.caBundle | default "" }}`

	mcmEnabledIf  = "{{- if .Values.mcm.enabled }}\n"
	mcmDisabledIf = "{{- if not .Values.mcm.enabled }}\n"
	templateEnd   = "{{- end }}\n"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "generate webhook chart manifests:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()
	// Never dialed: Validation()/Mutation() only register cache indexers.
	cfg := &rest.Config{Host: "https://127.0.0.1:6443"}

	enabledValidators, enabledMutators, err := handlers(ctx, cfg, true)
	if err != nil {
		return fmt.Errorf("building mcm-enabled handlers: %w", err)
	}
	disabledValidators, disabledMutators, err := handlers(ctx, cfg, false)
	if err != nil {
		return fmt.Errorf("building mcm-disabled handlers: %w", err)
	}

	validatingClientConfig := v1.WebhookClientConfig{
		Service: &v1.ServiceReference{
			Namespace: webhookNamespace,
			Name:      webhookServiceName,
			Path:      admission.Ptr(validationPath),
			Port:      admission.Ptr(webhookClientPort),
		},
		CABundle: []byte(caBundlePlaceholder),
	}
	mutatingClientConfig := v1.WebhookClientConfig{
		Service: &v1.ServiceReference{
			Namespace: webhookNamespace,
			Name:      webhookServiceName,
			Path:      admission.Ptr(mutationPath),
			Port:      admission.Ptr(webhookClientPort),
		},
		CABundle: []byte(caBundlePlaceholder),
	}

	enabledValidating, err := entriesFor(enabledValidators, validatingClientConfig, validatingWebhookEntry)
	if err != nil {
		return err
	}
	disabledValidating, err := entriesFor(disabledValidators, validatingClientConfig, validatingWebhookEntry)
	if err != nil {
		return err
	}
	enabledMutating, err := entriesFor(enabledMutators, mutatingClientConfig, mutatingWebhookEntry)
	if err != nil {
		return err
	}
	disabledMutating, err := entriesFor(disabledMutators, mutatingClientConfig, mutatingWebhookEntry)
	if err != nil {
		return err
	}

	var doc strings.Builder
	doc.WriteString("apiVersion: admissionregistration.k8s.io/v1\n")
	doc.WriteString("kind: ValidatingWebhookConfiguration\n")
	doc.WriteString("metadata:\n  name: rancher.cattle.io\n")
	doc.WriteString("webhooks:\n")
	doc.WriteString(mergeEntries(enabledValidating, disabledValidating))
	doc.WriteString("---\n")
	doc.WriteString("apiVersion: admissionregistration.k8s.io/v1\n")
	doc.WriteString("kind: MutatingWebhookConfiguration\n")
	doc.WriteString("metadata:\n  name: rancher.cattle.io\n")
	doc.WriteString("webhooks:\n")
	doc.WriteString(mergeEntries(enabledMutating, disabledMutating))

	out := caBundleLine.ReplaceAllString(doc.String(), "${1} "+caBundleTemplateExpr)
	return os.WriteFile(outputPath, []byte(out), 0o644)
}

// caBundleLine matches the base64-encoded caBundlePlaceholder that
// sigs.k8s.io/yaml renders for the CABundle []byte field, so it can be
// swapped for the Helm template expression regardless of exact base64 or
// quoting form.
var caBundleLine = regexp.MustCompile(`(?m)^(\s*caBundle:).*$`)

func handlers(ctx context.Context, cfg *rest.Config, mcmEnabled bool) ([]admission.ValidatingAdmissionHandler, []admission.MutatingAdmissionHandler, error) {
	c, err := clients.NewWithOptions(ctx, cfg, &clients.Options{
		MCMEnabled: mcmEnabled,
		StartCache: false,
	})
	if err != nil {
		return nil, nil, err
	}
	validators, err := server.Validation(c)
	if err != nil {
		return nil, nil, err
	}
	mutators, err := server.Mutation(c)
	if err != nil {
		return nil, nil, err
	}
	return validators, mutators, nil
}

// namedEntry is a single rendered ("- name: ...") YAML list entry, kept
// alongside the webhook name it was rendered from so entries can be diffed
// and re-grouped without re-parsing the YAML.
type namedEntry struct {
	name string
	yaml string
}

func validatingWebhookEntry(clientConfig v1.WebhookClientConfig, h admission.ValidatingAdmissionHandler) ([]namedEntry, error) {
	var out []namedEntry
	for _, wh := range h.ValidatingWebhook(clientConfig) {
		b, err := yaml.Marshal([]v1.ValidatingWebhook{wh})
		if err != nil {
			return nil, err
		}
		out = append(out, namedEntry{name: wh.Name, yaml: string(b)})
	}
	return out, nil
}

func mutatingWebhookEntry(clientConfig v1.WebhookClientConfig, h admission.MutatingAdmissionHandler) ([]namedEntry, error) {
	var out []namedEntry
	for _, wh := range h.MutatingWebhook(clientConfig) {
		b, err := yaml.Marshal([]v1.MutatingWebhook{wh})
		if err != nil {
			return nil, err
		}
		out = append(out, namedEntry{name: wh.Name, yaml: string(b)})
	}
	return out, nil
}

func entriesFor[H any](handlers []H, clientConfig v1.WebhookClientConfig, render func(v1.WebhookClientConfig, H) ([]namedEntry, error)) ([]namedEntry, error) {
	var out []namedEntry
	for _, h := range handlers {
		entries, err := render(clientConfig, h)
		if err != nil {
			return nil, err
		}
		out = append(out, entries...)
	}
	return out, nil
}

// mergeEntries walks enabled in order, grouping consecutive runs of entries
// that are also present in disabled (unconditional) vs not (gated behind
// {{ .Values.mcm.enabled }}), then appends any disabled-only entries gated
// behind {{ if not .Values.mcm.enabled }}.
func mergeEntries(enabled, disabled []namedEntry) string {
	disabledNames := make(map[string]bool, len(disabled))
	for _, e := range disabled {
		disabledNames[e.name] = true
	}
	enabledNames := make(map[string]bool, len(enabled))
	for _, e := range enabled {
		enabledNames[e.name] = true
	}

	var out strings.Builder
	i := 0
	for i < len(enabled) {
		mcmOnly := !disabledNames[enabled[i].name]
		j := i
		for j < len(enabled) && !disabledNames[enabled[j].name] == mcmOnly {
			j++
		}
		if mcmOnly {
			out.WriteString(mcmEnabledIf)
		}
		for _, e := range enabled[i:j] {
			out.WriteString(e.yaml)
		}
		if mcmOnly {
			out.WriteString(templateEnd)
		}
		i = j
	}

	var disabledOnly []namedEntry
	for _, e := range disabled {
		if !enabledNames[e.name] {
			disabledOnly = append(disabledOnly, e)
		}
	}
	if len(disabledOnly) > 0 {
		out.WriteString(mcmDisabledIf)
		for _, e := range disabledOnly {
			out.WriteString(e.yaml)
		}
		out.WriteString(templateEnd)
	}
	return out.String()
}
