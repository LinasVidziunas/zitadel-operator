// Command schemas exports the committed CRD schemas for YAML language servers.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sigs.k8s.io/yaml"
)

func main() {
	if err := generate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generate() error {
	paths, err := filepath.Glob("charts/zitadel-operator-crds/templates/*.yaml")
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return fmt.Errorf("run from the repository root; no CRDs found")
	}
	if err := os.MkdirAll("schemas", 0755); err != nil {
		return err
	}
	var refs []any
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var crd struct {
			Spec struct {
				Group string `json:"group"`
				Names struct {
					Kind string `json:"kind"`
				} `json:"names"`
				Versions []struct {
					Name   string `json:"name"`
					Served bool   `json:"served"`
					Schema struct {
						OpenAPI map[string]any `json:"openAPIV3Schema"`
					} `json:"schema"`
				} `json:"versions"`
			} `json:"spec"`
		}
		if err := yaml.Unmarshal(raw, &crd); err != nil {
			return err
		}
		for _, version := range crd.Spec.Versions {
			if !version.Served {
				continue
			}
			schema := version.Schema.OpenAPI
			if schema == nil {
				return fmt.Errorf("%s has no schema", path)
			}
			adapt(schema)
			schema["$schema"] = "http://json-schema.org/draft-07/schema#"
			schema["title"] = crd.Spec.Names.Kind
			props, ok := schema["properties"].(map[string]any)
			if !ok {
				return fmt.Errorf("%s has no properties", path)
			}
			props["apiVersion"] = map[string]any{"type": "string", "enum": []string{crd.Spec.Group + "/" + version.Name}}
			props["kind"] = map[string]any{"type": "string", "enum": []string{crd.Spec.Names.Kind}}
			props["metadata"] = map[string]any{"type": "object", "properties": map[string]any{
				"name": map[string]any{"type": "string"}, "namespace": map[string]any{"type": "string"},
				"labels":      map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}},
				"annotations": map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}},
			}}
			required, _ := schema["required"].([]any)
			schema["required"] = append(required, "apiVersion", "kind", "metadata")
			filename := strings.ToLower(crd.Spec.Names.Kind) + "-" + version.Name + ".json"
			if err := write(filename, schema); err != nil {
				return err
			}
			refs = append(refs, map[string]any{"$ref": filename})
		}
	}
	return write("all.json", map[string]any{"$schema": "http://json-schema.org/draft-07/schema#", "oneOf": refs})
}

// Structural CRDs prune unknown fields; editors should report those typos.
// Open-ended maps and preserve-unknown-fields objects remain open. Kubernetes
// extensions (including CEL) stay in the schema but are enforced by the API server.
func adapt(schema map[string]any) {
	if props, ok := schema["properties"].(map[string]any); ok {
		if schema["x-kubernetes-preserve-unknown-fields"] != true {
			if _, exists := schema["additionalProperties"]; !exists {
				schema["additionalProperties"] = false
			}
		}
		for _, value := range props {
			if child, ok := value.(map[string]any); ok {
				adapt(child)
			}
		}
	}
	for _, key := range []string{"items", "additionalProperties"} {
		if child, ok := schema[key].(map[string]any); ok {
			adapt(child)
		}
	}
	if schema["nullable"] == true {
		if kind, ok := schema["type"].(string); ok {
			schema["type"] = []string{kind, "null"}
		}
		delete(schema, "nullable")
	}
	if schema["x-kubernetes-int-or-string"] == true {
		delete(schema, "type")
		schema["anyOf"] = []any{map[string]any{"type": "integer"}, map[string]any{"type": "string"}}
	}
}

func write(name string, schema map[string]any) error {
	raw, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join("schemas", name), append(raw, '\n'), 0644)
}
