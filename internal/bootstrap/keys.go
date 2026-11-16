package bootstrap

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// PrepareKeys creates persistent bootstrap keys once and publishes only their
// system public key as Helm values. It does not contact Zitadel. Retries reuse
// stored keys, including after a failure publishing the public ConfigMap.
func PrepareKeys(ctx context.Context, kube client.Client, cfg *Config) error {
	if cfg.KeysSecret == "" || cfg.KeysSecret == cfg.SecretName || cfg.PublicConfigMap == "" || cfg.PublicNamespace == "" {
		return fmt.Errorf("distinct keys Secret and public ConfigMap namespace/name are required")
	}
	if cfg.Namespace == "" || cfg.Username == "" || cfg.SystemUser == "" || cfg.Issuer == "" {
		return fmt.Errorf("bootstrap identity settings are required")
	}
	metadata := func(namespace, name string) metav1.ObjectMeta {
		return metav1.ObjectMeta{
			Name: name, Namespace: namespace,
			Labels: map[string]string{"zitadel.truvity.io/bootstrap": cfg.Username},
			Annotations: map[string]string{
				"zitadel.truvity.io/bootstrap-issuer":      cfg.Issuer,
				"zitadel.truvity.io/bootstrap-system-user": cfg.SystemUser,
			},
		}
	}
	owned := func(obj client.Object) bool {
		return obj.GetLabels()["zitadel.truvity.io/bootstrap"] == cfg.Username &&
			obj.GetAnnotations()["zitadel.truvity.io/bootstrap-issuer"] == cfg.Issuer &&
			obj.GetAnnotations()["zitadel.truvity.io/bootstrap-system-user"] == cfg.SystemUser
	}
	// Check publication ownership before creating any new private material.
	public := &corev1.ConfigMap{}
	publicRef := client.ObjectKey{Namespace: cfg.PublicNamespace, Name: cfg.PublicConfigMap}
	err := kube.Get(ctx, publicRef, public)
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("cannot read bootstrap public ConfigMap")
	}
	publicExists := err == nil
	if publicExists && !owned(public) {
		return fmt.Errorf("public ConfigMap exists and is not owned by this bootstrap identity")
	}
	keys := &corev1.Secret{}
	ref := client.ObjectKey{Namespace: cfg.Namespace, Name: cfg.KeysSecret}
	if err := kube.Get(ctx, ref, keys); apierrors.IsNotFound(err) {
		keys.ObjectMeta = metadata(ref.Namespace, ref.Name)
		keys.Data = make(map[string][]byte, 2)
		for _, name := range []string{"system.pem", "machine.pem"} {
			key, err := rsa.GenerateKey(rand.Reader, 3072)
			if err != nil {
				return fmt.Errorf("cannot generate bootstrap RSA key")
			}
			keys.Data[name] = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
		}
		immutable := true
		keys.Immutable = &immutable
		// No ownerReference: hook cleanup/uninstall must not delete the keys.
		if err := kube.Create(ctx, keys); apierrors.IsAlreadyExists(err) {
			// Another bootstrap won. Always use its persisted keys.
			if err := kube.Get(ctx, ref, keys); err != nil {
				return fmt.Errorf("cannot read persisted bootstrap keys")
			}
		} else if err != nil {
			return fmt.Errorf("cannot persist bootstrap keys")
		}
	} else if err != nil {
		return fmt.Errorf("cannot read bootstrap keys")
	}
	if !owned(keys) {
		return fmt.Errorf("keys Secret exists and is not owned by this bootstrap identity")
	}
	system, err := privateKey(keys.Data["system.pem"])
	if err != nil {
		return fmt.Errorf("stored bootstrap system key is invalid")
	}
	if _, err := privateKey(keys.Data["machine.pem"]); err != nil {
		return fmt.Errorf("stored bootstrap machine key is invalid")
	}
	der, err := x509.MarshalPKIXPublicKey(&system.PublicKey)
	if err != nil {
		return fmt.Errorf("cannot encode bootstrap public key")
	}
	// JSON is valid YAML and avoids hand-escaping configurable identity names.
	values, err := json.Marshal(map[string]any{
		"zitadel": map[string]any{"configmapConfig": map[string]any{
			"SystemAPIUsers": map[string]any{cfg.SystemUser: map[string]any{
				"KeyData":     base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
				"Memberships": []any{map[string]any{"MemberType": "System", "Roles": []string{"IAM_OWNER", "ORG_OWNER"}}},
			}},
		}},
	})
	if err != nil {
		return fmt.Errorf("cannot encode bootstrap public configuration")
	}
	if !publicExists {
		public.ObjectMeta = metadata(publicRef.Namespace, publicRef.Name)
		public.Data = map[string]string{"values.yaml": string(values)}
		public.Labels["reconcile.fluxcd.io/watch"] = "Enabled"
		if err := kube.Create(ctx, public); err != nil {
			return fmt.Errorf("cannot publish bootstrap public ConfigMap; retry")
		}
	} else if public.Data["values.yaml"] != string(values) || public.Labels["reconcile.fluxcd.io/watch"] != "Enabled" {
		if public.Data == nil {
			public.Data = map[string]string{}
		}
		public.Data["values.yaml"] = string(values)
		public.Labels["reconcile.fluxcd.io/watch"] = "Enabled"
		if err := kube.Update(ctx, public); err != nil {
			return fmt.Errorf("cannot update bootstrap public ConfigMap; retry")
		}
	}
	cfg.SystemKey, cfg.MachineKey = keys.Data["system.pem"], keys.Data["machine.pem"]
	return nil
}
