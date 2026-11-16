package bootstrap

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func keyConfig() Config {
	return Config{
		Issuer: "https://auth.example.test", SystemUser: "gitops-bootstrap", Username: "operator",
		Namespace: "operator", SecretName: "credential", GenerateKeys: true,
		KeysSecret: "bootstrap-keys", PublicNamespace: "zitadel", PublicConfigMap: "bootstrap-public",
	}
}

func keyClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}

type publicationFailure struct {
	client.Client
}

func (c publicationFailure) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if _, ok := obj.(*corev1.ConfigMap); ok {
		return errors.New("publication unavailable")
	}
	return c.Client.Create(ctx, obj, opts...)
}

func TestGeneratedKeysSurvivePublicationRetry(t *testing.T) {
	ctx := context.Background()
	cfg := keyConfig()
	kube := keyClient(t)
	require.Error(t, PrepareKeys(ctx, publicationFailure{kube}, &cfg))
	var original corev1.Secret
	require.NoError(t, kube.Get(ctx, client.ObjectKey{Namespace: cfg.Namespace, Name: cfg.KeysSecret}, &original))
	require.Len(t, original.Data, 2)
	require.Empty(t, original.OwnerReferences, "hook cleanup must not erase credentials")

	require.NoError(t, PrepareKeys(ctx, kube, &cfg))
	require.True(t, bytes.Equal(original.Data["system.pem"], cfg.SystemKey), "retry must preserve system key")
	require.True(t, bytes.Equal(original.Data["machine.pem"], cfg.MachineKey), "retry must preserve machine key")
	require.False(t, bytes.Equal(cfg.SystemKey, cfg.MachineKey), "identities need separate keys")
	var public corev1.ConfigMap
	ref := client.ObjectKey{Namespace: cfg.PublicNamespace, Name: cfg.PublicConfigMap}
	require.NoError(t, kube.Get(ctx, ref, &public))
	require.Equal(t, "Enabled", public.Labels["reconcile.fluxcd.io/watch"])
	require.Empty(t, public.OwnerReferences)
	require.NotContains(t, public.Data["values.yaml"], "PRIVATE KEY")
	var values struct {
		Zitadel struct {
			Config struct {
				Users map[string]struct {
					KeyData     string
					Memberships []struct {
						MemberType string
						Roles      []string
					}
				} `json:"SystemAPIUsers"`
			} `json:"configmapConfig"`
		} `json:"zitadel"`
	}
	require.NoError(t, json.Unmarshal([]byte(public.Data["values.yaml"]), &values))
	user := values.Zitadel.Config.Users[cfg.SystemUser]
	require.Len(t, user.Memberships, 1)
	require.Equal(t, "System", user.Memberships[0].MemberType)
	require.ElementsMatch(t, []string{"IAM_OWNER", "ORG_OWNER"}, user.Memberships[0].Roles)
	key, err := privateKey(cfg.SystemKey)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	require.Equal(t, base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), user.KeyData)

	version := public.ResourceVersion
	fresh := keyConfig()
	require.NoError(t, PrepareKeys(ctx, kube, &fresh))
	require.True(t, bytes.Equal(cfg.SystemKey, fresh.SystemKey))
	require.True(t, bytes.Equal(cfg.MachineKey, fresh.MachineKey))
	require.NoError(t, kube.Get(ctx, ref, &public))
	require.Equal(t, version, public.ResourceVersion, "unchanged public trust must not trigger another rollout")
}

func TestBootstrapPreservesConflictingOrInvalidInputs(t *testing.T) {
	cfg := keyConfig()
	for _, tc := range []struct {
		name    string
		object  client.Object
		message string
	}{
		{"foreign public configuration", &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: cfg.PublicConfigMap, Namespace: cfg.PublicNamespace}}, "public ConfigMap exists"},
		{"foreign keys", &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: cfg.KeysSecret, Namespace: cfg.Namespace}}, "keys Secret exists"},
		{"invalid owned keys", &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Name: cfg.KeysSecret, Namespace: cfg.Namespace,
			Labels:      map[string]string{"zitadel.truvity.io/bootstrap": cfg.Username},
			Annotations: map[string]string{"zitadel.truvity.io/bootstrap-issuer": cfg.Issuer, "zitadel.truvity.io/bootstrap-system-user": cfg.SystemUser},
		}, Data: map[string][]byte{"system.pem": []byte("invalid")}}, "stored bootstrap system key is invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kube := keyClient(t, tc.object)
			var before corev1.Secret
			_ = kube.Get(context.Background(), client.ObjectKey{Namespace: cfg.Namespace, Name: cfg.KeysSecret}, &before)
			require.ErrorContains(t, PrepareKeys(context.Background(), kube, &cfg), tc.message)
			if _, ok := tc.object.(*corev1.Secret); ok {
				var after corev1.Secret
				require.NoError(t, kube.Get(context.Background(), client.ObjectKeyFromObject(tc.object), &after))
				require.True(t, bytes.Equal(before.Data["system.pem"], after.Data["system.pem"]))
				require.Equal(t, before.ResourceVersion, after.ResourceVersion)
			} else {
				require.True(t, apierrors.IsNotFound(kube.Get(context.Background(), client.ObjectKey{Namespace: cfg.Namespace, Name: cfg.KeysSecret}, &corev1.Secret{})))
			}
		})
	}
}

func TestInvalidOutputDoesNotGenerateReplacement(t *testing.T) {
	cfg := keyConfig()
	output := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: cfg.SecretName, Namespace: cfg.Namespace,
		Labels: map[string]string{"zitadel.truvity.io/bootstrap": cfg.Username},
	}, Data: map[string][]byte{"key.json": []byte("invalid")}}
	kube := keyClient(t, output)
	require.ErrorContains(t, Run(context.Background(), kube, cfg), "cannot load bootstrapped machine credential")
	var keys corev1.Secret
	require.True(t, apierrors.IsNotFound(kube.Get(context.Background(), client.ObjectKey{Namespace: cfg.Namespace, Name: cfg.KeysSecret}, &keys)))
	var unchanged corev1.Secret
	require.NoError(t, kube.Get(context.Background(), client.ObjectKeyFromObject(output), &unchanged))
	require.True(t, bytes.Equal(output.Data["key.json"], unchanged.Data["key.json"]))
}
