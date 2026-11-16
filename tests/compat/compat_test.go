//go:build compat

package compat

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	api "github.com/truvity/zitadel-operator/api/v1alpha2"
	"github.com/truvity/zitadel-operator/internal/bootstrap"
	"github.com/truvity/zitadel-operator/internal/controller"
	"github.com/truvity/zitadel-operator/internal/zitadel"
	application "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/application/v2"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// Runs only inside the disposable container environment; never against kubeconfig
// or a production Zitadel. Covers bootstrap, public PKCE handoff and drift.
func TestBootstrapAndOIDC(t *testing.T) {
	ctx := context.Background()
	issuer := os.Getenv("COMPAT_ISSUER")
	require.Equal(t, "https://zitadel:8080", issuer)
	httpClient := &http.Client{Timeout: 5 * time.Second}
	require.Eventually(t, func() bool {
		r, err := httpClient.Get(issuer + "/debug/ready")
		if err != nil {
			return false
		}
		defer r.Body.Close()
		return r.StatusCode == 200
	}, 3*time.Minute, 2*time.Second)
	env := &envtest.Environment{CRDDirectoryPaths: []string{filepath.Join("..", "..", "charts", "zitadel-operator-crds", "templates")}, ErrorIfCRDPathMissing: true}
	rest, err := env.Start()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, env.Stop()) })
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, api.AddToScheme(scheme))
	kube, err := client.New(rest, client.Options{Scheme: scheme})
	require.NoError(t, err)
	require.NoError(t, kube.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "compat"}}))
	systemKey, err := os.ReadFile("/state/system.pem")
	require.NoError(t, err)
	machineKey, err := os.ReadFile("/state/machine.pem")
	require.NoError(t, err)
	// Seed the generated-input Secret with this disposable server's trusted test
	// key. Unit tests cover first creation; this covers public-value publication,
	// normal machine authentication and the default effectively non-expiring key.
	require.NoError(t, kube.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "bootstrap-keys", Namespace: "compat",
			Labels:      map[string]string{"zitadel.truvity.io/bootstrap": "operator"},
			Annotations: map[string]string{"zitadel.truvity.io/bootstrap-issuer": issuer, "zitadel.truvity.io/bootstrap-system-user": "gitops-bootstrap"}},
		Data: map[string][]byte{"system.pem": systemKey, "machine.pem": machineKey},
	}))
	cfg := bootstrap.Config{Issuer: issuer, SystemUser: "gitops-bootstrap", Username: "operator", Namespace: "compat", SecretName: "operator-key",
		GenerateKeys: true, KeysSecret: "bootstrap-keys", PublicNamespace: "compat", PublicConfigMap: "bootstrap-public"}
	require.EventuallyWithT(t, func(c *assert.CollectT) { require.NoError(c, bootstrap.Run(ctx, kube, cfg)) }, time.Minute, 2*time.Second)
	var key corev1.Secret
	require.NoError(t, kube.Get(ctx, types.NamespacedName{Namespace: "compat", Name: "operator-key"}, &key))
	saved := string(key.Data["key.json"])
	require.NoError(t, bootstrap.Run(ctx, kube, cfg))
	require.NoError(t, kube.Get(ctx, types.NamespacedName{Namespace: "compat", Name: "operator-key"}, &key))
	require.True(t, saved == string(key.Data["key.json"]), "rerun must preserve credentials")
	z, err := zitadel.NewClient(ctx, &zitadel.ClientConfig{Domain: "zitadel", Port: "8080", KeyJSON: key.Data["key.json"]})
	require.NoError(t, err)
	org, err := z.Management().GetMyOrg(ctx, &management.GetMyOrgRequest{})
	require.NoError(t, err)
	project := &api.Project{ObjectMeta: metav1.ObjectMeta{Name: "books", Namespace: "compat"}, Spec: api.ProjectSpec{OrganizationId: org.GetOrg().GetId(), Roles: []string{"reader"}}}
	for i := 0; i < 100; i++ {
		project.Spec.Roles = append(project.Spec.Roles, fmt.Sprintf("role-%03d", i))
	}
	require.NoError(t, kube.Create(ctx, project))
	pr := controller.ProjectReconciler{Client: kube, Zitadel: z}
	projectReq := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(project)}
	_, err = pr.Reconcile(ctx, projectReq)
	require.NoError(t, err)
	require.NoError(t, kube.Get(ctx, projectReq.NamespacedName, project))
	require.NotEmpty(t, project.Status.ProjectId)
	app := &api.OIDCApp{ObjectMeta: metav1.ObjectMeta{Name: "books", Namespace: "compat"}, Spec: api.OIDCAppSpec{ProjectId: project.Status.ProjectId, Type: "native", AuthMethod: "none", GrantTypes: []string{"authorization_code", "refresh_token"}, RedirectUris: []string{"https://books.example.test/oauth2-callback", "bookorbit://oauth2-callback"}, SecretRef: api.SecretRefSpec{Name: "books-oidc"}}}
	require.NoError(t, kube.Create(ctx, app))
	r := controller.OIDCAppReconciler{Client: kube, Zitadel: z}
	appReq := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}
	_, err = r.Reconcile(ctx, appReq)
	require.NoError(t, err)
	require.NoError(t, kube.Get(ctx, appReq.NamespacedName, app))
	require.True(t, app.Status.Ready)
	var output corev1.Secret
	require.NoError(t, kube.Get(ctx, types.NamespacedName{Namespace: "compat", Name: "books-oidc"}, &output))
	require.Equal(t, app.Status.ClientId, string(output.Data["client_id"]))
	require.Empty(t, output.Data["client_secret"])
	remote, err := z.Application().GetApplication(ctx, &application.GetApplicationRequest{ApplicationId: app.Status.ApplicationId})
	require.NoError(t, err)
	require.Contains(t, remote.GetApplication().GetOidcConfiguration().GetGrantTypes(), application.OIDCGrantType_OIDC_GRANT_TYPE_REFRESH_TOKEN)
	_, err = z.Application().UpdateApplication(ctx, &application.UpdateApplicationRequest{ApplicationId: app.Status.ApplicationId, ProjectId: project.Status.ProjectId, ApplicationType: &application.UpdateApplicationRequest_OidcConfiguration{OidcConfiguration: &application.UpdateOIDCApplicationConfigurationRequest{RedirectUris: []string{"https://drift.example.test/callback"}}}})
	require.NoError(t, err)
	// Zitadel's ID lookup is projection-backed; reconciliation converges once
	// the out-of-band update is visible to reads.
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		_, reconcileErr := r.Reconcile(ctx, appReq)
		require.NoError(c, reconcileErr)
		current, getErr := z.Application().GetApplication(ctx, &application.GetApplicationRequest{ApplicationId: app.Status.ApplicationId})
		require.NoError(c, getErr)
		require.Equal(c, app.Spec.RedirectUris, current.GetApplication().GetOidcConfiguration().GetRedirectUris())
	}, 10*time.Second, 200*time.Millisecond)
	// A rename keeps the same remote application and client identity.
	require.NoError(t, kube.Get(ctx, appReq.NamespacedName, app))
	app.Spec.Name = "BookOrbit renamed"
	require.NoError(t, kube.Update(ctx, app))
	_, err = r.Reconcile(ctx, appReq)
	require.NoError(t, err)
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		current, getErr := z.Application().GetApplication(ctx, &application.GetApplicationRequest{ApplicationId: app.Status.ApplicationId})
		require.NoError(c, getErr)
		require.Equal(c, app.Spec.Name, current.GetApplication().GetName())
		require.Equal(c, app.Status.ClientId, current.GetApplication().GetOidcConfiguration().GetClientId())
	}, 10*time.Second, 200*time.Millisecond)

	confidential := &api.OIDCApp{ObjectMeta: metav1.ObjectMeta{Name: "server", Namespace: "compat"}, Spec: api.OIDCAppSpec{
		ProjectId: project.Status.ProjectId, Type: "confidential", AuthMethod: "basic", DeletionPolicy: "Delete",
		RedirectUris: []string{"https://server.example.test/callback"}, SecretRef: api.SecretRefSpec{Name: "server-oidc"},
	}}
	require.NoError(t, kube.Create(ctx, confidential))
	serverReq := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(confidential)}
	_, err = r.Reconcile(ctx, serverReq)
	require.NoError(t, err)
	require.NoError(t, kube.Get(ctx, serverReq.NamespacedName, confidential))
	serverKey := types.NamespacedName{Namespace: "compat", Name: "server-oidc"}
	var credential corev1.Secret
	require.NoError(t, kube.Get(ctx, serverKey, &credential))
	require.NotEmpty(t, credential.Data["client_secret"])
	oldCredential := string(credential.Data["client_secret"])
	require.NoError(t, kube.Delete(ctx, &credential))
	_, err = r.Reconcile(ctx, serverReq)
	require.ErrorContains(t, err, "rotateSecret", "missing credentials must not silently rotate")
	require.NoError(t, kube.Get(ctx, serverReq.NamespacedName, confidential))
	confidential.Spec.RotateSecret = "recover-1"
	require.NoError(t, kube.Update(ctx, confidential))
	_, err = r.Reconcile(ctx, serverReq)
	require.NoError(t, err)
	require.NoError(t, kube.Get(ctx, serverKey, &credential))
	require.NotEmpty(t, credential.Data["client_secret"])
	require.True(t, oldCredential != string(credential.Data["client_secret"]), "explicit recovery must rotate")
	newCredential := string(credential.Data["client_secret"])
	_, err = r.Reconcile(ctx, serverReq)
	require.NoError(t, err)
	require.NoError(t, kube.Get(ctx, serverKey, &credential))
	require.True(t, newCredential == string(credential.Data["client_secret"]), "completed rotation must not repeat")
	require.NoError(t, kube.Get(ctx, serverReq.NamespacedName, confidential))
	require.NoError(t, kube.Delete(ctx, confidential))
	_, err = r.Reconcile(ctx, serverReq)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		_, getErr := z.Application().GetApplication(ctx, &application.GetApplicationRequest{ApplicationId: confidential.Status.ApplicationId})
		return status.Code(getErr) == codes.NotFound
	}, 10*time.Second, 200*time.Millisecond, "Delete must remove the remote application")
	project.Spec.Roles = []string{}
	require.NoError(t, kube.Update(ctx, project))
	_, err = pr.Reconcile(ctx, projectReq)
	require.NoError(t, err)
	roles, err := z.Management().ListProjectRoles(ctx, &management.ListProjectRolesRequest{ProjectId: project.Status.ProjectId})
	require.NoError(t, err)
	require.Empty(t, roles.GetResult())
	require.NoError(t, kube.Get(ctx, appReq.NamespacedName, app))
	require.NoError(t, kube.Delete(ctx, app))
	_, err = r.Reconcile(ctx, appReq)
	require.NoError(t, err)
	_, err = z.Application().GetApplication(ctx, &application.GetApplicationRequest{ApplicationId: app.Status.ApplicationId})
	require.NoError(t, err, "Retain must preserve remote application")
}
