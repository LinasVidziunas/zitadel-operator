package controller

// OIDCApp reconciler unit tests against an in-process fake Application
// service: the real zitadel-go SDK client is dialed over bufconn, so the
// exact protobuf requests the reconciler sends can be asserted without a
// live Zitadel.

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	zitadelv1alpha2 "github.com/truvity/zitadel-operator/api/v1alpha2"
	"github.com/truvity/zitadel-operator/internal/zitadel"

	zitadelclient "github.com/zitadel/zitadel-go/v3/pkg/client"
	applicationv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/application/v2"
	sdkzitadel "github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

// fakeApplicationServer records the requests the reconciler sends.
type fakeApplicationServer struct {
	applicationv2.UnimplementedApplicationServiceServer

	mu        sync.Mutex
	createReq *applicationv2.CreateApplicationRequest
	updateReq *applicationv2.UpdateApplicationRequest
	listErr   error
	getErr    error
	apps      []*applicationv2.Application
}

func (f *fakeApplicationServer) GetApplication(_ context.Context, req *applicationv2.GetApplicationRequest) (*applicationv2.GetApplicationResponse, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	for _, app := range f.apps {
		if app.GetApplicationId() == req.GetApplicationId() {
			return &applicationv2.GetApplicationResponse{Application: app}, nil
		}
	}
	return nil, status.Error(codes.NotFound, "missing application")
}

func (f *fakeApplicationServer) ListApplications(_ context.Context, _ *applicationv2.ListApplicationsRequest) (*applicationv2.ListApplicationsResponse, error) {
	return &applicationv2.ListApplicationsResponse{Applications: f.apps}, f.listErr
}

func (f *fakeApplicationServer) CreateApplication(_ context.Context, req *applicationv2.CreateApplicationRequest) (*applicationv2.CreateApplicationResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.createReq = req
	return &applicationv2.CreateApplicationResponse{
		ApplicationId: "app-1",
		ApplicationType: &applicationv2.CreateApplicationResponse_OidcConfiguration{
			OidcConfiguration: &applicationv2.CreateOIDCApplicationResponse{
				ClientId:     "client-1",
				ClientSecret: "secret-1",
			},
		},
	}, nil
}

func (f *fakeApplicationServer) UpdateApplication(_ context.Context, req *applicationv2.UpdateApplicationRequest) (*applicationv2.UpdateApplicationResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updateReq = req
	return &applicationv2.UpdateApplicationResponse{}, nil
}

// newFakeZitadelClient serves fake over bufconn and returns an operator
// client whose SDK connection is dialed against it (static token, no OIDC
// discovery, no network).
func newFakeZitadelClient(t *testing.T, fake applicationv2.ApplicationServiceServer) *zitadel.Client {
	t.Helper()

	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	applicationv2.RegisterApplicationServiceServer(srv, fake)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	inner, err := zitadelclient.New(context.Background(),
		sdkzitadel.New("bufconn", sdkzitadel.WithInsecure("0")),
		zitadelclient.WithAuth(func(_ context.Context, _ string) (oauth2.TokenSource, error) {
			return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token"}), nil
		}),
		zitadelclient.WithGRPCDialOptions(
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				return lis.DialContext(ctx)
			}),
		),
	)
	require.NoError(t, err)
	return zitadel.NewFromSDK(inner)
}

func testOIDCApp() *zitadelv1alpha2.OIDCApp {
	return &zitadelv1alpha2.OIDCApp{
		ObjectMeta: metav1.ObjectMeta{Name: "my-app", Namespace: "default", UID: "test-app-uid"},
		Spec: zitadelv1alpha2.OIDCAppSpec{
			Type:         "confidential",
			AuthMethod:   "basic",
			RedirectUris: []string{"https://app.example.com/callback"},
			SecretRef:    zitadelv1alpha2.SecretRefSpec{Name: "my-app-oidc"},
		},
	}
}

func outputClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(s))
	require.NoError(t, zitadelv1alpha2.AddToScheme(s))
	return fake.NewClientBuilder().WithScheme(s).WithObjects(objects...).Build()
}

func TestOIDCLookupFailuresNeverCreate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		server *fakeApplicationServer
	}{
		{"unavailable", &fakeApplicationServer{listErr: status.Error(codes.Unavailable, "offline")}},
		{"ambiguous", &fakeApplicationServer{apps: []*applicationv2.Application{{ApplicationId: "a"}, {ApplicationId: "b"}}}},
		{"wrong type", &fakeApplicationServer{apps: []*applicationv2.Application{{ApplicationId: "a"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &OIDCAppReconciler{Client: outputClient(t), Zitadel: newFakeZitadelClient(t, tc.server)}
			_, _, _, err := r.findOrCreateApp(context.Background(), "project", "my-app", testOIDCApp())
			require.Error(t, err)
			require.Nil(t, tc.server.createReq, "uncertain lookup must never create an application")
		})
	}
}

func TestOIDCPublicHandoffAndSecretCollision(t *testing.T) {
	ctx := context.Background()
	cr := testOIDCApp()
	cr.Spec.Type = "native"
	cr.Spec.AuthMethod = "none"
	kube := outputClient(t)
	r := &OIDCAppReconciler{Client: kube}
	require.NoError(t, r.ensureCredentialSecret(ctx, cr, "public-client", ""))
	var secret corev1.Secret
	key := client.ObjectKey{Namespace: cr.Namespace, Name: cr.Spec.SecretRef.Name}
	require.NoError(t, kube.Get(ctx, key, &secret))
	require.Equal(t, "public-client", string(secret.Data["client_id"]))
	require.Empty(t, secret.Data["client_secret"])
	require.True(t, metav1.IsControlledBy(&secret, cr))
	other := cr.DeepCopy()
	other.UID = "different-app"
	require.Error(t, r.ensureCredentialSecret(ctx, other, "replacement", ""))
	require.NoError(t, kube.Get(ctx, key, &secret))
	require.Equal(t, "public-client", string(secret.Data["client_id"]))
}

func TestOIDCProtocolDrift(t *testing.T) {
	server := &fakeApplicationServer{}
	r := &OIDCAppReconciler{Zitadel: newFakeZitadelClient(t, server)}
	cr := testOIDCApp()
	cr.Spec.Type = "native"
	cr.Spec.AuthMethod = "none"
	cr.Spec.GrantTypes = []string{"authorization_code", "refresh_token"}
	app := &applicationv2.Application{Configuration: &applicationv2.Application_OidcConfiguration{OidcConfiguration: &applicationv2.OIDCConfiguration{RedirectUris: cr.Spec.RedirectUris}}}
	require.NoError(t, r.updateOIDCAppIfNeeded(context.Background(), "app", "project", app, cr))
	got := server.updateReq.GetOidcConfiguration()
	require.Equal(t, applicationv2.OIDCApplicationType_OIDC_APP_TYPE_NATIVE, got.GetApplicationType())
	require.Equal(t, applicationv2.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_NONE, got.GetAuthMethodType())
	require.Contains(t, got.GetGrantTypes(), applicationv2.OIDCGrantType_OIDC_GRANT_TYPE_REFRESH_TOKEN)
}

func TestOIDCRejectsUnsafeAdoption(t *testing.T) {
	for _, name := range []string{"missing credential", "mismatched client", "project move", "missing managed app"} {
		t.Run(name, func(t *testing.T) {
			cr := testOIDCApp()
			cr.Status.ApplicationId = "managed"
			cr.Status.ProjectId = "project"
			app := &applicationv2.Application{ApplicationId: "managed", ProjectId: "project", Name: "old name", Configuration: &applicationv2.Application_OidcConfiguration{OidcConfiguration: &applicationv2.OIDCConfiguration{ClientId: "managed-client", AuthMethodType: applicationv2.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_NONE}}}
			server := &fakeApplicationServer{apps: []*applicationv2.Application{app}}
			kube := outputClient(t)
			r := &OIDCAppReconciler{Client: kube, Zitadel: newFakeZitadelClient(t, server)}
			switch name {
			case "mismatched client":
				require.NoError(t, r.ensureSecret(context.Background(), cr, "different-client", "stale-secret"))
			case "project move":
				cr.Status.ProjectId = "old-project"
			case "missing managed app":
				server.apps = nil
			}
			_, _, _, err := r.findOrCreateApp(context.Background(), "project", cr.DisplayName(), cr)
			require.Error(t, err)
			require.Nil(t, server.createReq)
			require.Nil(t, server.updateReq, "rejected adoption must not partially mutate the remote application")
		})
	}
}

func TestDeletionFailureKeepsFinalizer(t *testing.T) {
	ctx := context.Background()
	cr := testOIDCApp()
	cr.Finalizers = []string{finalizerName}
	kube := outputClient(t, cr)
	require.NoError(t, kube.Delete(ctx, cr))
	require.NoError(t, kube.Get(ctx, client.ObjectKeyFromObject(cr), cr))
	_, _, err := handleDeletion(ctx, kube, cr, func() error { return errors.New("remote unavailable") })
	require.Error(t, err)
	require.NoError(t, kube.Get(ctx, client.ObjectKeyFromObject(cr), cr))
	require.Contains(t, cr.Finalizers, finalizerName)
}

func TestCreateOIDCApp_PropagatesIdTokenUserinfoAssertion(t *testing.T) {
	fake := &fakeApplicationServer{}
	r := &OIDCAppReconciler{Zitadel: newFakeZitadelClient(t, fake)}

	cr := testOIDCApp()
	cr.Spec.IdTokenRoleAssertion = true
	cr.Spec.IdTokenUserinfoAssertion = true

	appID, clientID, clientSecret, err := r.createOIDCApp(context.Background(), "proj-1", cr)
	require.NoError(t, err)
	assert.Equal(t, "app-1", appID)
	assert.Equal(t, "client-1", clientID)
	assert.Equal(t, "secret-1", clientSecret)

	require.NotNil(t, fake.createReq)
	oidcCfg := fake.createReq.GetOidcConfiguration()
	require.NotNil(t, oidcCfg)
	assert.True(t, oidcCfg.GetIdTokenRoleAssertion())
	assert.True(t, oidcCfg.GetIdTokenUserinfoAssertion(),
		"spec.idTokenUserinfoAssertion must reach the create request")
}

func TestUpdateOIDCAppIfNeeded_IdTokenUserinfoDriftTriggersUpdate(t *testing.T) {
	fake := &fakeApplicationServer{}
	r := &OIDCAppReconciler{Zitadel: newFakeZitadelClient(t, fake)}

	cr := testOIDCApp()
	cr.Spec.IdTokenUserinfoAssertion = true

	// Server state matches the spec except idTokenUserinfoAssertion.
	app := &applicationv2.Application{
		Name: cr.DisplayName(),
		Configuration: &applicationv2.Application_OidcConfiguration{
			OidcConfiguration: &applicationv2.OIDCConfiguration{
				RedirectUris:             cr.Spec.RedirectUris,
				GrantTypes:               desiredGrantTypes(cr),
				AccessTokenType:          applicationv2.OIDCTokenType_OIDC_TOKEN_TYPE_BEARER,
				IdTokenUserinfoAssertion: false,
			},
		},
	}

	err := r.updateOIDCAppIfNeeded(context.Background(), "app-1", "proj-1", app, cr)
	require.NoError(t, err)

	require.NotNil(t, fake.updateReq, "drift on idTokenUserinfoAssertion must trigger an update")
	oidcCfg := fake.updateReq.GetOidcConfiguration()
	require.NotNil(t, oidcCfg)
	assert.True(t, oidcCfg.GetIdTokenUserinfoAssertion(),
		"update must carry the desired idTokenUserinfoAssertion value")
}

func TestUpdateOIDCAppIfNeeded_NoDriftNoUpdate(t *testing.T) {
	fake := &fakeApplicationServer{}
	r := &OIDCAppReconciler{Zitadel: newFakeZitadelClient(t, fake)}

	cr := testOIDCApp()
	cr.Spec.IdTokenUserinfoAssertion = true

	app := &applicationv2.Application{
		Name: cr.DisplayName(),
		Configuration: &applicationv2.Application_OidcConfiguration{
			OidcConfiguration: &applicationv2.OIDCConfiguration{
				RedirectUris:             cr.Spec.RedirectUris,
				GrantTypes:               desiredGrantTypes(cr),
				AccessTokenType:          applicationv2.OIDCTokenType_OIDC_TOKEN_TYPE_BEARER,
				IdTokenUserinfoAssertion: true,
			},
		},
	}

	err := r.updateOIDCAppIfNeeded(context.Background(), "app-1", "proj-1", app, cr)
	require.NoError(t, err)
	assert.Nil(t, fake.updateReq, "matching state must not produce an update call")
}
