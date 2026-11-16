package controller

import (
	"context"
	"fmt"
	"reflect"
	"slices"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	zitadelv1alpha2 "github.com/truvity/zitadel-operator/api/v1alpha2"
	"github.com/truvity/zitadel-operator/internal/config"
	"github.com/truvity/zitadel-operator/internal/delegation"
	"github.com/truvity/zitadel-operator/internal/scopemap"
	"github.com/truvity/zitadel-operator/internal/zitadel"

	applicationv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/application/v2"
	filterv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/filter/v2"
)

// OIDCAppReconciler reconciles an OIDCApp object.
type OIDCAppReconciler struct {
	client.Client
	Zitadel *zitadel.Client
	Config  *config.Config

	// Resolver enables v0.18 scope-map resolution when non-nil; with maps
	// present, reconciliation runs with a delegated per-scope client.
	Resolver *scopemap.Resolver
	// Delegation mints/caches the per-scope delegated clients.
	Delegation *delegation.Manager
}

// +kubebuilder:rbac:groups=zitadel.truvity.io,resources=oidcapps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=zitadel.truvity.io,resources=oidcapps/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=zitadel.truvity.io,resources=oidcapps/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch

func (r *OIDCAppReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var cr zitadelv1alpha2.OIDCApp
	if err := r.Get(ctx, req.NamespacedName, &cr); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// v0.18 (INF-422/INF-423): dual-serving instance gate + scope
	// resolution. Fail-closed outcomes return immediately; during deletion
	// failures fall back to the binding client so finalizers cannot deadlock.
	ctx, rs, rsDone, rsResult, rsErr := tenantPreamble(ctx, r.Client, r.Config,
		r.Resolver, r.Delegation, r.Zitadel, &cr, cr.Spec.Instance, &cr.Status.Conditions, req.Namespace)
	if rsDone {
		return rsResult, rsErr
	}
	if !cr.DeletionTimestamp.IsZero() && cr.Spec.DeletionPolicy != "Delete" {
		_, result, err := handleDeletionStrict(ctx, r.Client, &cr, nil)
		return result, err
	}
	if !cr.DeletionTimestamp.IsZero() {
		_, result, err := handleDeletionStrict(ctx, r.Client, &cr, func() error {
			if cr.Status.ApplicationId == "" {
				return nil
			}
			_, err := zclient(ctx, r.Zitadel).Application().DeleteApplication(ctx, &applicationv2.DeleteApplicationRequest{
				ApplicationId: cr.Status.ApplicationId, ProjectId: cr.Status.ProjectId,
			})
			if status.Code(err) == codes.NotFound {
				return nil
			}
			return err
		})
		return result, err
	}

	// Resolve project ID (and inherited org ID).
	projectID, inheritedOrgID, err := resolveScopedProjectId(ctx, r.Client, rs, cr.Spec.ProjectRef, cr.Spec.ProjectId, cr.Namespace, cr.Status.ProjectId, cr.Status.OrganizationId)
	if err != nil {
		if waiting, result := waitForRef(ctx, r.Client, r.Config, &cr, &cr.Status.Conditions, "ProjectNotReady", err); waiting {
			return result, nil
		}
		return ctrl.Result{}, fmt.Errorf("resolving project: %w", err)
	}

	// Add finalizer if not present.
	if err := ensureFinalizer(ctx, r.Client, &cr); err != nil {
		return ctrl.Result{}, err
	}
	// ensureFinalizer's full-object Update refreshed the object from the
	// server, dropping in-memory condition edits — re-apply ScopeResolved.
	applyScopeResolvedCondition(rs, &cr.Status.Conditions)

	// Find or create app.
	displayName := cr.DisplayName()
	appID, clientID, clientSecret, err := r.findOrCreateApp(ctx, projectID, displayName, &cr)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Store credentials in Secret.
	if err := r.ensureCredentialSecret(ctx, &cr, clientID, clientSecret); err != nil {
		return ctrl.Result{}, err
	}

	// Update status only if changed.
	if err := r.updateStatusIfNeeded(ctx, &cr, appID, clientID, projectID, inheritedOrgID); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: requeueInterval}, nil
}

func (r *OIDCAppReconciler) ensureCredentialSecret(ctx context.Context, cr *zitadelv1alpha2.OIDCApp, clientID, clientSecret string) error {
	if clientID == "" {
		return fmt.Errorf("OIDC application returned no client ID")
	}
	_, authMethod := zitadelAppType(cr.Spec.Type, cr.Spec.AuthMethod)
	if clientSecret != "" && authMethod != applicationv2.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_NONE {
		return r.ensureSecret(ctx, cr, clientID, clientSecret)
	}
	return r.ensureSecretClientID(ctx, cr, clientID)
}

func (r *OIDCAppReconciler) updateStatusIfNeeded(ctx context.Context, cr *zitadelv1alpha2.OIDCApp, appID, clientID, projectID, inheritedOrgID string) error {
	rotatedFor := cr.Status.RotatedFor
	_, authMethod := zitadelAppType(cr.Spec.Type, cr.Spec.AuthMethod)
	if authMethod != applicationv2.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_NONE && cr.Spec.RotateSecret != "" {
		rotatedFor = cr.Spec.RotateSecret
	}
	statusChanged := cr.Status.RotatedFor != rotatedFor || cr.Status.ApplicationId != appID || cr.Status.ClientId != clientID ||
		cr.Status.ProjectId != projectID || cr.Status.OrganizationId != inheritedOrgID
	cr.Status.ApplicationId = appID
	cr.Status.ClientId = clientID
	cr.Status.ProjectId = projectID
	cr.Status.OrganizationId = inheritedOrgID
	cr.Status.RotatedFor = rotatedFor
	return markReady(ctx, r.Client, r.Config, cr, statusFields{
		conditions: &cr.Status.Conditions, ready: &cr.Status.Ready, lastSyncTime: &cr.Status.LastSyncTime,
	}, statusChanged)
}

func (r *OIDCAppReconciler) findOrCreateApp(ctx context.Context, projectID, displayName string, cr *zitadelv1alpha2.OIDCApp) (appID, clientID, clientSecret string, err error) {
	if err := r.checkOutputSecret(ctx, cr); err != nil {
		return "", "", "", err
	}
	var existingAppID string
	var existingApp *applicationv2.Application
	if cr.Status.ApplicationId != "" {
		if cr.Status.ProjectId != "" && cr.Status.ProjectId != projectID {
			return "", "", "", fmt.Errorf("an existing OIDC application cannot move projects; create a new OIDCApp")
		}
		resp, getErr := zclient(ctx, r.Zitadel).Application().GetApplication(ctx, &applicationv2.GetApplicationRequest{ApplicationId: cr.Status.ApplicationId})
		if getErr != nil {
			return "", "", "", fmt.Errorf("getting managed OIDC application: %w", getErr)
		}
		existingApp = resp.GetApplication()
		if existingApp.GetProjectId() != projectID {
			return "", "", "", fmt.Errorf("managed application belongs to a different project")
		}
		existingAppID = existingApp.GetApplicationId()
		if existingAppID != cr.Status.ApplicationId {
			return "", "", "", fmt.Errorf("managed application ID mismatch")
		}
	} else {
		existingAppID, existingApp, err = r.findAppByName(ctx, projectID, displayName)
	}
	if err != nil {
		return "", "", "", err
	}

	if existingAppID == "" {
		return r.createOIDCApp(ctx, projectID, cr)
	}

	appID = existingAppID
	if existingApp.GetOidcConfiguration() == nil {
		return "", "", "", fmt.Errorf("matching application is not OIDC")
	}
	clientID = r.getClientIDFromApp(existingApp)
	if clientID == "" {
		return "", "", "", fmt.Errorf("existing OIDC application has no client ID")
	}
	// Validate credential recovery before changing the remote authentication method.
	_, authMethod := zitadelAppType(cr.Spec.Type, cr.Spec.AuthMethod)
	rotate := authMethod != applicationv2.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_NONE && cr.Spec.RotateSecret != "" && cr.Spec.RotateSecret != cr.Status.RotatedFor
	if authMethod != applicationv2.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_NONE && !rotate {
		secret := &corev1.Secret{}
		err = r.Get(ctx, types.NamespacedName{Namespace: cr.Namespace, Name: cr.Spec.SecretRef.Name}, secret)
		if client.IgnoreNotFound(err) != nil {
			return "", "", "", err
		}
		if len(secret.Data[clientSecretKey(cr)]) == 0 || string(secret.Data[clientIDKey(cr)]) != clientID {
			return "", "", "", fmt.Errorf("existing application has no matching stored credential; set spec.rotateSecret explicitly to recover")
		}
	}
	if err := r.updateOIDCAppIfNeeded(ctx, existingAppID, projectID, existingApp, cr); err != nil {
		return "", "", "", err
	}
	if rotate {
		resp, e := zclient(ctx, r.Zitadel).Application().GenerateClientSecret(ctx, &applicationv2.GenerateClientSecretRequest{ApplicationId: appID, ProjectId: projectID})
		if e != nil {
			return "", "", "", e
		}
		clientSecret = resp.GetClientSecret()
		if clientSecret == "" {
			return "", "", "", fmt.Errorf("credential rotation returned no secret")
		}
	}
	return appID, clientID, clientSecret, nil
}

func (r *OIDCAppReconciler) findAppByName(ctx context.Context, projectID, appName string) (string, *applicationv2.Application, error) {
	listResp, err := zclient(ctx, r.Zitadel).Application().ListApplications(ctx, &applicationv2.ListApplicationsRequest{
		Filters: []*applicationv2.ApplicationSearchFilter{
			{Filter: &applicationv2.ApplicationSearchFilter_NameFilter{NameFilter: &applicationv2.ApplicationNameFilter{Name: appName, Method: filterv2.TextFilterMethod_TEXT_FILTER_METHOD_EQUALS}}},
			{
				Filter: &applicationv2.ApplicationSearchFilter_ProjectIdFilter{
					ProjectIdFilter: &applicationv2.ProjectIDFilter{
						ProjectId: projectID,
					},
				},
			},
		},
	})
	if err != nil {
		return "", nil, err
	}
	if len(listResp.GetApplications()) > 1 || listResp.GetPagination().GetTotalResult() > 1 {
		return "", nil, fmt.Errorf("ambiguous application name %q", appName)
	}
	if len(listResp.GetApplications()) == 1 {
		app := listResp.GetApplications()[0]
		return app.GetApplicationId(), app, nil
	}
	return "", nil, nil
}

func (r *OIDCAppReconciler) createOIDCApp(ctx context.Context, projectID string, cr *zitadelv1alpha2.OIDCApp) (appID, clientID, clientSecret string, err error) {
	appType, authMethod := zitadelAppType(cr.Spec.Type, cr.Spec.AuthMethod)

	accessTokenType := applicationv2.OIDCTokenType_OIDC_TOKEN_TYPE_BEARER
	if cr.Spec.AccessTokenType == "jwt" {
		accessTokenType = applicationv2.OIDCTokenType_OIDC_TOKEN_TYPE_JWT
	}

	resp, createErr := zclient(ctx, r.Zitadel).Application().CreateApplication(ctx, &applicationv2.CreateApplicationRequest{
		ProjectId: projectID,
		Name:      cr.DisplayName(),
		ApplicationType: &applicationv2.CreateApplicationRequest_OidcConfiguration{
			OidcConfiguration: &applicationv2.CreateOIDCApplicationRequest{
				RedirectUris:             cr.Spec.RedirectUris,
				PostLogoutRedirectUris:   cr.Spec.PostLogoutRedirectUris,
				ResponseTypes:            []applicationv2.OIDCResponseType{applicationv2.OIDCResponseType_OIDC_RESPONSE_TYPE_CODE},
				GrantTypes:               desiredGrantTypes(cr),
				ApplicationType:          appType,
				AuthMethodType:           authMethod,
				AccessTokenType:          accessTokenType,
				AccessTokenRoleAssertion: cr.Spec.AccessTokenRoleAssertion,
				IdTokenRoleAssertion:     cr.Spec.IdTokenRoleAssertion,
				IdTokenUserinfoAssertion: cr.Spec.IdTokenUserinfoAssertion,
			},
		},
	})
	if createErr != nil {
		return "", "", "", fmt.Errorf("creating OIDC application: %w", createErr)
	}

	appID = resp.GetApplicationId()
	if oidcResp := resp.GetApplicationType(); oidcResp != nil {
		if oidcRespConfig, ok := oidcResp.(*applicationv2.CreateApplicationResponse_OidcConfiguration); ok {
			clientID = oidcRespConfig.OidcConfiguration.GetClientId()
			clientSecret = oidcRespConfig.OidcConfiguration.GetClientSecret()
		}
	}

	return appID, clientID, clientSecret, nil
}

func (r *OIDCAppReconciler) getClientIDFromApp(app *applicationv2.Application) string {
	if app == nil {
		return ""
	}
	if oidcConfig := app.GetOidcConfiguration(); oidcConfig != nil {
		return oidcConfig.GetClientId()
	}
	return ""
}

func (r *OIDCAppReconciler) updateOIDCAppIfNeeded(ctx context.Context, appID, projectID string, app *applicationv2.Application, cr *zitadelv1alpha2.OIDCApp) error {
	if app == nil {
		return nil
	}
	oidcConfig := app.GetOidcConfiguration()
	if oidcConfig == nil {
		return fmt.Errorf("matching application is not OIDC")
	}
	appType, authMethod := zitadelAppType(cr.Spec.Type, cr.Spec.AuthMethod)
	grants := desiredGrantTypes(cr)
	protocolChanged := oidcConfig.GetApplicationType() != appType || oidcConfig.GetAuthMethodType() != authMethod || !slices.Equal(oidcConfig.GetGrantTypes(), grants)

	// Detect drift across all mutable fields.
	redirectsChanged := !reflect.DeepEqual(oidcConfig.GetRedirectUris(), cr.Spec.RedirectUris)
	postLogoutChanged := !reflect.DeepEqual(oidcConfig.GetPostLogoutRedirectUris(), cr.Spec.PostLogoutRedirectUris)

	desiredAccessTokenType := applicationv2.OIDCTokenType_OIDC_TOKEN_TYPE_BEARER
	if cr.Spec.AccessTokenType == "jwt" {
		desiredAccessTokenType = applicationv2.OIDCTokenType_OIDC_TOKEN_TYPE_JWT
	}
	accessTokenTypeChanged := oidcConfig.GetAccessTokenType() != desiredAccessTokenType

	accessTokenRoleChanged := oidcConfig.GetAccessTokenRoleAssertion() != cr.Spec.AccessTokenRoleAssertion
	idTokenRoleChanged := oidcConfig.GetIdTokenRoleAssertion() != cr.Spec.IdTokenRoleAssertion
	idTokenUserinfoChanged := oidcConfig.GetIdTokenUserinfoAssertion() != cr.Spec.IdTokenUserinfoAssertion

	configChanged := protocolChanged || redirectsChanged || postLogoutChanged || accessTokenTypeChanged || accessTokenRoleChanged || idTokenRoleChanged || idTokenUserinfoChanged
	if !configChanged && app.GetName() == cr.DisplayName() {
		return nil
	}

	logger := log.FromContext(ctx)
	logger.Info("drift detected, updating OIDC app",
		"redirectsChanged", redirectsChanged,
		"postLogoutChanged", postLogoutChanged,
		"accessTokenTypeChanged", accessTokenTypeChanged,
		"accessTokenRoleChanged", accessTokenRoleChanged,
		"idTokenRoleChanged", idTokenRoleChanged,
		"idTokenUserinfoChanged", idTokenUserinfoChanged,
	)

	// INF-400 root cause: sending the (unchanged) Name alongside a changed
	// OIDC configuration makes Zitadel's name-change command reject the whole
	// request with "No changes (COMMAND-2m8vx)" — the URI list then never
	// converges. Per the API contract, an unset Name leaves the name alone,
	// so it is only included when it actually drifted.
	updateName := ""
	if app.GetName() != cr.DisplayName() {
		updateName = cr.DisplayName()
	}
	req := &applicationv2.UpdateApplicationRequest{
		ApplicationId: appID,
		ProjectId:     projectID,
		Name:          updateName,
	}
	if configChanged {
		req.ApplicationType = &applicationv2.UpdateApplicationRequest_OidcConfiguration{
			OidcConfiguration: &applicationv2.UpdateOIDCApplicationConfigurationRequest{
				ApplicationType:          &appType,
				AuthMethodType:           &authMethod,
				GrantTypes:               grants,
				RedirectUris:             cr.Spec.RedirectUris,
				PostLogoutRedirectUris:   cr.Spec.PostLogoutRedirectUris,
				AccessTokenType:          &desiredAccessTokenType,
				AccessTokenRoleAssertion: &cr.Spec.AccessTokenRoleAssertion,
				IdTokenRoleAssertion:     &cr.Spec.IdTokenRoleAssertion,
				IdTokenUserinfoAssertion: &cr.Spec.IdTokenUserinfoAssertion,
			},
		}
	}
	_, err := zclient(ctx, r.Zitadel).Application().UpdateApplication(ctx, req)
	if err != nil {
		return fmt.Errorf("updating OIDC application: %w", err)
	}
	return nil
}

func clientIDKey(cr *zitadelv1alpha2.OIDCApp) string {
	if cr.Spec.SecretRef.Keys != nil && cr.Spec.SecretRef.Keys.ClientId != "" {
		return cr.Spec.SecretRef.Keys.ClientId
	}
	return "client_id"
}

func clientSecretKey(cr *zitadelv1alpha2.OIDCApp) string {
	if cr.Spec.SecretRef.Keys != nil && cr.Spec.SecretRef.Keys.ClientSecret != "" {
		return cr.Spec.SecretRef.Keys.ClientSecret
	}
	return "client_secret"
}

func (r *OIDCAppReconciler) ensureSecret(ctx context.Context, cr *zitadelv1alpha2.OIDCApp, clientID, clientSecret string) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.SecretRef.Name,
			Namespace: cr.Namespace,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		if err := claimOIDCSecret(cr, secret); err != nil {
			return err
		}
		if secret.Data == nil {
			secret.Data = make(map[string][]byte)
		}
		secret.Data[clientIDKey(cr)] = []byte(clientID)
		secret.Data[clientSecretKey(cr)] = []byte(clientSecret)
		for k, v := range cr.Spec.SecretRef.ExtraData {
			if k == clientIDKey(cr) || k == clientSecretKey(cr) {
				return fmt.Errorf("extraData must not overwrite credential keys")
			}
			secret.Data[k] = []byte(v)
		}
		return nil
	})
	return err
}

func (r *OIDCAppReconciler) ensureSecretClientID(ctx context.Context, cr *zitadelv1alpha2.OIDCApp, clientID string) error {
	secret := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{
		Name:      cr.Spec.SecretRef.Name,
		Namespace: cr.Namespace,
	}, secret)
	if err != nil {
		if client.IgnoreNotFound(err) == nil {
			data := map[string][]byte{
				clientIDKey(cr): []byte(clientID),
			}
			for k, v := range cr.Spec.SecretRef.ExtraData {
				data[k] = []byte(v)
			}
			newSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      cr.Spec.SecretRef.Name,
					Namespace: cr.Namespace,
				},
				Data: data,
			}
			if err := claimOIDCSecret(cr, newSecret); err != nil {
				return err
			}
			return r.Create(ctx, newSecret)
		}
		return err
	}
	if err := claimOIDCSecret(cr, secret); err != nil {
		return err
	}

	updated := false
	_, authMethod := zitadelAppType(cr.Spec.Type, cr.Spec.AuthMethod)
	if authMethod == applicationv2.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_NONE && secret.Data[clientSecretKey(cr)] != nil {
		delete(secret.Data, clientSecretKey(cr))
		updated = true
	}
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}
	idKey := clientIDKey(cr)
	if string(secret.Data[idKey]) != clientID {
		secret.Data[idKey] = []byte(clientID)
		updated = true
	}
	for k, v := range cr.Spec.SecretRef.ExtraData {
		if k == clientIDKey(cr) || k == clientSecretKey(cr) {
			return fmt.Errorf("extraData must not overwrite credential keys")
		}
		if string(secret.Data[k]) != v {
			secret.Data[k] = []byte(v)
			updated = true
		}
	}
	if updated {
		return r.Update(ctx, secret)
	}
	return nil
}

func desiredGrantTypes(cr *zitadelv1alpha2.OIDCApp) []applicationv2.OIDCGrantType {
	grants := []applicationv2.OIDCGrantType{applicationv2.OIDCGrantType_OIDC_GRANT_TYPE_AUTHORIZATION_CODE}
	if slices.Contains(cr.Spec.GrantTypes, "refresh_token") {
		grants = append(grants, applicationv2.OIDCGrantType_OIDC_GRANT_TYPE_REFRESH_TOKEN)
	}
	return grants
}

func claimOIDCSecret(cr *zitadelv1alpha2.OIDCApp, secret *corev1.Secret) error {
	if secret.ResourceVersion != "" && !metav1.IsControlledBy(secret, cr) {
		return fmt.Errorf("output Secret %s already exists and is not owned by this OIDCApp", secret.Name)
	}
	if secret.ResourceVersion == "" {
		secret.OwnerReferences = []metav1.OwnerReference{*metav1.NewControllerRef(cr, zitadelv1alpha2.GroupVersion.WithKind("OIDCApp"))}
	}
	return nil
}

func (r *OIDCAppReconciler) checkOutputSecret(ctx context.Context, cr *zitadelv1alpha2.OIDCApp) error {
	if cr.Spec.SecretRef.Name == "" {
		return fmt.Errorf("secretRef.name is required")
	}
	if clientIDKey(cr) == clientSecretKey(cr) {
		return fmt.Errorf("client ID and secret keys must differ")
	}
	for key := range cr.Spec.SecretRef.ExtraData {
		if key == clientIDKey(cr) || key == clientSecretKey(cr) {
			return fmt.Errorf("extraData must not overwrite credential keys")
		}
	}
	secret := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Namespace: cr.Namespace, Name: cr.Spec.SecretRef.Name}, secret)
	if err != nil {
		return client.IgnoreNotFound(err)
	}
	return claimOIDCSecret(cr, secret)
}

// SetupWithManager sets up the controller with the Manager.
func (r *OIDCAppReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&zitadelv1alpha2.OIDCApp{}).
		Named("oidcapp").
		WithEventFilter(generationChangedPredicate()).
		Complete(r)
}

// zitadelAppType maps the CRD's type/authMethod pair onto Zitadel's
// application and auth-method types. public and native clients never
// hold a secret, so their auth method is NONE regardless of the field;
// confidential follows authMethod.
func zitadelAppType(crType, crAuthMethod string) (applicationv2.OIDCApplicationType, applicationv2.OIDCAuthMethodType) {
	switch crType {
	case "public":
		return applicationv2.OIDCApplicationType_OIDC_APP_TYPE_USER_AGENT, applicationv2.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_NONE
	case "native":
		return applicationv2.OIDCApplicationType_OIDC_APP_TYPE_NATIVE, applicationv2.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_NONE
	}

	authMethod := applicationv2.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_BASIC
	if crAuthMethod == "none" {
		authMethod = applicationv2.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_NONE
	}

	return applicationv2.OIDCApplicationType_OIDC_APP_TYPE_WEB, authMethod
}
