package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	api "github.com/truvity/zitadel-operator/api/v1alpha2"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestOrganizationRetentionNeedsNoRemoteDeletion(t *testing.T) {
	ctx := context.Background()
	org := &api.Organization{
		ObjectMeta: metav1.ObjectMeta{Name: "kubesaurus", Namespace: "default", Finalizers: []string{finalizerName},
			Annotations: map[string]string{"zitadel.truvity.io/deletion-policy": "Retain"}},
		Status: api.OrganizationStatus{OrganizationId: "existing-organization"},
	}
	kube := outputClient(t, org)
	require.NoError(t, kube.Delete(ctx, org))
	r := &OrganizationReconciler{Client: kube}
	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(org)})
	require.NoError(t, err)
	require.True(t, apierrors.IsNotFound(kube.Get(ctx, client.ObjectKeyFromObject(org), org)))
}
