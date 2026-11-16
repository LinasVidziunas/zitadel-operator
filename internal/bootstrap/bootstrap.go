// Package bootstrap provisions the operator's normal machine identity using a
// configuration-defined SystemAPIUser. The operator still verifies real IAM
// memberships; a system user is never passed off as a machine user.
package bootstrap

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/truvity/zitadel-operator/internal/zitadel"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Config struct {
	Issuer, SystemUser, Username, Namespace, SecretName, SecretKey string
	SystemKey, MachineKey                                          []byte
	Expires                                                        time.Time
	GenerateKeys                                                   bool
	KeysSecret, PublicConfigMap, PublicNamespace                   string
}

func privateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("expected RSA private PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid private key")
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("RSA key required")
	}
	return rsaKey, nil
}

// Run creates a credential Secret only when it does not exist. In generated
// mode it persists its input keys and publishes public trust configuration for
// the Zitadel HelmRelease. Existing credentials are verified, never rotated.
func Run(ctx context.Context, kube client.Client, cfg Config) error {
	if cfg.SecretKey == "" {
		cfg.SecretKey = "key.json"
	}
	issuer, err := url.Parse(cfg.Issuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.Path != "" || issuer.RawQuery != "" || issuer.Fragment != "" || issuer.User != nil {
		return fmt.Errorf("issuer must be an HTTPS origin")
	}
	if cfg.SystemUser == "" || cfg.Username == "" || cfg.Namespace == "" || cfg.SecretName == "" {
		return fmt.Errorf("bootstrap identity and output settings are required")
	}
	existing := &corev1.Secret{}
	err = kube.Get(ctx, types.NamespacedName{Namespace: cfg.Namespace, Name: cfg.SecretName}, existing)
	if err == nil {
		if existing.Labels["zitadel.truvity.io/bootstrap"] != cfg.Username {
			return fmt.Errorf("output Secret exists and is not owned by this bootstrap identity")
		}
		return verify(ctx, issuer, existing.Data[cfg.SecretKey])
	}
	if client.IgnoreNotFound(err) != nil {
		return err
	}
	if cfg.Expires.IsZero() {
		// Zitadel requires an expiry. Default to effectively non-expiring rather
		// than making an installation-specific renewal date a prerequisite.
		cfg.Expires = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
	}
	if !cfg.Expires.After(time.Now().Add(time.Hour)) {
		return fmt.Errorf("machine key expiry must be more than one hour in the future")
	}
	if cfg.GenerateKeys {
		if err := PrepareKeys(ctx, kube, &cfg); err != nil {
			return err
		}
	}
	systemKey, err := privateKey(cfg.SystemKey)
	if err != nil {
		return err
	}
	machineKey, err := privateKey(cfg.MachineKey)
	if err != nil {
		return err
	}
	httpClient := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	request := func(path, method string, body any, org string, result any) error {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		token, err := systemJWT(cfg.Issuer, cfg.SystemUser, systemKey)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, method, cfg.Issuer+path, bytes.NewReader(raw))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		if org != "" {
			req.Header.Set("x-zitadel-orgid", org)
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("bootstrap API connection failed")
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("bootstrap API %s: HTTP %d", path, resp.StatusCode)
		}
		if result == nil {
			return nil
		}
		return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(result)
	}
	var org struct {
		Org struct {
			ID string `json:"id"`
		} `json:"org"`
	}
	if err = request("/admin/v1/orgs/default", "GET", nil, "", &org); err != nil {
		return err
	}
	if org.Org.ID == "" {
		return fmt.Errorf("default organization not found")
	}
	var users struct {
		Result []struct {
			ID      string          `json:"id"`
			Machine json.RawMessage `json:"machine"`
		} `json:"result"`
	}
	if err = request("/management/v1/users/_search", "POST", map[string]any{"queries": []any{map[string]any{"userNameQuery": map[string]string{"userName": cfg.Username, "method": "TEXT_QUERY_METHOD_EQUALS"}}}}, org.Org.ID, &users); err != nil {
		return err
	}
	if len(users.Result) > 1 {
		return fmt.Errorf("ambiguous bootstrap username")
	}
	var userID string
	if len(users.Result) == 1 {
		if len(users.Result[0].Machine) == 0 || string(users.Result[0].Machine) == "null" {
			return fmt.Errorf("bootstrap username belongs to a human user")
		}
		userID = users.Result[0].ID
	} else {
		var created struct {
			UserID string `json:"userId"`
		}
		err = request("/management/v1/users/machine", "POST", map[string]string{"userName": cfg.Username, "name": cfg.Username}, org.Org.ID, &created)
		if err != nil {
			return err
		}
		userID = created.UserID
	}
	if userID == "" {
		return fmt.Errorf("machine user ID missing")
	}
	// Read the exact membership before adding; do not overwrite existing roles.
	var members struct {
		Result []struct {
			UserID string   `json:"userId"`
			Roles  []string `json:"roles"`
		} `json:"result"`
	}
	if err = request("/admin/v1/members/_search", "POST", map[string]any{"queries": []any{map[string]any{"userIdQuery": map[string]string{"userId": userID}}}}, "", &members); err != nil {
		return err
	}
	found := false
	for _, m := range members.Result {
		if m.UserID == userID {
			for _, role := range m.Roles {
				if role == "IAM_OWNER" {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("existing machine membership is not IAM_OWNER; reconcile its permissions explicitly")
			}
		}
	}
	if !found {
		if err = request("/admin/v1/members", "POST", map[string]any{"userId": userID, "roles": []string{"IAM_OWNER"}}, "", nil); err != nil {
			return err
		}
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&machineKey.PublicKey)
	if err != nil {
		return err
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	var key struct {
		ID string `json:"keyId"`
	}
	err = request("/v2/users/"+url.PathEscape(userID)+"/keys", "POST", map[string]any{"publicKey": base64.StdEncoding.EncodeToString(publicPEM), "expirationDate": cfg.Expires.UTC().Format(time.RFC3339)}, org.Org.ID, &key)
	if err != nil {
		return err
	}
	if key.ID == "" {
		return fmt.Errorf("registered key ID missing")
	}
	bundle, err := json.Marshal(map[string]string{"type": "serviceaccount", "keyId": key.ID, "userId": userID, "key": string(cfg.MachineKey)})
	if err != nil {
		return err
	}
	if err = kube.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: cfg.SecretName, Namespace: cfg.Namespace, Labels: map[string]string{"zitadel.truvity.io/bootstrap": cfg.Username}}, Data: map[string][]byte{cfg.SecretKey: bundle}}); err != nil {
		return err
	}
	return verify(ctx, issuer, bundle)
}

func verify(ctx context.Context, issuer *url.URL, bundle []byte) error {
	port := issuer.Port()
	if port == "" {
		port = "443"
	}
	c, err := zitadel.NewClient(ctx, &zitadel.ClientConfig{Domain: issuer.Hostname(), Port: port, KeyJSON: bundle})
	if err != nil {
		return fmt.Errorf("cannot load bootstrapped machine credential")
	}
	_, err = zitadel.VerifyBinding(ctx, c, "iam-owner")
	if err != nil {
		return fmt.Errorf("bootstrapped machine credential failed IAM_OWNER verification; rerun after projections converge")
	}
	return nil
}

func systemJWT(issuer, subject string, key *rsa.PrivateKey) (string, error) {
	encode := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	now := time.Now().Unix()
	message := encode(map[string]string{"alg": "RS256", "typ": "JWT"}) + "." + encode(map[string]any{"iss": subject, "sub": subject, "aud": issuer, "iat": now, "exp": now + 300})
	digest := sha256.Sum256([]byte(message))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return strings.Join([]string{message, base64.RawURLEncoding.EncodeToString(sig)}, "."), nil
}
