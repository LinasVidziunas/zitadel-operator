package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/truvity/zitadel-operator/internal/bootstrap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func main() {
	var cfg bootstrap.Config
	var systemKey, machineKey, expiry string
	var timeout time.Duration
	flag.StringVar(&cfg.Issuer, "issuer", "", "HTTPS Zitadel origin")
	flag.StringVar(&cfg.SystemUser, "system-user", "gitops-bootstrap", "Configured SystemAPIUsers identity")
	flag.StringVar(&cfg.Username, "username", "zitadel-operator", "Machine username to provision")
	flag.StringVar(&cfg.Namespace, "namespace", "zitadel-operator", "Output Secret namespace")
	flag.StringVar(&cfg.SecretName, "secret", "zitadel-admin-sa", "Output Secret name")
	flag.StringVar(&cfg.SecretKey, "output-key", "key.json", "Output Secret data key")
	flag.StringVar(&systemKey, "system-key", "", "Mounted system-user private PEM")
	flag.StringVar(&machineKey, "machine-key", "", "Mounted user-supplied machine private PEM")
	flag.BoolVar(&cfg.GenerateKeys, "generate-keys", true, "Generate and retain bootstrap keys in Kubernetes")
	flag.StringVar(&cfg.KeysSecret, "keys-secret", "zitadel-operator-bootstrap-keys", "Generated input keys Secret name")
	flag.StringVar(&cfg.PublicNamespace, "public-namespace", "", "Zitadel HelmRelease namespace")
	flag.StringVar(&cfg.PublicConfigMap, "public-configmap", "zitadel-operator-bootstrap-public", "Generated public Helm values ConfigMap")
	flag.StringVar(&expiry, "expires", "", "Optional machine key expiry (RFC3339); default year 9999")
	flag.DurationVar(&timeout, "timeout", 10*time.Minute, "Wait for server trust configuration and IAM projections")
	flag.Parse()
	if err := run(cfg, systemKey, machineKey, expiry, timeout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("Operator identity provisioned and IAM_OWNER verified")
}

func run(cfg bootstrap.Config, systemKey, machineKey, expiry string, timeout time.Duration) error {
	var err error
	if expiry != "" {
		cfg.Expires, err = time.Parse(time.RFC3339, expiry)
		if err != nil {
			return fmt.Errorf("--expires must be RFC3339")
		}
	}
	if timeout <= 0 {
		return fmt.Errorf("--timeout must be positive")
	}
	if cfg.GenerateKeys {
		if systemKey != "" || machineKey != "" {
			return fmt.Errorf("mounted keys require --generate-keys=false")
		}
	} else {
		cfg.SystemKey, err = os.ReadFile(systemKey)
		if err != nil {
			return fmt.Errorf("cannot read system key")
		}
		cfg.MachineKey, err = os.ReadFile(machineKey)
		if err != nil {
			return fmt.Errorf("cannot read machine key")
		}
	}
	scheme := runtime.NewScheme()
	if err = corev1.AddToScheme(scheme); err != nil {
		return err
	}
	restConfig, err := ctrl.GetConfig()
	if err != nil {
		return err
	}
	kube, err := client.New(restConfig, client.Options{Scheme: scheme})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		if err = bootstrap.Run(ctx, kube, cfg); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("bootstrap did not converge before timeout: %w", err)
		case <-ticker.C:
		}
	}
}
