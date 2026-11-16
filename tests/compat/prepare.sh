#!/usr/bin/env bash
set -euo pipefail
# Synthetic keys exist only in the disposable compose volume, never the checkout.
openssl req -x509 -newkey rsa:2048 -nodes -keyout /state/tls.key -out /state/tls.crt -days 1 -subj /CN=zitadel -addext subjectAltName=DNS:zitadel >/dev/null 2>&1
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /state/system.pem >/dev/null 2>&1
openssl pkey -in /state/system.pem -pubout -out /state/system.pub >/dev/null 2>&1
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /state/machine.pem >/dev/null 2>&1
chmod 644 /state/*
cat > /state/zitadel.yaml <<'EOF'
ExternalDomain: zitadel
ExternalPort: 8080
ExternalSecure: true
TLS:
  Enabled: true
  CertPath: /state/tls.crt
  KeyPath: /state/tls.key
Database:
  Postgres:
    Host: db
    Port: 5432
    Database: zitadel
    User:
      Username: zitadel
      Password: disposable-test-password
      SSL:
        Mode: disable
    Admin:
      Username: postgres
      Password: disposable-test-password
      SSL:
        Mode: disable
FirstInstance:
  Org:
    Name: Compat
    Human:
      UserName: test-admin
      Password: Disposable-Test-Password-123!
      PasswordChangeRequired: false
SystemAPIUsers:
  gitops-bootstrap:
    Path: /state/system.pub
    Memberships:
      - MemberType: System
        Roles: [IAM_OWNER, ORG_OWNER]
EOF
