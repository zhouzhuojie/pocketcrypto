# PocketCrypto

Column-level encryption for PocketBase with post-quantum ML-KEM-768 support.

```go
_, err := pocketcrypto.Register(app, &pocketcrypto.MLKEM768{},
    pocketcrypto.CollectionConfig{Collection: "wallets", Fields: []string{"private_key", "mnemonic"}},
)
```

## Quick Start

```bash
go get github.com/zhouzhuojie/pocketcrypto
```

```go
import "github.com/zhouzhuojie/pocketcrypto"

// One-line setup with automatic hook registration
_, err := pocketcrypto.Register(app, &pocketcrypto.MLKEM768{},
    pocketcrypto.CollectionConfig{Collection: "wallets", Fields: []string{"private_key", "mnemonic"}},
    pocketcrypto.CollectionConfig{Collection: "secrets", Fields: []string{"value"}},
)
```

Set the `ENCRYPTION_KEY` environment variable (32 bytes, base64 encoded):

```bash
export ENCRYPTION_KEY="$(openssl rand -base64 32)"
```

## Example

See [examples/simple/](examples/simple/) for a complete working example:

```bash
cd examples/simple
go run main.go
```

The example demonstrates:
- Setting up PocketBase with encryption hooks
- Configuring ML-KEM-768 post-quantum encryption
- Registering the admin API for field encryption migration

## Gradual Field Encryption Opt-in

Existing plaintext fields can be gradually migrated to encrypted format without downtime:

### 1. Register the Admin API

```go
pocketcrypto.RegisterDefaultFieldEncryptionAPI(app)
```

### 2. Check Encryption Status

```bash
curl http://localhost:8090/api/field-encryption/status/wallets \
  -H "Authorization: YOUR_ADMIN_TOKEN"
```

### 3. Dry-Run First (Preview)

```bash
curl -X POST http://localhost:8090/api/field-encryption/dry-run \
  -H "Content-Type: application/json" \
  -H "Authorization: YOUR_ADMIN_TOKEN" \
  -d '{
    "collection": "wallets",
    "fields": ["private_key"],
    "batch_size": 100
  }'
```

Response shows how many records would be migrated without making changes.

### 4. Apply Encryption

```bash
curl -X POST http://localhost:8090/api/field-encryption/apply \
  -H "Content-Type: application/json" \
  -H "Authorization: YOUR_ADMIN_TOKEN" \
  -d '{
    "collection": "wallets",
    "fields": ["private_key"],
    "batch_size": 100
  }'
```

### Key Behaviors

- **Already encrypted fields**: Skipped
- **Empty/null fields**: Skipped
- **Plaintext fields**: Encrypted and updated
- **Mixed state supported**: Read path handles both encrypted and plaintext
- **Batch processing**: Configurable batch size (default 100)

## Providers

| Provider | Environment | Description |
|----------|-------------|-------------|
| Local | `ENCRYPTION_KEY`, `ENCRYPTION_KEY_OLD` | 32-byte base64 keys (development) |
| AWS KMS | `KEY_PROVIDER=aws-kms`, `AWS_KMS_KEY_ID`, `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | Managed AWS keys |
| Vault | `KEY_PROVIDER=vault`, `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_MOUNT_PATH`, `VAULT_KEY_PATH` | HashiCorp secrets |

```bash
# Local (single key for production, or both keys for rotation)
export ENCRYPTION_KEY="$(openssl rand -base64 32)"
export ENCRYPTION_KEY_OLD="old-key-base64-here"  # during rotation

# AWS KMS (credentials auto-loaded from env, ~/.aws/credentials, or IAM role)
export KEY_PROVIDER=aws-kms
export AWS_KMS_KEY_ID=alias/pocketcrypto-key
export AWS_REGION=us-east-1
# Optional: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

# Vault
export KEY_PROVIDER=vault
export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN=your-token
export VAULT_MOUNT_PATH=secret  # optional, defaults to "secret"
export VAULT_KEY_PATH=pocketcrypto-key  # optional, defaults to "pocketcrypto/encryption-key"
```

## Key Rotation

PocketCrypto supports **lazy key rotation** by default:

### How It Works

1. **Encrypt always uses current key**
2. **Decrypt tries current key first**, falls back to previous key if needed
3. **Old data is automatically re-encrypted on read** (lazy rotation)
4. **Proactive batch migration** available for complete migration

### Local Provider Rotation

```bash
# Before rotation: only current key
export ENCRYPTION_KEY="new-key-base64"

# During rotation: set old key alongside new key
export ENCRYPTION_KEY="new-key-base64"
export ENCRYPTION_KEY_OLD="old-key-base64"

# After rotation: remove old key
export ENCRYPTION_KEY="new-key-base64"
# (unset ENCRYPTION_KEY_OLD)
```

### Production Flow

**Read Path (Automatic Lazy Rotation):**
```
Read Record → Try decrypt with current key → Failed?
  → Try decrypt with previous key → Success?
    → Re-encrypt with current key, save, return plaintext
  → Current key success? Return plaintext
```

**Write Path:**
```
Write Record → Encrypt with current key → Save
  → Works seamlessly during rotation
  → No code changes needed
```

### Proactive Batch Migration

For faster migration or zero reads on first access, use the admin API:

```bash
# Preview changes (dry-run)
curl -X POST http://localhost:8090/api/field-encryption/dry-run \
  -H "Content-Type: application/json" \
  -H "Authorization: YOUR_ADMIN_TOKEN" \
  -d '{"collection": "wallets", "fields": ["private_key"], "batch_size": 100}'

# Apply encryption
curl -X POST http://localhost:8090/api/field-encryption/apply \
  -H "Content-Type: application/json" \
  -H "Authorization: YOUR_ADMIN_TOKEN" \
  -d '{"collection": "wallets", "fields": ["private_key"], "batch_size": 100}'
```

Or register the API in your app:

```go
pocketcrypto.RegisterDefaultFieldEncryptionAPI(app)
```

### Rotation Checklist

1. **Before rotation:** Store new key (Local: ENCRYPTION_KEY, KMS/Vault: in service)
2. **During rotation:** Reads automatically lazy-rotate old data
3. **After rotation:** Remove old key (ENCRYPTION_KEY_OLD) when all data migrated

## What You Can't Do

- Search or filter encrypted fields
- Index encrypted fields for fast lookups
- Compare encrypted values

## License

Apache 2.0
