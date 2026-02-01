# PocketCrypto

Column-level encryption for PocketBase.

```go
_, err := pocketcrypto.Register(app, &pocketcrypto.AES256GCM{},
    pocketcrypto.CollectionConfig{Collection: "wallets", Fields: []string{"private_key", "mnemonic"}},
)
```

## Quick Start

```bash
go get github.com/zhouzhuojie/pocketcrypto
```

```go
import "github.com/zhouzhuojie/pocketcrypto"

_, err := pocketcrypto.Register(app, &pocketcrypto.AES256GCM{},
    pocketcrypto.CollectionConfig{Collection: "wallets", Fields: []string{"private_key", "mnemonic"}},
    pocketcrypto.CollectionConfig{Collection: "secrets", Fields: []string{"value"}},
)
```

## Providers

| Provider | Environment | Description |
|----------|-------------|-------------|
| Local | `ENCRYPTION_KEY` | 32-byte base64 key (development) |
| AWS KMS | `KEY_PROVIDER=aws-kms`, `AWS_KMS_KEY_ID` | Managed AWS keys |
| Vault | `KEY_PROVIDER=vault`, `VAULT_TOKEN` | HashiCorp secrets |

```bash
# Local
export ENCRYPTION_KEY="$(openssl rand -base64 32)"

# AWS KMS
export KEY_PROVIDER=aws-kms
export AWS_KMS_KEY_ID=alias/pocketcrypto-key

# Vault
export KEY_PROVIDER=vault
export VAULT_TOKEN=your-token
```

## Algorithms

| Algorithm | Speed | Use Case |
|-----------|-------|----------|
| AES-256-GCM | ~150 MB/s | Most data |
| ML-KEM-768 | ~25 KB/s | High-value secrets |

```go
// Standard encryption (recommended)
_, err := pocketcrypto.Register(app, &pocketcrypto.AES256GCM{}, config)

// Post-quantum security
_, err := pocketcrypto.Register(app, &pocketcrypto.MLKEM768{}, config)
```

## Key Rotation

```go
// Lazy rotation - re-encrypts on read
rotator := pocketcrypto.NewKeyRotator(provider, &pocketcrypto.MLKEM768{})
_, newEncrypted, rotated, _ := rotator.LazyDecrypt(old, provider)

// Batch migration
rotator.RotateCollection(ctx, records, 100, func(r *pocketcrypto.EncryptedRecord) error {
    return db.Save(r)
})
```

## What You Can't Do

- Search or filter encrypted fields
- Index encrypted fields for fast lookups
- Compare encrypted values

## License

Apache 2.0
