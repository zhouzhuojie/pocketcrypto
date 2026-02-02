# PocketCrypto

Column-level encryption for PocketBase with post-quantum ML-KEM-768 support.

**Value:** Encrypt sensitive fields at rest without changing your PocketBase API or client code. Supports gradual opt-in for existing plaintext data and zero-downtime key rotation.

```go
// One-line setup with automatic hook registration
_, err := pocketcrypto.Register(app, &pocketcrypto.MLKEM768{},
    pocketcrypto.CollectionConfig{Collection: "wallets", Fields: []string{"private_key", "mnemonic"}},
)
```

## Quick Start

```bash
go get github.com/zhouzhuojie/pocketcrypto
```

Set `ENCRYPTION_KEY` (32 bytes, base64):

```bash
export ENCRYPTION_KEY="$(openssl rand -base64 32)"
```

See [examples/simple/](examples/simple/) for a working example.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Encrypter (Interface)                    │
│  ┌─────────────────────┐    ┌─────────────────────┐        │
│  │      AES256GCM      │    │       MLKEM768      │        │
│  └──────────┬──────────┘    └──────────┬──────────┘        │
│             │                         │                     │
│             ▼                         ▼                     │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                    KeyProvider                         │  │
│  ├────────────────┬─────────────────┬──────────────────┤  │
│  │    Local       │   AWS KMS       │      Vault       │  │
│  └────────────────┴─────────────────┴──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

Both encrypters use `KeyProvider` identically:
- **Encrypt:** `provider.GetKey(keyID)` → stores `provider.KeyID()` in envelope
- **Decrypt:** reads `envelope.KeyID` → `provider.GetKey(envelope.KeyID)`

## Providers

| Provider | Env Vars | Use Case |
|----------|----------|----------|
| Local | `ENCRYPTION_KEY`, `ENCRYPTION_KEY_OLD` | Development, simple deployments |
| AWS KMS | `KEY_PROVIDER=aws-kms`, `AWS_KMS_KEY_ID`, `AWS_REGION` | Production with AWS |
| Vault | `KEY_PROVIDER=vault`, `VAULT_ADDR`, `VAULT_TOKEN` | Enterprise with HashiCorp Vault |

```bash
# Local (both keys during rotation)
export ENCRYPTION_KEY="$(openssl rand -base64 32)"
export ENCRYPTION_KEY_OLD="old-key-base64"  # optional, during rotation

# AWS KMS
export KEY_PROVIDER=aws-kms
export AWS_KMS_KEY_ID=alias/pocketcrypto-key
export AWS_REGION=us-east-1

# Vault
export KEY_PROVIDER=vault
export VAULT_ADDR="https://vault.company.com"
export VAULT_TOKEN=your-token
```

## Key Rotation

PocketCrypto uses **lazy rotation** - old data is re-encrypted on read.

**Rotation flow:**
```
1. Deploy new key (ENCRYPTION_KEY=new, ENCRYPTION_KEY_OLD=old)
2. Read → decrypt fails with current → try previous → succeeds
3. On success: re-encrypt with current key, save
4. After all reads: remove ENCRYPTION_KEY_OLD
```

No code changes required. Works seamlessly during rotation.

## Gradual Field Opt-in

Migrate existing plaintext fields without downtime:

```bash
# Register admin API
pocketcrypto.RegisterDefaultFieldEncryptionAPI(app)

# Dry-run first
curl -X POST http://localhost:8090/api/field-encryption/dry-run \
  -H "Authorization: YOUR_ADMIN_TOKEN" \
  -d '{"collection": "wallets", "fields": ["private_key"], "batch_size": 100}'

# Apply
curl -X POST http://localhost:8090/api/field-encryption/apply \
  -H "Authorization: YOUR_ADMIN_TOKEN" \
  -d '{"collection": "wallets", "fields": ["private_key"], "batch_size": 100}'
```

Behaviors:
- Already encrypted → skipped
- Empty/null → skipped
- Plaintext → encrypted
- Mixed state supported (read path handles both)

## Limitations

Encrypted fields cannot be:
- Searched or filtered
- Indexed for fast lookups
- Compared for equality

## License

Apache 2.0
