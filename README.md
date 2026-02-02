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

## File Structure

```
pocketcrypto/
├── lib.go         # Main entry point: Register(), public APIs, interfaces, types
├── algos.go       # Encryption algorithms: AES256GCM, MLKEM768
├── providers.go   # Key providers: LocalProvider, AWSKMSProvider, VaultProvider
├── rotator.go     # Key rotation logic: KeyRotator
├── api.go         # REST API endpoints for field encryption
├── *_test.go      # Test files
```

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                      Encrypter (Interface)                     │
│  ┌─────────────────────┐         ┌─────────────────────┐       │
│  │      AES256GCM      │         │       MLKEM768      │       │
│  └──────────┬──────────┘         └──────────┬──────────┘       │
│             │                               │                  │
│             ▼                               ▼                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                        KeyProvider                      │   │
│  ├────────────────┬──────────────────┬─────────────────────┤   │
│  │     Local      │    AWS KMS       │        Vault        │   │
│  └────────────────┴──────────────────┴─────────────────────┘   │
└────────────────────────────────────────────────────────────────┘
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

## Environment Variables

| Variable | Provider | Required | Description |
|----------|----------|----------|-------------|
| `KEY_PROVIDER` | All | No | Provider type: `local`, `aws-kms`, `vault`. Defaults to `local`. |
| `ENCRYPTION_KEY` | Local | Yes | Current master key (32 bytes, base64 encoded). |
| `ENCRYPTION_KEY_OLD` | Local | No | Previous key for lazy rotation. |
| `AWS_KMS_KEY_ID` | AWS KMS | Yes | KMS key ID or alias (e.g., `alias/pocketcrypto-key`). |
| `AWS_REGION` | AWS KMS | No | AWS region. Uses SDK default if not set. |
| `VAULT_ADDR` | Vault | Yes | Vault server address (e.g., `https://vault.company.com`). |
| `VAULT_TOKEN` | Vault | Yes | Vault authentication token. |
| `VAULT_MOUNT_PATH` | Vault | No | Vault secrets mount path. Defaults to `secret`. |
| `VAULT_KEY_PATH` | Vault | No | Vault key path within mount. Defaults to `pocketcrypto/encryption-key`. |

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

## Extending PocketCrypto

### Bring Your Own Algorithm (No Upstream Changes)

Implement the `Encrypter` interface and pass it to `Register()`:

```go
import "github.com/zhouzhuojie/pocketcrypto"

type MyAlgorithm struct{}

func (a *MyAlgorithm) Encrypt(plaintext string, provider pocketcrypto.KeyProvider) (string, error) {
    // Your encryption logic
}

func (a *MyAlgorithm) Decrypt(encrypted string, provider pocketcrypto.KeyProvider) (string, error) {
    // Your decryption logic
}

func (a *MyAlgorithm) Algorithm() string {
    return "MyAlgorithm"
}

func (a *MyAlgorithm) KeySize() int {
    return 32
}

// Use it:
pocketcrypto.Register(app, &MyAlgorithm{},
    pocketcrypto.CollectionConfig{Collection: "wallets", Fields: []string{"secret"}},
)
```

Use `DataEnvelope` to store encryption metadata for compatibility with lazy rotation.

### Bring Your Own Key Provider (No Upstream Changes)

Implement `KeyProvider` and register with `RegisterProvider()`:

```go
import "github.com/zhouzhuojie/pocketcrypto"

type MyProvider struct{ secret string }

func (p *MyProvider) GetKey(keyID string) ([]byte, error) {
    return []byte(p.secret), nil
}

func (p *MyProvider) EncryptKey(key []byte, keyID string) ([]byte, error) {
    return key, nil
}

func (p *MyProvider) DecryptKey(encryptedKey []byte) ([]byte, error) {
    return encryptedKey, nil
}

func (p *MyProvider) KeyID() string {
    return "my-provider://default"
}

func newMyProvider() (pocketcrypto.KeyProvider, error) {
    return &MyProvider{secret: "my-key"}, nil
}

func init() {
    pocketcrypto.RegisterProvider("my-provider", newMyProvider)
}
```

Set `KEY_PROVIDER=my-provider` environment variable to use your provider.

For rotation support, also implement `RotatableProvider`:

```go
type RotatableProvider interface {
    KeyProvider
    RotateKey(ctx context.Context) (string, error)
    GetKeyVersion(keyID string, version int) ([]byte, error)
    CurrentKeyVersion() int
}
```

### Contributing to Upstream

To add new algorithms or providers to the package itself:

1. **Algorithms**: Add to `algos.go` with `Encrypt`, `Decrypt`, `Algorithm()`, `KeySize()` methods
2. **Providers**: Add factory to `providers.go` and register in `lib.go` init()
3. Add provider type constant: `const ProviderTypeX ProviderType = "x"`
4. Add tests in respective `_test.go` files

## Limitations

Encrypted fields cannot be:
- Searched or filtered
- Indexed for fast lookups
- Compared for equality

## License

Apache 2.0
