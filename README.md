# PocketCrypto - Column-Level Encryption for PocketBase

A Go library providing column-level encryption at rest for PocketBase applications.

## One-Call Setup

```go
_, err := pocketcrypto.Register(app, &pocketcrypto.AES256GCM{},
    pocketcrypto.CollectionConfig{Collection: "wallets", Fields: []string{"private_key", "mnemonic"}},
    pocketcrypto.CollectionConfig{Collection: "secrets", Fields: []string{"value"}},
)
```

## Key Providers

### Local Provider (Default)

Simple environment variable-based key management. Best for development.

```bash
# Generate a 32-byte key
openssl rand -base64 32
# Example: MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=

# Set environment variable
export ENCRYPTION_KEY="MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
```

```go
// Uses ENCRYPTION_KEY automatically
_, err := pocketcrypto.Register(app, &pocketcrypto.AES256GCM{},
    pocketcrypto.CollectionConfig{Collection: "secrets", Fields: []string{"value"}},
)
```

### AWS KMS Provider

Managed key service with automatic key rotation and audit logging.

```bash
# Create a KMS key
aws kms create-key --key-spec AES_256 --origin AWS_KMS
# Note the KeyId and create an alias

# Set environment variables
export KEY_PROVIDER="aws-kms"
export AWS_KMS_KEY_ID="alias/pocketcrypto-key"
# AWS credentials from environment, ~/.aws/credentials, or IAM role
```

```go
// Configure via environment - KEY_PROVIDER=aws-kms, AWS_KMS_KEY_ID=...
_, err := pocketcrypto.Register(app, &pocketcrypto.AES256GCM{},
    pocketcrypto.CollectionConfig{Collection: "wallets", Fields: []string{"private_key"}},
)
```

### HashiCorp Vault Provider

Enterprise secrets management with fine-grained access control.

```bash
# Start Vault
vault server -dev
export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="dev-token"

# Store encryption key
vault kv put secret/pocketcrypto key="$(openssl rand -base64 32)"

# Configure provider
export KEY_PROVIDER="vault"
export VAULT_TOKEN="your-token"
```

```go
// Configure via environment - KEY_PROVIDER=vault, VAULT_TOKEN=...
_, err := pocketcrypto.Register(app, &pocketcrypto.AES256GCM{},
    pocketcrypto.CollectionConfig{Collection: "secrets", Fields: []string{"api_key"}},
)
```

## Encryption Algorithms

### AES-256-GCM

Fast, industry-standard encryption for most use cases.

```go
_, err := pocketcrypto.Register(app, &pocketcrypto.AES256GCM{},
    pocketcrypto.CollectionConfig{Collection: "wallets", Fields: []string{"private_key"}},
)
```

### ML-KEM-768

Post-quantum encryption. Slower but protects against future quantum attacks.

```go
_, err := pocketcrypto.Register(app, &pocketcrypto.MLKEM768{},
    pocketcrypto.CollectionConfig{Collection: "high_value", Fields: []string{"seed_phrase"}},
)
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Encryption Interface                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │
│  │   AES-256   │  │  ML-KEM768  │  │  KeyProvider    │  │
│  │   GCM       │  │ (Default)   │  │  Interface      │  │
│  │             │  │  (Go 1.24)  │  │                 │  │
│  └──────┬──────┘  └──────┬──────┘  └────────┬────────┘  │
│         │                │                  │           │
│         └────────────────┴──────────────────┘           │
│                          │                              │
│                    ┌─────▼─────┐                        │
│                    │  Pocket   │                        │
│                    │  Base     │                        │
│                    │  Hooks    │                        │
│                    └─────┬─────┘                        │
└──────────────────────────┼────────────────────── ───────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
         ┌────────┐  ┌─────────┐  ┌──────────────┐
         │  AES   │  │ ML-KEM  │  │  Key Rotation│
         │  GCM   │  │  768    │  │  (Lazy/Batch)│
         └────────┘  └─────────┘  └──────────────┘
```

## Key Rotation

### Lazy Rotation (Recommended)

Lazy rotation automatically re-encrypts data with the new key when it's accessed:

```go
rotator := pocketcrypto.NewKeyRotator(provider, &pocketcrypto.MLKEM768{})

// When decrypting old data, it automatically re-encrypts with new key
plaintext, newEncrypted, rotated, err := rotator.LazyDecrypt(oldEncrypted, provider)
if rotated {
    // Save newEncrypted back to database
    saveToDatabase(recordID, newEncrypted)
}
```

### Batch Rotation (For Proactive Migration)

Rotate all records in batches for complete key migration:

```go
rotator := pocketcrypto.NewKeyRotator(provider, &pocketcrypto.MLKEM768{})

records := []pocketcrypto.EncryptedRecord{
    {ID: "1", EncryptedFields: map[string]string{"private_key": "..."}},
    {ID: "2", EncryptedFields: map[string]string{"private_key": "..."}},
    // ... more records
}

migrated, skipped, err := rotator.RotateCollection(
    context.Background(),
    records,
    100, // batch size
    func(record *pocketcrypto.EncryptedRecord) error {
        return database.Save(record) // Persist rotated record
    },
)
fmt.Printf("Migrated: %d, Skipped: %d\n", migrated, skipped)
```

## Benchmark Results

Performance benchmarks on Linux x86_64:

### AES-256-GCM

| Operation | Size | Time | Throughput |
|-----------|------|------|------------|
| Encrypt | 32 bytes | ~2 μs | 16 MB/s |
| Decrypt | 32 bytes | ~5 μs | 6 MB/s |
| Encrypt | 256 bytes | ~3 μs | 85 MB/s |
| Decrypt | 256 bytes | ~9 μs | 28 MB/s |
| Encrypt | 1 KB | ~7 μs | 147 MB/s |
| Decrypt | 1 KB | ~21 μs | 49 MB/s |
| Encrypt | 4 KB | ~23 μs | 177 MB/s |
| Decrypt | 4 KB | ~66 μs | 61 MB/s |
| Baseline (no encryption) | 256 bytes | ~90 ns | 2,800 MB/s |

### ML-KEM-768 (Post-Quantum)

| Operation | Size | Time | Throughput |
|-----------|------|------|------------|
| Encapsulate | 32 bytes | ~1.2 ms | ~26 KB/s |
| Decapsulate | 32 bytes | ~0.8 ms | ~40 KB/s |
| Hybrid Encrypt | 32 bytes | ~1.3 ms | ~25 KB/s |

**Note**: ML-KEM-768 is ~500x slower than AES-256-GCM but provides post-quantum security. Use for high-value, long-term secrets.

Run benchmarks:

```bash
# AES-256-GCM benchmarks
go test ./... -run=^$ -bench=BenchmarkAES256 -benchmem

# ML-KEM-768 benchmarks
go test ./... -run=^$ -bench=BenchmarkMLKEM -benchmem
```

## Limitations

1. **Encrypted Field Queries**: Cannot search or filter encrypted fields. Plaintext comparison and range queries are not supported.

2. **Encrypted Field Indexing**: Indexes on encrypted fields are useless. Consider storing a hash of the plaintext for lookups (with awareness of hash vulnerabilities).

3. **Field Size Increase**: Encrypted data is larger than plaintext (~28 bytes overhead for AES-256-GCM, ~1KB+ for ML-KEM-768 encapsulated keys).

4. **ML-KEM Key Management**: ML-KEM encapsulation keys must be securely stored or rotated periodically for forward secrecy.

5. **No Built-in Key Versioning**: The current implementation does not track key versions. Old keys must be stored for lazy rotation to work.

6. **PocketBase Version Dependency**: Requires PocketBase v0.22.0+. Later versions may have API changes.

7. **Memory Usage**: Large batch operations require holding all records in memory. Use smaller batch sizes for memory-constrained environments.

8. **Concurrent Access**: While encryption is thread-safe, concurrent write access to the same record may cause race conditions.

## Development

```bash
# Run all tests
go test ./... -v

# Run with coverage
go test ./... -cover -coverprofile=coverage.out

# Run benchmarks
go test ./... -bench=. -benchmem

# Run linter (install first: curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh)
golangci-lint run ./...
```

## Project Structure

```
pocketcrypto/
├── aes256.go              # AES-256-GCM implementation
├── mlkem.go               # ML-KEM-768 implementation
├── interface.go           # KeyProvider & Encrypter interfaces, types
├── local_provider.go      # Environment variable provider
├── aws_kms_provider.go    # AWS KMS provider
├── vault_provider.go      # HashiCorp Vault provider
├── rotator.go             # Key rotation logic
├── encryption.go          # PocketBase hooks registration
├── *_test.go              # Unit tests
├── go.mod
└── .gitignore
```

## Security Considerations

1. **Key Management**: Use AWS KMS or HashiCorp Vault in production
2. **Key Rotation**: Implement regular key rotation for sensitive data
3. **Audit Logging**: Log all encryption/decryption operations
4. **Access Control**: Restrict access to encrypted fields via PocketBase rules
5. **Backup Encryption**: Ensure backups are also encrypted

## License

Apache 2.0
