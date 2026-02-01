# PocketCrypto - Column-Level Encryption for PocketBase

A Go library providing column-level encryption at rest for PocketBase applications, with support for AES-256-GCM authenticated encryption, post-quantum ML-KEM-768 key encapsulation, and multiple key management providers.

## Features

- **Post-Quantum ML-KEM-768** (Default): FIPS 203 compliant key encapsulation using Go 1.24's `crypto/mlkem`
- **AES-256-GCM Encryption**: Industry-standard authenticated encryption for sensitive data
- **Multiple Key Providers**: Local (env var), AWS KMS, and HashiCorp Vault support
- **PocketBase Hooks Integration**: Automatic encryption on create/update, decryption on view
- **Key Rotation**: Lazy rotation (on-read) and batch rotation for proactive migration
- **Batch Processing**: Efficient batch processing with configurable size for large datasets

## Installation

```bash
go get github.com/yourusername/pocketcrypto
```

## Quick Start

### One-Call Setup (Recommended)

```go
package main

import (
    "context"
    "log"
    "os"

    "github.com/pocketbase/pocketbase"
    "github.com/yourusername/pocketcrypto"
)

func main() {
    os.Setenv("ENCRYPTION_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")

    app := pocketbase.New()

    _, err := pocketcrypto.Register(context.Background(), app, &pocketcrypto.MLKEM768{}, []pocketcrypto.CollectionConfig{
        {Collection: "wallets", Fields: []string{"private_key", "mnemonic", "seed_phrase"}},
        {Collection: "accounts", Fields: []string{"api_key", "api_secret"}},
    })
    if err != nil {
        log.Fatal(err)
    }

    app.Start()
}
```

### Builder Pattern (Advanced)

For fine-grained control, use the builder pattern:

```go
import "github.com/yourusername/pocketcrypto"

// Create custom provider
provider, err := pocketcrypto.NewAWSKMSProvider(context.Background(), "alias/my-key")
if err != nil {
    log.Fatal(err)
}

hooks := pocketcrypto.NewEncryptionHooks(app, &pocketcrypto.AES256GCM{}, provider)
hooks.AddCollection("wallets", "private_key")
hooks.AddCollection("secrets", "value")
hooks.Register()
```

## Generating Encryption Keys

### Local Provider (Environment Variable)

The local provider requires a 32-byte (256-bit) key encoded in base64:

```bash
# Generate a random 32-byte key and encode it
openssl rand -base64 32
# Example output: MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=

# Set the environment variable
export ENCRYPTION_KEY="MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
```

### ML-KEM-768 Key Generation

For post-quantum encryption, generate a key pair:

```go
import "github.com/yourusername/pocketcrypto"

// Generate a new ML-KEM-768 key pair
mlkem, err := pocketcrypto.NewMLKEM768()
if err != nil {
    log.Fatal(err)
}

// Store the decapsulation key securely (for decryption)
decapsulationKey := mlkem.DecapsulationKeyBytes()

// Share the encapsulation key with parties that need to encrypt data
encapsulationKey := mlkem.EncapsulationKeyBytes()
```

### From Seed (Deterministic Key Generation)

Generate a key pair from a seed for reproducible key derivation:

```go
import "github.com/yourusername/pocketcrypto"

// Seed must be 64 bytes of random data
seed := make([]byte, 64)
if _, err := rand.Read(seed); err != nil {
    log.Fatal(err)
}

mlkem, err := pocketcrypto.NewMLKEM768FromSeed(seed)
if err != nil {
    log.Fatal(err)
}
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
