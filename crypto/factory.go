package crypto

import (
	"context"
	"os"
)

// ProviderType defines the type of key provider to use.
type ProviderType string

const (
	// ProviderTypeLocal uses environment variable for key storage.
	ProviderTypeLocal ProviderType = "local"
	// ProviderTypeAWSKMS uses AWS Key Management Service.
	ProviderTypeAWSKMS ProviderType = "aws-kms"
	// ProviderTypeVault uses HashiCorp Vault.
	ProviderTypeVault ProviderType = "vault"
)

// NewProvider creates a KeyProvider based on the specified type.
// The provider type is determined by the KEY_PROVIDER environment variable
// or can be passed directly.
func NewProvider(ctx context.Context, providerType ProviderType) (KeyProvider, error) {
	if providerType == "" {
		providerType = ProviderType(os.Getenv("KEY_PROVIDER"))
	}

	// Default to local provider
	if providerType == "" {
		providerType = ProviderTypeLocal
	}

	switch providerType {
	case ProviderTypeLocal:
		return NewLocalProvider()
	case ProviderTypeAWSKMS:
		return NewAWSKMSProviderFromEnv(ctx)
	case ProviderTypeVault:
		return NewVaultProvider()
	default:
		return nil, ErrUnknownProviderType
	}
}

// NewProviderFromEnv creates a KeyProvider using the KEY_PROVIDER
// environment variable.
func NewProviderFromEnv(ctx context.Context) (KeyProvider, error) {
	return NewProvider(ctx, "")
}

// MustProvider creates a KeyProvider and panics on error.
// This is useful for initialization in main().
func MustProvider(ctx context.Context, providerType ProviderType) KeyProvider {
	provider, err := NewProvider(ctx, providerType)
	if err != nil {
		panic(err)
	}
	return provider
}

// ErrUnknownProviderType is returned when an unknown provider type is specified.
var ErrUnknownProviderType = &UnknownProviderTypeError{}

// UnknownProviderTypeError is an error for unknown provider types.
type UnknownProviderTypeError struct{}

func (e *UnknownProviderTypeError) Error() string {
	return "unknown key provider type"
}
