package main

import (
	"fmt"
	"log"
	"os"

	"github.com/pocketbase/pocketbase"

	"github.com/zhouzhuojie/pocketcrypto"
)

func main() {
	// Set encryption key (must be 32 bytes, base64 encoded)
	// This is a sample key for testing - in production use a secure key
	os.Setenv("ENCRYPTION_KEY", "dGVzdC1lbmNyeXB0aW9uLWtleS0zMi1ieXRlcyEhISE=") // "test-encryption-key-32-bytes!!!!"

	fmt.Println(">>> STARTING EXAMPLE <<<")
	app := pocketbase.New()

	// Configure encryption with ML-KEM-768 (post-quantum)
	fmt.Println(">>> CALLING Register <<<")
	encrypter, err := pocketcrypto.NewMLKEM768()
	if err != nil {
		log.Fatalf("Failed to create ML-KEM-768 encrypter: %v", err)
	}
	hooks, err := pocketcrypto.Register(app, encrypter,
		pocketcrypto.CollectionConfig{
			Collection: "wallets",
			Fields:     []string{"private_key", "mnemonic"},
		},
	)
	if err != nil {
		log.Fatalf("Failed to register encryption hooks: %v", err)
	}
	fmt.Printf(">>> Register done, hooks registered for: %v\n", hooks)

	// Register the field encryption API with superadmin authentication
	pocketcrypto.RegisterDefaultFieldEncryptionAPI(app)

	// Start the server
	// Default superadmin: admin@example.com / password123
	fmt.Println(">>> STARTING SERVER <<<")
	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}
