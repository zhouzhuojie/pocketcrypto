# Simple Example

This example demonstrates how to use pocketcrypto with PocketBase.

## Setup

1. Start the server:

```bash
go run main.go
```

2. Create a superadmin via the UI or API:
   - Visit http://127.0.0.1:8090/_/
   - Sign up as superadmin with email `admin@example.com` and password `password123`

## API Endpoints

The field encryption API is available at:

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/field-encryption/apply` | Apply encryption to plaintext fields |
| `POST` | `/api/field-encryption/dry-run` | Preview encryption without changes |
| `GET` | `/api/field-encryption/status/:collection` | Check encryption status |

All endpoints require superadmin authentication.

## Example Request

```bash
# Dry run to preview
curl -X POST http://127.0.0.1:8090/api/field-encryption/dry-run \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"collection": "wallets", "fields": ["private_key"], "batch_size": 100}'

# Apply encryption
curl -X POST http://127.0.0.1:8090/api/field-encryption/apply \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"collection": "wallets", "fields": ["private_key"], "batch_size": 100}'
```

## Environment Variables

Set the encryption key:

```bash
export ENCRYPTION_KEY="your-base64-encoded-32-byte-key"
```
