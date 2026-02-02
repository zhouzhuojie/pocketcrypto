package pocketcrypto

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
)

// RegisterFieldEncryptionAPI registers the field encryption endpoints on a PocketBase app.
//
// The authenticator function is called to verify superadmin access.
// Returns an error if registration fails.
func RegisterFieldEncryptionAPI(app *pocketbase.PocketBase, authenticator func(*core.RequestEvent) bool) error {
	// Create encrypter and provider
	provider, err := newProvider("")
	if err != nil {
		return err
	}

	fieldEncrypter := newFieldEncrypter(app, &AES256GCM{}, provider)

	// POST /api/field-encryption/apply - Apply encryption to plaintext fields
	app.OnServe().BindFunc(func(se *core.ServeEvent) error {
		se.Router.POST("/api/field-encryption/apply", func(re *core.RequestEvent) error {
			// Superadmin check
			if authenticator != nil && !authenticator(re) {
				return re.JSON(http.StatusForbidden, map[string]string{
					"error": "superadmin access required",
				})
			}

			var req FieldEncryptionRequest
			if err := json.NewDecoder(re.Request.Body).Decode(&req); err != nil {
				return re.JSON(http.StatusBadRequest, map[string]string{
					"error": "invalid request body",
				})
			}

			if req.Collection == "" {
				return re.JSON(http.StatusBadRequest, map[string]string{
					"error": "collection is required",
				})
			}

			if len(req.Fields) == 0 {
				return re.JSON(http.StatusBadRequest, map[string]string{
					"error": "fields is required",
				})
			}

			result, err := fieldEncrypter.Apply(context.Background(), req)
			if err != nil {
				return re.JSON(http.StatusInternalServerError, map[string]string{
					"error": err.Error(),
				})
			}

			return re.JSON(http.StatusOK, result)
		})
		return se.Next()
	})

	// POST /api/field-encryption/dry-run - Preview encryption without changes
	app.OnServe().BindFunc(func(se *core.ServeEvent) error {
		se.Router.POST("/api/field-encryption/dry-run", func(re *core.RequestEvent) error {
			// Superadmin check
			if authenticator != nil && !authenticator(re) {
				return re.JSON(http.StatusForbidden, map[string]string{
					"error": "superadmin access required",
				})
			}

			var req FieldEncryptionRequest
			if err := json.NewDecoder(re.Request.Body).Decode(&req); err != nil {
				return re.JSON(http.StatusBadRequest, map[string]string{
					"error": "invalid request body",
				})
			}

			// Set dry run mode
			req.DryRun = true

			if req.Collection == "" {
				return re.JSON(http.StatusBadRequest, map[string]string{
					"error": "collection is required",
				})
			}

			if len(req.Fields) == 0 {
				return re.JSON(http.StatusBadRequest, map[string]string{
					"error": "fields is required",
				})
			}

			result, err := fieldEncrypter.Apply(context.Background(), req)
			if err != nil {
				return re.JSON(http.StatusInternalServerError, map[string]string{
					"error": err.Error(),
				})
			}

			return re.JSON(http.StatusOK, result)
		})
		return se.Next()
	})

	// GET /api/field-encryption/status/:collection - Check encryption status
	app.OnServe().BindFunc(func(se *core.ServeEvent) error {
		se.Router.GET("/api/field-encryption/status/{collection}", func(re *core.RequestEvent) error {
			// Superadmin check
			if authenticator != nil && !authenticator(re) {
				return re.JSON(http.StatusForbidden, map[string]string{
					"error": "superadmin access required",
				})
			}

			collectionName := chi.URLParam(re.Request, "collection")
			if collectionName == "" {
				return re.JSON(http.StatusBadRequest, map[string]string{
					"error": "collection is required",
				})
			}

			status, err := fieldEncrypter.Status(context.Background(), collectionName)
			if err != nil {
				return re.JSON(http.StatusInternalServerError, map[string]string{
					"error": err.Error(),
				})
			}

			return re.JSON(http.StatusOK, status)
		})
		return se.Next()
	})

	return nil
}

// RegisterDefaultFieldEncryptionAPI registers the field encryption API with default superadmin authentication.
func RegisterDefaultFieldEncryptionAPI(app *pocketbase.PocketBase) error {
	return RegisterFieldEncryptionAPI(app, isSuperadmin)
}

func isSuperadmin(e *core.RequestEvent) bool {
	if e.Auth == nil {
		return false
	}
	return e.Auth.IsSuperuser()
}
