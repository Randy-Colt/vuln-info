package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"threat-info/internal/api"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/oapi-codegen/nethttp-middleware"
)

// Validator — кастомный обработчик ошибок валидации запроса. Возвращает
// ошибку 400 при невалидном запросе.
func Validator(swagger *openapi3.T) func(http.Handler) http.Handler {
    return nethttpmiddleware.OapiRequestValidatorWithOptions(swagger, &nethttpmiddleware.Options{
        ErrorHandlerWithOpts: func(ctx context.Context, err error, w http.ResponseWriter, r *http.Request, opts nethttpmiddleware.ErrorHandlerOpts) {
            w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(opts.StatusCode)
			json.NewEncoder(w).Encode(api.ErrorResponse{
				Message: "invalid request",
				Details: new(formatValidationError(err)),
			})
        },
    })
}

func formatValidationError(err error) string {
    var schemaErr *openapi3.SchemaError
    if errors.As(err, &schemaErr) {
        ptr := strings.Join(schemaErr.JSONPointer(), "/")

        if ptr == "" {
            ptr = schemaErr.SchemaField
        }

        if schemaErr.Reason != "" {
            return fmt.Sprintf("%s: %s", ptr, schemaErr.Reason)
        }
        return "/" + ptr
    }
    return err.Error()
}


func FormateRateLimit(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusTooManyRequests)
    _ = json.NewEncoder(w).Encode(api.ErrorResponse{
        Message: "rate limit exceeded",
    })
}