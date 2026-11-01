package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/oapi-codegen/nethttp-middleware"

	"threat-info/internal/api"
	"threat-info/internal/service"
	"threat-info/internal/storage/sqlite"
)

const validMD5 = "d41d8cd98f00b204e9800998ecf8427e"

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	if testing.Short() {
		t.Skip("integration test")
	}
	path := filepath.Join(t.TempDir(), "test.db")
	store, err := sqlite.New(path)
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	// logger = nil — сервис подставит slog.Default() и не будет писать в тестах
	// ничего лишнего, кроме случаев неизвестных ошибок (их в тестах нет).
	svc := service.New(store, nil)
	srv := api.New(svc)

	swagger, err := api.GetSpec()
	if err != nil {
		t.Fatalf("GetSpec: %v", err)
	}
	swagger.Servers = nil // чтобы валидатор не придирался к Host

	validator := nethttpmiddleware.OapiRequestValidator(swagger)
	r := chi.NewRouter()
	r.Use(validator)
	r.Mount("/", api.Handler(api.NewStrictHandler(srv, nil)))

	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return ts
}

func doJSON(t *testing.T, method, url string, body any) *http.Response {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, url, r)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

// decodeErrorBody читает ErrorResponse. Возвращает message и details (nil, если не было).
func decodeErrorBody(t *testing.T, resp *http.Response) (string, *string) {
	t.Helper()
	var body struct {
		Message string  `json:"message"`
		Details *string `json:"details"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	return body.Message, body.Details
}

func TestE2E_CreateGetUpdate(t *testing.T) {
	ts := newTestServer(t)

	// POST /info — создание.
	resp := doJSON(t, http.MethodPost, ts.URL+"/info", map[string]any{
		"md5": validMD5, "name": "Trojan.Win32.Generic", "file_size": 1024, "file_type": "pe",
	})
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: want 201, got %d: %s", resp.StatusCode, b)
	}
	if loc := resp.Header.Get("Location"); loc != "/info/"+validMD5 {
		t.Fatalf("bad Location header: %q", loc)
	}

	// GET /info/{md5} — читаем то, что создали.
	resp = doJSON(t, http.MethodGet, ts.URL+"/info/"+validMD5, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get: want 200, got %d", resp.StatusCode)
	}
	var got map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["name"] != "Trojan.Win32.Generic" {
		t.Fatalf("bad name in response: %v", got["name"])
	}
	if _, ok := got["created_at"]; !ok {
		t.Fatalf("created_at missing in response")
	}

	// PUT /info/{md5} — обновляем.
	resp = doJSON(t, http.MethodPut, ts.URL+"/info/"+validMD5, map[string]any{
		"name": "Worm.Linux.Mirai", "file_size": 2048,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update: want 200, got %d", resp.StatusCode)
	}

	// GET — проверяем, что изменения применились.
	resp = doJSON(t, http.MethodGet, ts.URL+"/info/"+validMD5, nil)
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got["name"] != "Worm.Linux.Mirai" {
		t.Fatalf("name not updated: %v", got["name"])
	}
}

func TestE2E_NotFound(t *testing.T) {
	ts := newTestServer(t)

	t.Run("GET unknown md5", func(t *testing.T) {
		resp := doJSON(t, http.MethodGet, ts.URL+"/info/"+validMD5, nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("want 404, got %d", resp.StatusCode)
		}
		msg, details := decodeErrorBody(t, resp)
		if msg != "threat not found" {
			t.Fatalf("bad message: %q", msg)
		}
		if details == nil || *details != "threat "+validMD5+" not found" {
			t.Fatalf("bad details: %v", details)
		}
	})

	t.Run("PUT unknown md5", func(t *testing.T) {
		resp := doJSON(t, http.MethodPut, ts.URL+"/info/"+validMD5, map[string]any{
			"name": "Trojan.Win32.Generic", "file_size": 1,
		})
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("want 404, got %d", resp.StatusCode)
		}
	})
}

func TestE2E_Conflict(t *testing.T) {
	ts := newTestServer(t)
	body := map[string]any{"md5": validMD5, "name": "Trojan.Win32.Generic", "file_size": 1}

	if r := doJSON(t, http.MethodPost, ts.URL+"/info", body); r.StatusCode != http.StatusCreated {
		t.Fatalf("first create: want 201, got %d", r.StatusCode)
	}

	resp := doJSON(t, http.MethodPost, ts.URL+"/info", body)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("dup create: want 409, got %d", resp.StatusCode)
	}
	msg, details := decodeErrorBody(t, resp)
	if msg != "threat already exists" {
		t.Fatalf("bad message: %q", msg)
	}
	if details == nil || *details != "threat with hash "+validMD5+" already exists" {
		t.Fatalf("bad details: %v", details)
	}
}

func TestE2E_Validation(t *testing.T) {
	ts := newTestServer(t)

	t.Run("invalid md5 rejected by validator", func(t *testing.T) {
		resp := doJSON(t, http.MethodPost, ts.URL+"/info", map[string]any{
			"md5": "zzz", "name": "Trojan.Win32.Generic", "file_size": 1,
		})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", resp.StatusCode)
		}
	})

	t.Run("negative file_size rejected by validator", func(t *testing.T) {
		resp := doJSON(t, http.MethodPost, ts.URL+"/info", map[string]any{
			"md5": validMD5, "name": "Trojan.Win32.Generic", "file_size": -1,
		})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", resp.StatusCode)
		}
	})

	t.Run("invalid name rejected by service", func(t *testing.T) {
		// В спеке у name нет pattern — middleware пропустит,
		// сервис вернёт domain.ErrInvalidName, хендлер — 400.
		resp := doJSON(t, http.MethodPost, ts.URL+"/info", map[string]any{
			"md5": validMD5, "name": "Trojan.Win32", "file_size": 1,
		})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", resp.StatusCode)
		}
		msg, _ := decodeErrorBody(t, resp)
		if msg != "invalid name" {
			t.Fatalf("bad message: %q", msg)
		}
	})
}