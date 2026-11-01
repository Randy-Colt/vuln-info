package service_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"threat-info/internal/domain"
	"threat-info/internal/service"
	"threat-info/internal/storage"
)

const validMD5 = "d41d8cd98f00b204e9800998ecf8427e"

// errBoom — маркерная ошибка для проверки «сервис не глотает не-доменные ошибки».
var errBoom = errors.New("boom")

type fakeRepo struct {
	mu   sync.Mutex
	data map[string]domain.Threat

	getErr    error
	createErr error
	updateErr error
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{data: make(map[string]domain.Threat)}
}

func (f *fakeRepo) Threat(_ context.Context, md5 string) (domain.Threat, error) {
	if f.getErr != nil {
		return domain.Threat{}, f.getErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.data[md5]
	if !ok {
		return domain.Threat{}, storage.ErrThreatNotFound
	}
	return t, nil
}

func (f *fakeRepo) Create(_ context.Context, t domain.Threat) (domain.Threat, error) {
	if f.createErr != nil {
		return domain.Threat{}, f.createErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.data[t.MD5]; ok {
		return domain.Threat{}, storage.ErrThreatExists
	}
	f.data[t.MD5] = t
	return t, nil
}

func (f *fakeRepo) Update(_ context.Context, t domain.Threat) (domain.Threat, error) {
	if f.updateErr != nil {
		return domain.Threat{}, f.updateErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.data[t.MD5]; !ok {
		return domain.Threat{}, storage.ErrThreatNotFound
	}
	f.data[t.MD5] = t
	return t, nil
}

// --- Threat (get) ---

func TestThreat_Threat(t *testing.T) {
	stored := domain.Threat{MD5: validMD5, Behavior: "Trojan", Platform: "Win32", Family: "Generic"}

	tests := []struct {
		name      string
		md5       string
		seed      func(*fakeRepo)
		wantErr   error // domain-сентинел, ожидается через errors.Is
		wantIsErr error // сырая ошибка, ожидается через errors.Is
	}{
		{name: "ok", md5: validMD5, seed: func(r *fakeRepo) { r.data[validMD5] = stored }},
		{name: "normalizes uppercase", md5: "D41D8CD98F00B204E9800998ECF8427E",
			seed: func(r *fakeRepo) { r.data[validMD5] = stored }},
		{name: "trims spaces", md5: "  " + validMD5 + "  ",
			seed: func(r *fakeRepo) { r.data[validMD5] = stored }},
		{name: "not found", md5: validMD5, wantErr: domain.ErrNotFound},
		{name: "invalid md5 length", md5: "abc", wantErr: domain.ErrInvalidMD5},
		{name: "invalid md5 hex", md5: "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", wantErr: domain.ErrInvalidMD5},
		{name: "repo error propagates", md5: validMD5,
			seed:      func(r *fakeRepo) { r.getErr = errBoom },
			wantIsErr: errBoom},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newFakeRepo()
			if tt.seed != nil {
				tt.seed(repo)
			}
			svc := service.New(repo, nil)

			got, err := svc.Threat(context.Background(), tt.md5)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("want err %v, got %v", tt.wantErr, err)
				}
				return
			}
			if tt.wantIsErr != nil {
				if !errors.Is(err, tt.wantIsErr) {
					t.Fatalf("want err %v, got %v", tt.wantIsErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got.MD5 != validMD5 {
				t.Fatalf("want md5 %q, got %q", validMD5, got.MD5)
			}
		})
	}
}

// --- Create ---

func TestThreat_Create(t *testing.T) {
	pe := "pe"

	tests := []struct {
		name      string
		in        service.CreateInput
		seed      func(*fakeRepo)
		wantErr   error
		wantIsErr error
		want      func(*testing.T, domain.Threat)
	}{
		{
			name: "ok, splits name",
			in:   service.CreateInput{MD5: validMD5, Name: "Trojan.Win32.Generic", FileSize: 100},
			want: func(t *testing.T, got domain.Threat) {
				if got.Behavior != "Trojan" || got.Platform != "Win32" || got.Family != "Generic" {
					t.Fatalf("bad split: %+v", got)
				}
			},
		},
		{
			name: "4 parts — variant lands in family",
			in:   service.CreateInput{MD5: validMD5, Name: "Trojan.Win32.Generic.avy", FileSize: 100},
			want: func(t *testing.T, got domain.Threat) {
				if got.Family != "Generic.avy" {
					t.Fatalf("want family=Generic.avy, got %q", got.Family)
				}
			},
		},
		{
			name:    "too few parts",
			in:      service.CreateInput{MD5: validMD5, Name: "Trojan.Win32", FileSize: 100},
			wantErr: domain.ErrInvalidName,
		},
		{
			name:    "empty part",
			in:      service.CreateInput{MD5: validMD5, Name: "Trojan..Generic", FileSize: 100},
			wantErr: domain.ErrInvalidName,
		},
		{
			name:    "negative file size",
			in:      service.CreateInput{MD5: validMD5, Name: "Trojan.Win32.Generic", FileSize: -1},
			wantErr: domain.ErrInvalidFileSize,
		},
		{
			name:    "invalid md5",
			in:      service.CreateInput{MD5: "abc", Name: "Trojan.Win32.Generic", FileSize: 100},
			wantErr: domain.ErrInvalidMD5,
		},
		{
			name: "file_type nil stays nil",
			in:   service.CreateInput{MD5: validMD5, Name: "Trojan.Win32.Generic", FileSize: 100},
			want: func(t *testing.T, got domain.Threat) {
				if got.FileType != nil {
					t.Fatalf("want nil file type, got %q", *got.FileType)
				}
			},
		},
		{
			name: "file_type whitespace becomes nil",
			in:   service.CreateInput{MD5: validMD5, Name: "Trojan.Win32.Generic", FileSize: 100, FileType: new("   ")},
			want: func(t *testing.T, got domain.Threat) {
				if got.FileType != nil {
					t.Fatalf("want nil file type, got %q", *got.FileType)
				}
			},
		},
		{
			name: "file_type trimmed",
			in:   service.CreateInput{MD5: validMD5, Name: "Trojan.Win32.Generic", FileSize: 100, FileType: new("  " + pe + "  ")},
			want: func(t *testing.T, got domain.Threat) {
				if got.FileType == nil || *got.FileType != pe {
					t.Fatalf("want %q, got %v", pe, got.FileType)
				}
			},
		},
		{
			name: "already exists",
			in:   service.CreateInput{MD5: validMD5, Name: "Trojan.Win32.Generic", FileSize: 100},
			seed: func(r *fakeRepo) { r.data[validMD5] = domain.Threat{MD5: validMD5} },
			wantErr: domain.ErrAlreadyExists,
		},
		{
			name: "repo error propagates",
			in:   service.CreateInput{MD5: validMD5, Name: "Trojan.Win32.Generic", FileSize: 100},
			seed:      func(r *fakeRepo) { r.createErr = errBoom },
			wantIsErr: errBoom,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newFakeRepo()
			if tt.seed != nil {
				tt.seed(repo)
			}
			svc := service.New(repo, nil)

			got, err := svc.Create(context.Background(), tt.in)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("want err %v, got %v", tt.wantErr, err)
				}
				return
			}
			if tt.wantIsErr != nil {
				if !errors.Is(err, tt.wantIsErr) {
					t.Fatalf("want err %v, got %v", tt.wantIsErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if tt.want != nil {
				tt.want(t, got)
			}
		})
	}
}

// --- Update ---

func TestThreat_Update(t *testing.T) {
	tests := []struct {
		name      string
		md5       string
		in        service.UpdateInput
		seed      func(*fakeRepo)
		wantErr   error
		wantIsErr error
		want      func(*testing.T, domain.Threat)
	}{
		{
			name: "ok",
			md5:  validMD5,
			in:   service.UpdateInput{Name: "Worm.Linux.Mirai", FileSize: 200},
			seed: func(r *fakeRepo) { r.data[validMD5] = domain.Threat{MD5: validMD5} },
			want: func(t *testing.T, got domain.Threat) {
				if got.Behavior != "Worm" || got.Platform != "Linux" || got.Family != "Mirai" {
					t.Fatalf("bad update: %+v", got)
				}
			},
		},
		{
			name: "normalizes md5",
			md5:  "D41D8CD98F00B204E9800998ECF8427E",
			in:   service.UpdateInput{Name: "Worm.Linux.Mirai", FileSize: 200},
			seed: func(r *fakeRepo) { r.data[validMD5] = domain.Threat{MD5: validMD5} },
		},
		{
			name:    "not found",
			md5:     validMD5,
			in:      service.UpdateInput{Name: "Worm.Linux.Mirai", FileSize: 200},
			wantErr: domain.ErrNotFound,
		},
		{
			name:    "invalid md5",
			md5:     "abc",
			in:      service.UpdateInput{Name: "Worm.Linux.Mirai", FileSize: 200},
			wantErr: domain.ErrInvalidMD5,
		},
		{
			name:    "invalid name",
			md5:     validMD5,
			in:      service.UpdateInput{Name: "OnlyTwo.Parts", FileSize: 200},
			wantErr: domain.ErrInvalidName,
		},
		{
			name:    "negative file size",
			md5:     validMD5,
			in:      service.UpdateInput{Name: "Worm.Linux.Mirai", FileSize: -1},
			wantErr: domain.ErrInvalidFileSize,
		},
		{
			name: "file_type cleared",
			md5:  validMD5,
			in:   service.UpdateInput{Name: "Worm.Linux.Mirai", FileSize: 200, FileType: nil},
			seed: func(r *fakeRepo) {
				v := "pe"
				r.data[validMD5] = domain.Threat{MD5: validMD5, FileType: &v}
			},
			want: func(t *testing.T, got domain.Threat) {
				if got.FileType != nil {
					t.Fatalf("want nil file type, got %q", *got.FileType)
				}
			},
		},
		{
			name: "repo error propagates",
			md5:  validMD5,
			in:   service.UpdateInput{Name: "Worm.Linux.Mirai", FileSize: 200},
			seed:      func(r *fakeRepo) { r.updateErr = errBoom },
			wantIsErr: errBoom,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newFakeRepo()
			if tt.seed != nil {
				tt.seed(repo)
			}
			svc := service.New(repo, nil)

			got, err := svc.Update(context.Background(), tt.md5, tt.in)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("want err %v, got %v", tt.wantErr, err)
				}
				return
			}
			if tt.wantIsErr != nil {
				if !errors.Is(err, tt.wantIsErr) {
					t.Fatalf("want err %v, got %v", tt.wantIsErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if tt.want != nil {
				tt.want(t, got)
			}
		})
	}
}