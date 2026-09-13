package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLegacyPanelRedirects(t *testing.T) {
	h := NewHandler(Config{
		Panel: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
	})
	for _, path := range []string{"/", "/dashboard", "/dashboard/"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusTemporaryRedirect || w.Header().Get("Location") != "/panel/" {
			t.Fatalf("%s: expected redirect to /panel/, got %d", path, w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/does-not-exist", nil))
	if w.Code != http.StatusNotFound {
		t.Fatal("unknown API routes must not redirect")
	}
}
