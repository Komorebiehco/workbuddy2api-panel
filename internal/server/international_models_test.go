package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

func TestMixedCatalogUnionAndChatSelection(t *testing.T) {
	chatCalls := 0
	up := &upstream.Client{ChatBaseCN: "https://copilot.tencent.com"}
	up.HTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		raw := `{"code":0,"data":{"models":[{"id":"cn-model"}],"agents":[{"name":"cli","models":["cn-model"]}]}}`
		if r.URL.Host == "www.workbuddy.ai" {
			raw = `{"code":0,"data":{"models":[{"id":"intl-model"}],"agents":[{"name":"cli","tags":["default"],"models":["intl-model"]}]}}`
		}
		if r.URL.Path == "/v2/chat/completions" {
			chatCalls++
			if r.URL.Host != "www.workbuddy.ai" {
				t.Fatal("international model sent to domestic account")
			}
			raw = sseOK
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(raw))}, nil
	})}
	cn := &auth.Auth{UID: "cn", AccessToken: "cn", ExpiresAt: 9999999999}
	intl := &auth.Auth{UID: "intl", AccessToken: "intl", Domain: "www.workbuddy.ai", ExpiresAt: 9999999999}
	p := testPoolWith(cn, intl)
	h := NewHandler(Config{Pool: p, Upstream: up})
	if got := h.fetchDynamicModels(); len(got) != 2 {
		t.Fatalf("union=%v", got)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"intl-model","messages":[{"role":"user","content":"hi"}]}`)))
	if w.Code != 200 || chatCalls != 1 {
		t.Fatalf("chat=%d calls=%d", w.Code, chatCalls)
	}
	p.Remove("cn")
	got := h.fetchDynamicModels()
	if len(got) != 1 || got[0].ID != "intl-model" {
		t.Fatalf("removed account retained in catalog: %v", got)
	}
}

func TestInternationalCatalogFailureNeverUsesDomesticStaticModels(t *testing.T) {
	up := newFakeUpstream(t, func(string) (int, string, bool) { return 500, "unavailable", false })
	h := NewHandler(Config{Pool: testPoolWith(&auth.Auth{UID: "intl", AccessToken: "at", Domain: "www.workbuddy.ai"}), Upstream: up})
	if models := h.modelList(); len(models) != 0 {
		t.Fatalf("domestic fallback exposed for international account: %v", models)
	}
}

func TestCatalogCacheIsolatedBetweenHandlers(t *testing.T) {
	for _, id := range []string{"first", "second"} {
		up := newFakeUpstream(t, func(string) (int, string, bool) {
			return 200, `{"code":0,"data":{"models":[{"id":"` + id + `"}]}}`, false
		})
		h := NewHandler(Config{Pool: testPoolWith(&auth.Auth{UID: "same", AccessToken: "at"}), Upstream: up})
		models := h.fetchDynamicModels()
		if len(models) != 1 || models[0].ID != id {
			t.Fatalf("cross-handler catalog reused: %v", models)
		}
	}
}

func TestEmptyPoolPreservesStaticModels(t *testing.T) {
	h := NewHandler(Config{Pool: testPoolWith(), Upstream: upstream.New()})
	if len(h.modelList()) != len(staticModels) {
		t.Fatal("empty legacy pool should retain its static model listing")
	}
}

func TestSingleSiteCanTryNewModelBeforeCatalogRefresh(t *testing.T) {
	up := newFakeUpstream(t, func(string) (int, string, bool) {
		return 200, `{"code":0,"data":{"models":[{"id":"old-model"}],"agents":[]}}`, false
	})
	a := &auth.Auth{UID: "intl", AccessToken: "at", Domain: "www.workbuddy.ai", ExpiresAt: 9999999999}
	if _, err := up.FetchModels(a); err != nil {
		t.Fatal(err)
	}
	up.HTTP.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(sseOK))}, nil
	})
	h := NewHandler(Config{Pool: testPoolWith(a), Upstream: up})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"new-model","messages":[]}`)))
	if w.Code != 200 {
		t.Fatalf("old catalog blocked a single-site request: %d", w.Code)
	}
}
