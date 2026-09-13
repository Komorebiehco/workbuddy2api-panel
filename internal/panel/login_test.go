package panel

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

type loginRoundTrip func(*http.Request) (*http.Response, error)

func (f loginRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func loginResponse(raw string) *http.Response {
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(raw))}
}

func mockLogin(t *testing.T, fn loginRoundTrip) {
	t.Helper()
	previous := loginHTTP
	loginHTTP = &http.Client{Transport: fn}
	t.Cleanup(func() { loginHTTP = previous })
}

func TestLoginStartFixedProfiles(t *testing.T) {
	for _, tc := range []struct{ site, product, host, platform string }{
		{"cn", "cli", "copilot.tencent.com", "CLI"},
		{"cn", "workbuddy", "www.workbuddy.cn", "workbuddy"},
		{"intl", "workbuddy", "www.workbuddy.ai", "workbuddy"},
		{"intl", "cli", "www.codebuddy.ai", "CLI"},
	} {
		t.Run(tc.site+tc.product, func(t *testing.T) {
			mockLogin(t, func(r *http.Request) (*http.Response, error) {
				if r.URL.Host != tc.host || r.URL.Query().Get("platform") != tc.platform {
					t.Fatalf("incorrect login route: %s", r.URL)
				}
				return loginResponse(`{"code":0,"data":{"state":"upstream-state","authUrl":"https://` + tc.host + `/login?state=upstream-state"}}`), nil
			})
			p := New(Config{})
			w := httptest.NewRecorder()
			p.ServeHTTP(w, httptest.NewRequest("POST", "/panel/api/login/start",
				strings.NewReader(`{"site":"`+tc.site+`","product":"`+tc.product+`"}`)))
			if w.Code != 200 || len(p.logins) != 1 {
				t.Fatalf("start=%d %s", w.Code, w.Body)
			}
			for id, session := range p.logins {
				if id == "upstream-state" || session.State != "upstream-state" ||
					session.Site.International != (tc.site == "intl") {
					t.Fatal("login session lost routing identity")
				}
			}
		})
	}
}

func TestLoginRejectsArbitrarySite(t *testing.T) {
	mockLogin(t, func(r *http.Request) (*http.Response, error) {
		t.Fatal("untrusted site caused an upstream request")
		return nil, nil
	})
	p := New(Config{})
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest("POST", "/panel/api/login/start", strings.NewReader(`{"site":"https://evil.example"}`)))
	if w.Code != 400 {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestInternationalLoginPersistsAndIsIdempotent(t *testing.T) {
	calls := 0
	mockLogin(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Host != "www.workbuddy.ai" || r.URL.Query().Get("state") != "a&b" {
			t.Fatalf("wrong polling destination %s", r.URL)
		}
		if r.URL.Path == "/v2/plugin/auth/token" {
			return loginResponse(`{"code":0,"data":{"accessToken":"access","refreshToken":"refresh","expiresIn":3600,"domain":"www.workbuddy.ai","sessionState":"preserved"}}`), nil
		}
		if r.URL.Path != "/v2/plugin/login/account" || r.Header.Get("X-Domain") != "www.workbuddy.ai" ||
			r.Header.Get("Authorization") != "Bearer access" {
			t.Fatal("account request did not preserve international authentication")
		}
		return loginResponse(`{"code":0,"data":{"uid":"intl-user","nickname":"International","unknown":"kept"}}`), nil
	})
	p := New(Config{Pool: pool.New(""), AuthDir: t.TempDir(), Upstream: &upstream.Client{
		HTTP: &http.Client{Transport: loginRoundTrip(func(r *http.Request) (*http.Response, error) {
			if r.URL.Host != "www.workbuddy.ai" || r.URL.Path != "/v2/billing/meter/get-user-resource" {
				t.Fatalf("international login attempted a domestic task: %s", r.URL)
			}
			return loginResponse(`{"code":0,"data":{"Response":{"Data":{"Accounts":[{"CapacityRemain":350}]}}}}`), nil
		})},
	}})
	site, _ := auth.ResolveSite(&auth.Auth{Domain: "www.workbuddy.ai"})
	p.logins["local"] = &loginSession{Created: time.Now(), Site: site, State: "a&b"}
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		p.ServeHTTP(w, httptest.NewRequest("GET", "/panel/api/login/poll?state=local", nil))
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"done":true`) {
			t.Fatalf("poll=%d %s", w.Code, w.Body)
		}
	}
	if calls != 2 {
		t.Fatalf("completed login repeated upstream requests: %d", calls)
	}
	raw, err := os.ReadFile(filepath.Join(p.cfg.AuthDir, "workbuddy-intl-user.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]map[string]any
	_ = json.Unmarshal(raw, &doc)
	if doc["auth"]["sessionState"] != "preserved" || doc["account"]["unknown"] != "kept" {
		t.Fatal("OAuth persistence discarded unknown credential fields")
	}
	a := p.cfg.Pool.AuthByUID("intl-user")
	if a == nil || a.Domain != "www.workbuddy.ai" || a.NeedsRefresh(time.Minute) {
		t.Fatal("international credential was not loaded correctly")
	}
}

func TestLoginExpiredStateMakesNoRequest(t *testing.T) {
	mockLogin(t, func(r *http.Request) (*http.Response, error) {
		t.Fatal("expired state reached upstream")
		return nil, nil
	})
	p := New(Config{})
	p.logins["expired"] = &loginSession{Created: time.Now().Add(-2 * loginTTL)}
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest("GET", "/panel/api/login/poll?state=expired", nil))
	if w.Code != 404 {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestInternationalGrowthAPIsReturn501(t *testing.T) {
	pool := pool.New("")
	pool.Add(&auth.Auth{UID: "intl", Domain: "www.workbuddy.ai", AccessToken: "access"})
	p := New(Config{Pool: pool})
	for _, action := range []string{"tasks", "tasks/accept", "tasks/accept_all", "tasks/claim", "tasks/auto", "tasks/auto_all", "checkin"} {
		method := "POST"
		if action == "tasks" {
			method = "GET"
		}
		w := httptest.NewRecorder()
		p.ServeHTTP(w, httptest.NewRequest(method, "/panel/api/accounts/intl/"+action, strings.NewReader(`{}`)))
		if w.Code != 501 {
			t.Fatalf("%s status=%d", action, w.Code)
		}
	}
}
