package upstream

import (
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
)

func TestInternationalCredentialUsesOwnProductHost(t *testing.T) {
	c := New()
	for _, domain := range []string{"www.workbuddy.ai", "www.codebuddy.ai"} {
		a := &auth.Auth{Domain: domain, AccessToken: "token", UID: "u1"}
		want := "https://" + domain
		if c.chatBase(a) != want || c.billingBase(a) != want || originRefererFor(a) != want {
			t.Fatalf("credential was routed to the wrong product: %s", domain)
		}
		req, _ := http.NewRequest(http.MethodPost, want, nil)
		c.ChatHeaders(req, a)
		if req.Header.Get("Origin") != want || req.Header.Get("X-Domain") != domain {
			t.Fatal("international request headers do not match the credential")
		}
		if req.Header.Get("X-Refresh-Token") != "" {
			t.Fatal("chat must not send refresh tokens")
		}
	}
}

func TestInternationalRefreshAndChatRouting(t *testing.T) {
	for _, host := range []string{"www.workbuddy.ai", "www.codebuddy.ai"} {
		t.Run(host, func(t *testing.T) {
			a := &auth.Auth{Domain: host, AccessToken: "old", RefreshToken: "refresh", UID: "u"}
			c := testClient(func(r *http.Request) (*http.Response, error) {
				if r.URL.Host != host || r.Header.Get("X-Domain") != host {
					t.Fatalf("wrong credential destination %s", r.URL)
				}
				switch r.URL.Path {
				case "/v2/plugin/auth/token/refresh":
					if r.Header.Get("X-Refresh-Token") != "refresh" {
						t.Fatal("refresh token not sent to refresh endpoint")
					}
					return jsonResp(200, `{"code":0,"data":{"accessToken":"new","expiresIn":3600}}`), nil
				case "/v2/chat/completions":
					if r.Header.Get("Authorization") != "Bearer new" || r.Header.Get("X-Refresh-Token") != "" {
						t.Fatal("incorrect chat authentication")
					}
					return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader("data: [DONE]\n\n"))}, nil
				}
				t.Fatalf("unexpected path %s", r.URL.Path)
				return nil, nil
			})
			if err := c.RefreshToken(a); err != nil {
				t.Fatal(err)
			}
			rc, status, _, err := c.ChatStream(a, []byte(`{"model":"fast-model","messages":[]}`))
			if err != nil || status != 200 {
				t.Fatalf("chat status=%d err=%v", status, err)
			}
			rc.Close()
		})
	}
}

func TestConflictingRefreshDoesNotOverwriteCredential(t *testing.T) {
	c := testClient(func(r *http.Request) (*http.Response, error) {
		return jsonResp(200, `{"code":0,"data":{"accessToken":"bad","refreshToken":"bad","domain":"www.codebuddy.cn"}}`), nil
	})
	a := &auth.Auth{Domain: "www.workbuddy.ai", AccessToken: "old", RefreshToken: "old-refresh"}
	if c.RefreshToken(a) == nil || a.AccessToken != "old" || a.RefreshToken != "old-refresh" {
		t.Fatal("conflicting refresh changed the credential")
	}
}

func TestInternationalIssuerCannotLeakToDomestic(t *testing.T) {
	token := "e30." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://www.workbuddy.ai/auth/realms/x"}`)) + ".sig"
	c := testClient(func(r *http.Request) (*http.Response, error) {
		t.Fatal("conflicting token must never leave this process")
		return nil, nil
	})
	a := &auth.Auth{Domain: "www.codebuddy.cn", AccessToken: token, RefreshToken: "r"}
	if _, _, _, err := c.ChatStream(a, []byte(`{}`)); err == nil {
		t.Fatal("chat accepted conflicting hints")
	}
	if _, err := c.UserResource(a); err == nil {
		t.Fatal("billing accepted conflicting hints")
	}
	if err := c.RefreshToken(a); err == nil {
		t.Fatal("refresh accepted conflicting hints")
	}
}

func TestInternationalGrowthMakesNoRequests(t *testing.T) {
	c := testClient(func(r *http.Request) (*http.Response, error) {
		t.Fatalf("international growth sent a request: %s", r.URL)
		return nil, nil
	})
	a := &auth.Auth{Domain: "www.workbuddy.ai", AccessToken: "token"}
	checks := []func() error{
		func() error { return c.DailyCheckin(a) },
		func() error { _, err := c.ListTasks(a); return err },
		func() error { return c.ReportChatActivity(a, "test") },
		func() error { return c.ReportDesktopEvent(a, DesktopEvent{"eventCode": "test"}) },
		func() error { return c.ReportWebEvent(a, "test", "", "", "") },
		func() error { _, _, err := c.ClaimReward(a, "test"); return err },
	}
	for _, check := range checks {
		if check() == nil {
			t.Fatal("international growth was not rejected")
		}
	}
}

func TestEmptyCatalogDoesNotBlockAnUnknownModel(t *testing.T) {
	c := testClient(func(r *http.Request) (*http.Response, error) {
		return jsonResp(200, `{"code":0,"data":{"models":[],"agents":[]}}`), nil
	})
	a := &auth.Auth{UID: "intl", Domain: "www.workbuddy.ai", AccessToken: "token"}
	if _, err := c.FetchModels(a); err == nil {
		t.Fatal("empty remote catalog should not become an authoritative cache entry")
	}
	if !c.ModelAvailable(a, "new-model") {
		t.Fatal("failed catalog should leave model support unknown")
	}
}

func TestInternationalRoutingRejectsArbitraryDestinations(t *testing.T) {
	c := New()
	for _, domain := range []string{"www.workbuddy.ai.evil.example", "https://www.workbuddy.ai@evil.example", "http://www.workbuddy.ai", "www.workbuddy.ai:444", "www.workbuddy.ai/path", "127.0.0.1"} {
		a := &auth.Auth{Domain: domain}
		if internationalHost(a) != "" || c.chatBase(a) != "" {
			t.Fatalf("untrusted domain influenced request destination: %s", domain)
		}
	}
}

func TestInternationalModelsUseWorkBuddyCatalog(t *testing.T) {
	c := testClient(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "www.workbuddy.ai" || r.URL.Path != "/v3/config" ||
			r.Header.Get("X-IDE-Type") != "WorkBuddy" {
			t.Fatal("wrong WorkBuddy catalog request")
		}
		return jsonResp(200, `{"code":0,"data":{"models":[{"id":"work-model"},{"id":"cli-model"}],"agents":[{"name":"cli","models":["cli-model"]},{"name":"conversation","tags":["default"],"models":["work-model"]}]}}`), nil
	})
	models, err := c.FetchModels(&auth.Auth{Domain: "www.workbuddy.ai", AccessToken: "token"})
	if err != nil || len(models) != 1 || models[0].ID != "work-model" {
		t.Fatalf("incorrect product model list: %v", err)
	}
}
