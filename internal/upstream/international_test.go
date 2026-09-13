package upstream

import (
	"net/http"
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

func TestInternationalRoutingRejectsArbitraryDestinations(t *testing.T) {
	c := New()
	for _, domain := range []string{"www.workbuddy.ai.evil.example", "https://www.workbuddy.ai@evil.example", "http://www.workbuddy.ai", "www.workbuddy.ai:444", "www.workbuddy.ai/path", "127.0.0.1"} {
		a := &auth.Auth{Domain: domain}
		if internationalHost(a) != "" || c.chatBase(a) != c.ChatBaseCN {
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
		return jsonResp(200, `{"code":0,"data":{"models":[{"id":"work-model"},{"id":"cli-model"}],"agents":[{"name":"cli","models":["cli-model"]},{"name":"coordinator","models":["work-model"]}]}}`), nil
	})
	models, err := c.FetchModels(&auth.Auth{Domain: "www.workbuddy.ai", AccessToken: "token"})
	if err != nil || len(models) != 1 || models[0].ID != "work-model" {
		t.Fatalf("incorrect product model list: %v", err)
	}
}
