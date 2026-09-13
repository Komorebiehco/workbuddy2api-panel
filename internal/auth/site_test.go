package auth

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func tokenWithIssuer(issuer any) string {
	raw, _ := json.Marshal(map[string]any{"iss": issuer})
	return "e30." + base64.RawURLEncoding.EncodeToString(raw) + ".signature"
}

func TestResolveSite(t *testing.T) {
	for _, tc := range []struct {
		name, domain, issuer, host string
		intl, work, invalid        bool
	}{
		{"legacy", "", "", "www.codebuddy.cn", false, false, false},
		{"intl work", "https://WWW.WORKBUDDY.AI/", "https://www.workbuddy.ai/auth/realms/x", "www.workbuddy.ai", true, true, false},
		{"issuer only", "", "https://www.codebuddy.ai/realms/x", "www.codebuddy.ai", true, false, false},
		{"shared cn issuer", "www.workbuddy.cn", "https://copilot.tencent.com/auth/x", "www.workbuddy.cn", false, true, false},
		{"shared cn domain", "copilot.tencent.com", "https://www.workbuddy.cn", "www.workbuddy.cn", false, true, false},
		{"regions", "www.codebuddy.cn", "https://www.workbuddy.ai", "", false, false, true},
		{"products", "www.codebuddy.ai", "https://www.workbuddy.ai", "", false, false, true},
		{"cn products", "www.codebuddy.cn", "https://www.workbuddy.cn", "", false, false, true},
		{"unknown issuer", "www.workbuddy.ai", "https://untrusted.example", "", false, false, true},
		{"unknown host", "untrusted.example", "", "", false, false, true},
		{"userinfo", "https://www.workbuddy.ai@untrusted.example", "", "", false, false, true},
		{"port", "www.workbuddy.ai:443", "", "", false, false, true},
		{"path", "www.workbuddy.ai/other", "", "", false, false, true},
		{"http", "http://www.workbuddy.ai", "", "", false, false, true},
		{"query", "www.workbuddy.ai?x", "", "", false, false, true},
		{"control", "\nwww.workbuddy.ai", "", "", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &Auth{Domain: tc.domain}
			if tc.issuer != "" {
				a.AccessToken = tokenWithIssuer(tc.issuer)
			}
			site, err := ResolveSite(a)
			if tc.invalid {
				if err == nil {
					t.Fatal("expected credential routing to fail closed")
				}
				return
			}
			if err != nil || site.Host != tc.host || site.International != tc.intl || site.WorkBuddy != tc.work {
				t.Fatalf("site=%+v err=%v", site, err)
			}
		})
	}
}

func TestInvalidIssuerTypeIsRejected(t *testing.T) {
	if _, err := ResolveSite(&Auth{AccessToken: tokenWithIssuer(42)}); err == nil {
		t.Fatal("non-string issuer accepted")
	}
}
