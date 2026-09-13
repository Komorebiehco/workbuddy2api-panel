package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

type Site struct {
	Host          string
	International bool
	WorkBuddy     bool
}

func knownHost(value string, issuer bool) (string, error) {
	for _, c := range value {
		if c < 32 || c == 127 {
			return "", fmt.Errorf("invalid credential site")
		}
	}
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "\\?#") {
		return "", fmt.Errorf("invalid credential site")
	}
	if !strings.Contains(value, "://") {
		value = "https://" + value
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.User != nil ||
		u.Port() != "" || (!issuer && u.EscapedPath() != "" && u.EscapedPath() != "/") {
		return "", fmt.Errorf("unsupported credential site")
	}
	host := strings.ToLower(u.Host)
	switch host {
	case "www.codebuddy.cn", "copilot.tencent.com", "www.workbuddy.cn",
		"www.codebuddy.ai", "www.workbuddy.ai":
		return host, nil
	}
	return "", fmt.Errorf("unsupported credential site")
}

// ResolveSite uses JWT claims only as routing hints; upstream still verifies the token.
// Conflicting hints fail closed instead of sending a token to another region or product.
func ResolveSite(a *Auth) (Site, error) {
	var hints []string
	if a != nil {
		if a.Domain != "" {
			host, err := knownHost(a.Domain, false)
			if err != nil {
				return Site{}, err
			}
			hints = append(hints, host)
		}
		parts := strings.Split(a.AccessToken, ".")
		if len(parts) == 3 {
			raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
			var claims map[string]json.RawMessage
			if err == nil && json.Unmarshal(raw, &claims) == nil {
				if claim, ok := claims["iss"]; ok && string(claim) != "null" {
					var issuer string
					if json.Unmarshal(claim, &issuer) != nil {
						return Site{}, fmt.Errorf("invalid credential issuer")
					}
					if issuer != "" {
						host, err := knownHost(issuer, true)
						if err != nil {
							return Site{}, err
						}
						hints = append(hints, host)
					}
				}
			}
		}
	}
	site := Site{Host: "www.codebuddy.cn"}
	branded := ""
	for i, host := range hints {
		intl := strings.HasSuffix(host, ".ai")
		if i > 0 && intl != site.International {
			return Site{}, fmt.Errorf("conflicting credential regions")
		}
		if host == "copilot.tencent.com" {
			continue
		}
		if branded != "" && branded != host {
			return Site{}, fmt.Errorf("conflicting credential products")
		}
		branded = host
		site = Site{Host: host, International: intl, WorkBuddy: strings.HasPrefix(host, "www.workbuddy.")}
	}
	return site, nil
}
