package scheduler

import "github.com/linguo2625469/workbuddy2api-panel/internal/auth"

func supportsGrowth(a *auth.Auth) bool {
	site, err := auth.ResolveSite(a)
	return err == nil && !site.International
}
