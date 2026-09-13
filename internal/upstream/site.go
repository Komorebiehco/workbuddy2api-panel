package upstream

import (
	"fmt"
	"net/http"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
)

func rejectRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

func requireDomestic(a *auth.Auth) error {
	site, err := auth.ResolveSite(a)
	if err != nil {
		return err
	}
	if site.International {
		return fmt.Errorf("growth tasks are not supported for international accounts")
	}
	return nil
}
