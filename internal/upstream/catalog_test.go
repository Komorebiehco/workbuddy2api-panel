package upstream

import (
	"reflect"
	"testing"
)

func TestProductCatalogSelection(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		work      bool
		want      []string
		fail      bool
	}{
		{"default tag", `{"models":[{"id":"c"},{"id":"w"}],"agents":[{"name":"cli","models":["c"]},{"name":"main","tags":["default"],"models":["w"]}]}`, true, []string{"w"}, false},
		{"cli not default", `{"models":[{"id":"c"},{"id":"w"}],"agents":[{"name":"cli","models":["c"]},{"name":"main","tags":["default"],"models":["w"]}]}`, false, []string{"c"}, false},
		{"work cli fallback", `{"models":[{"id":"w"}],"agents":[{"name":"cli","tags":["default"],"models":["w"]}]}`, true, []string{"w"}, false},
		{"first nonempty", `{"models":[{"id":"w"}],"agents":[{"name":"first","models":[]},{"name":"second","models":["w"]}]}`, true, []string{"w"}, false},
		{"references", `{"models":[{"id":"a","name":"Alpha","aliases":["alias"]},{"id":"b","name":"Beta"},{"id":"c","disabled":true}],"agents":[{"name":"cli","models":[{"name":"Alpha"},"alias",{"id":"b"},"c"]}]}`, true, []string{"a", "b"}, false},
		{"available", `{"models":[{"id":"a"},{"id":"b"}],"availableModels":["b"]}`, true, []string{"b"}, false},
		{"empty available", `{"models":[{"id":"a"}],"availableModels":[]}`, true, []string{"a"}, false},
		{"explicit empty agent", `{"models":[{"id":"a"}],"agents":[{"name":"cli","models":[]}]}`, true, []string{}, false},
		{"unresolved", `{"models":[{"id":"a"}],"agents":[{"name":"cli","models":["missing"]}]}`, true, nil, true},
		{"invalid refs", `{"models":[{"id":"a"}],"agents":[{"name":"cli","models":[42]}]}`, true, nil, true},
		{"invalid catalog", `{"agents":[]}`, true, nil, true},
		{"duplicate IDs", `{"models":[{"id":"a"},{"id":"a"}]}`, true, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			models, err := selectProductModels([]byte(tc.raw), tc.work)
			if tc.fail {
				if err == nil {
					t.Fatal("expected invalid catalog")
				}
				return
			}
			got := make([]string, 0, len(models))
			for _, model := range models {
				got = append(got, model.ID)
			}
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("models=%v err=%v want=%v", got, err, tc.want)
			}
		})
	}
}
