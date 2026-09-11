package transport

import (
	"net/http"
	"strings"
)

// Mux routes requests between the agent wire endpoint ("/") and the operator
// admin API ("/admin/v1/*"). Everything else gets 404 from the agent handler,
// which rejects non-POST with 405.
func Mux(agent http.Handler, admin http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/admin/") {
			admin.ServeHTTP(w, r)
			return
		}
		agent.ServeHTTP(w, r)
	})
}
