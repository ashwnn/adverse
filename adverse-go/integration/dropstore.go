package integration

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// dropStoreServer is an in-process WebDAV-style dead-drop store for the
// integration test: PUT/GET/DELETE/PROPFIND over plain HTTP, backed by an
// in-memory map. It simulates third-party file storage (e.g. Nextcloud) in
// the loopback lab.
type dropStoreServer struct {
	mu    sync.Mutex
	blobs map[string][]byte
}

func newDropStoreServer() *dropStoreServer {
	return &dropStoreServer{blobs: make(map[string][]byte)}
}

func (d *dropStoreServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	href := "http://" + r.Host

	switch r.Method {
	case http.MethodPut:
		data, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if err != nil {
			http.Error(w, "read", http.StatusBadRequest)
			return
		}
		d.mu.Lock()
		d.blobs[path] = data
		d.mu.Unlock()
		w.WriteHeader(http.StatusCreated)

	case http.MethodGet:
		d.mu.Lock()
		data, ok := d.blobs[path]
		d.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(data)

	case http.MethodDelete:
		d.mu.Lock()
		delete(d.blobs, path)
		d.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)

	case "PROPFIND":
		d.mu.Lock()
		entries := d.listLocked(path)
		d.mu.Unlock()
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusMultiStatus)
		fmt.Fprintf(w, `<?xml version="1.0"?>`+"\n")
		fmt.Fprintf(w, `<d:multistatus xmlns:d="DAV:">`+"\n")
		// Always list the requested collection itself first.
		fmt.Fprintf(w, `  <d:response><d:href>%s/%s</d:href></d:response>`+"\n", href, path)
		for _, e := range entries {
			fmt.Fprintf(w, `  <d:response><d:href>%s/%s</d:href></d:response>`+"\n", href, e)
		}
		fmt.Fprintf(w, `</d:multistatus>`+"\n")

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// blobCount returns the number of blobs still stored (hygiene check).
func (d *dropStoreServer) blobCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.blobs)
}

// listLocked returns direct children of the collection at path (files and
// one-level directories), mirroring a Depth-1 PROPFIND.
func (d *dropStoreServer) listLocked(path string) []string {
	path = strings.Trim(path, "/")
	prefix := path
	if prefix != "" {
		prefix += "/"
	}
	seen := make(map[string]bool)
	for name := range d.blobs {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		rest := strings.TrimPrefix(name, prefix)
		if rest == "" {
			continue
		}
		if i := strings.Index(rest, "/"); i >= 0 {
			rest = rest[:i]
		}
		entry := path
		if entry != "" {
			entry += "/"
		}
		entry += rest
		seen[entry] = true
	}
	out := make([]string, 0, len(seen))
	for e := range seen {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}
