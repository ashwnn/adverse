package drop

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// davMultistatus mirrors the WebDAV PROPFIND response body subset needed to
// enumerate blob names.
type davMultistatus struct {
	XMLName  xml.Name      `xml:"multistatus"`
	Response []davResponse `xml:"response"`
}

type davResponse struct {
	Href string `xml:"href"`
}

// List implements Lister via WebDAV PROPFIND (Depth: 1). Works against
// Nextcloud/ownCloud and compatible DAV servers. Blob names are returned
// relative to the store root.
func (s *HTTPStore) List(ctx context.Context, prefix string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "PROPFIND", s.blobURL(prefix), nil)
	if err != nil {
		return nil, fmt.Errorf("drop http list: %w", err)
	}
	req.Header.Set("Depth", "1")
	req.Header.Set("Content-Type", "application/xml")
	s.applyAuth(req)
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("drop http list %s: %w", prefix, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // missing directory: empty
	}
	if resp.StatusCode != http.StatusMultiStatus && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("drop http list %s: status %d", prefix, resp.StatusCode)
	}
	var ms davMultistatus
	if err := xml.NewDecoder(resp.Body).Decode(&ms); err != nil {
		return nil, fmt.Errorf("drop http list %s: parse PROPFIND: %w", prefix, err)
	}

	root := s.BaseURL + "/"
	var names []string
	for _, r := range ms.Response {
		href := strings.TrimSpace(r.Href)
		if href == "" {
			continue
		}
		// Skip the directory itself and unescape URL-encoded paths.
		decoded, err := url.PathUnescape(href)
		if err != nil {
			continue
		}
		decoded = strings.TrimPrefix(decoded, root)
		decoded = strings.Trim(decoded, "/")
		if decoded == "" || decoded == strings.Trim(prefix, "/") {
			continue
		}
		names = append(names, decoded)
	}
	sort.Strings(names)
	return names, nil
}
