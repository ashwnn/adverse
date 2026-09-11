package drop

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// List implements Lister via the Graph API children listing:
//
//	GET /v1.0/users/{upn}/drive/root:/{path}:/children?$select=name
//
// Returns blob names relative to the store root, sorted.
func (s *GraphStore) List(ctx context.Context, prefix string) ([]string, error) {
	prefix = strings.Trim(prefix, "/")
	base := strings.TrimRight(s.GraphURL, "/")
	path := fmt.Sprintf("/v1.0/users/%s/drive/root:/%s:/children?$select=name&$top=999", url.PathEscape(s.UserUPN), prefix)

	var names []string
	next := base + path
	for next != "" {
		tok, err := s.token(ctx)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return nil, fmt.Errorf("drop graph list request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := s.Client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("drop graph list %s: %w", prefix, err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("drop graph list %s: read: %w", prefix, err)
		}
		if resp.StatusCode == http.StatusNotFound {
			return nil, nil // missing folder: empty
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("drop graph list %s: status %d: %s", prefix, resp.StatusCode, truncate(string(body), 200))
		}
		var page struct {
			Value []struct {
				Name string `json:"name"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("drop graph list %s: parse: %w", prefix, err)
		}
		for _, v := range page.Value {
			if v.Name == "" {
				continue
			}
			name := v.Name
			if prefix != "" {
				name = prefix + "/" + name
			}
			names = append(names, name)
		}
		next = page.NextLink
		if len(names) > 10000 {
			break
		}
	}
	sort.Strings(names)
	return names, nil
}

// ensuredDirs tracks parent folders already created this session.
var ensuredDirs sync.Map // string -> struct{}

// ensureParent creates the parent folder chain for a blob path (Graph simple
// upload does not create intermediate folders). Folder creation races with
// concurrent uploads are tolerated via AlreadyExists (409).
func (s *GraphStore) ensureParent(ctx context.Context, name string) error {
	idx := strings.LastIndex(name, "/")
	if idx < 0 {
		return nil
	}
	parent := name[:idx]
	if _, ok := ensuredDirs.Load(parent); ok {
		return nil
	}

	// Create each intermediate folder level (one Graph call per level).
	base := strings.TrimRight(s.GraphURL, "/")
	current := ""
	parts := strings.Split(parent, "/")
	for _, part := range parts {
		if current == "" {
			current = part
		} else {
			current += "/" + part
		}
		if _, ok := ensuredDirs.Load(current); ok {
			continue
		}
		tok, err := s.token(ctx)
		if err != nil {
			return err
		}
		body := fmt.Sprintf(`{"name":%q,"folder":{},"@microsoft.graph.conflictBehavior":"fail"}`, part)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			base+fmt.Sprintf("/v1.0/users/%s/drive/root:/%s:/children", url.PathEscape(s.UserUPN), current),
			strings.NewReader(body))
		if err != nil {
			return fmt.Errorf("drop graph mkdir request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		resp, err := s.Client.Do(req)
		if err != nil {
			return fmt.Errorf("drop graph mkdir %s: %w", current, err)
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusConflict && resp.StatusCode != http.StatusOK {
			return fmt.Errorf("drop graph mkdir %s: status %d", current, resp.StatusCode)
		}
		ensuredDirs.Store(current, struct{}{})
	}
	return nil
}
