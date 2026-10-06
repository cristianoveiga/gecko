package publicaccess

import (
	"net/http"
	"path"
	"strings"

	"github.com/openshift-online/gecko/orlop/pkg/apiserver/types"
)

// IsAuthorizationExemptRequest reports whether the request targets a resource
// operation explicitly configured for authorization-exempt access.
func IsAuthorizationExemptRequest(r *http.Request, resources []types.ResourceInfo) bool {
	if r == nil || r.URL == nil {
		return false
	}
	rawPath := r.URL.Path
	if rawPath == "" || !strings.HasPrefix(rawPath, "/") || path.Clean(rawPath) != rawPath || strings.Contains(rawPath, "..") {
		return false
	}
	parts := strings.Split(strings.Trim(rawPath, "/"), "/")
	if len(parts) < 4 || parts[0] != "apis" || parts[1] == "" || parts[2] == "" {
		return false
	}

	for _, resource := range resources {
		if resource.GVK.Group != parts[1] || resource.GVK.Version != parts[2] {
			continue
		}

		resourcePath, found := resourcePathForRequest(parts, resource)
		if !found {
			continue
		}
		verb, found := requestVerb(r, resourcePath)
		return found && resource.AuthorizationExemptVerbAllowed(verb)
	}
	return false
}

func resourcePathForRequest(parts []string, resource types.ResourceInfo) ([]string, bool) {
	if resource.Namespaced {
		if len(parts) != 6 && len(parts) != 7 || parts[3] != "namespaces" || parts[4] == "" || parts[5] != resource.Plural {
			return nil, false
		}
		return parts[5:], true
	}
	if (len(parts) != 4 && len(parts) != 5) || parts[3] != resource.Plural {
		return nil, false
	}
	return parts[3:], true
}

func requestVerb(r *http.Request, resourcePath []string) (string, bool) {
	if len(resourcePath) == 1 {
		switch r.Method {
		case http.MethodGet:
			if r.URL.Query().Get("watch") == "true" {
				return "watch", true
			}
			return "list", true
		case http.MethodPost:
			return "create", true
		}
		return "", false
	}
	if len(resourcePath) != 2 || resourcePath[1] == "" {
		return "", false
	}
	switch r.Method {
	case http.MethodGet:
		return "get", true
	case http.MethodPut:
		return "update", true
	case http.MethodPatch:
		return "patch", true
	case http.MethodDelete:
		return "delete", true
	}
	return "", false
}
