package publicaccess

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openshift-online/gecko/orlop/pkg/apiserver/types"

	runtimeschema "k8s.io/apimachinery/pkg/runtime/schema"
)

func TestIsAuthorizationExemptRequest(t *testing.T) {
	resources := []types.ResourceInfo{
		{
			GVK:                      runtimeschema.GroupVersionKind{Group: "gcp.managed.openshift.io", Version: "v1", Kind: "Version"},
			Plural:                   "versions",
			Verbs:                    []string{"get", "list"},
			AuthorizationExemptVerbs: []string{"get", "list"},
		},
		{
			GVK:                      runtimeschema.GroupVersionKind{Group: "gcp.managed.openshift.io", Version: "v1", Kind: "Channel"},
			Plural:                   "channels",
			Verbs:                    []string{"get", "list"},
			AuthorizationExemptVerbs: []string{"get", "list"},
		},
		{
			GVK:                      runtimeschema.GroupVersionKind{Group: "gcp.managed.openshift.io", Version: "v1", Kind: "WatchableCatalog"},
			Plural:                   "watchablecatalogs",
			Verbs:                    []string{"get", "list", "watch"},
			AuthorizationExemptVerbs: []string{"get", "list", "watch"},
		},
		{
			GVK:                      runtimeschema.GroupVersionKind{Group: "gcp.managed.openshift.io", Version: "v1", Kind: "Bootstrap"},
			Plural:                   "bootstraps",
			Verbs:                    []string{"create", "get", "list", "update", "patch", "delete"},
			AuthorizationExemptVerbs: []string{"create", "get", "list", "update", "patch", "delete"},
		},
		{
			GVK:    runtimeschema.GroupVersionKind{Group: "gcp.managed.openshift.io", Version: "v1", Kind: "Unmarked"},
			Plural: "unmarkedresources",
			Verbs:  []string{"get", "list"},
		},
		{
			GVK:                      runtimeschema.GroupVersionKind{Group: "gcp.managed.openshift.io", Version: "v1", Kind: "Namespaced"},
			Plural:                   "namespacedresources",
			Namespaced:               true,
			Verbs:                    []string{"get", "list"},
			AuthorizationExemptVerbs: []string{"get", "list"},
		},
	}

	tests := []struct {
		name   string
		method string
		path   string
		allow  bool
	}{
		{name: "list versions", method: http.MethodGet, path: "/apis/gcp.managed.openshift.io/v1/versions", allow: true},
		{name: "get version", method: http.MethodGet, path: "/apis/gcp.managed.openshift.io/v1/versions/4.22.1", allow: true},
		{name: "list channels", method: http.MethodGet, path: "/apis/gcp.managed.openshift.io/v1/channels", allow: true},
		{name: "get channel", method: http.MethodGet, path: "/apis/gcp.managed.openshift.io/v1/channels/stable", allow: true},
		{name: "watch excluded by verbs", method: http.MethodGet, path: "/apis/gcp.managed.openshift.io/v1/versions?watch=true"},
		{name: "watch allowed by verbs", method: http.MethodGet, path: "/apis/gcp.managed.openshift.io/v1/watchablecatalogs?watch=true", allow: true},
		{name: "list with watch false", method: http.MethodGet, path: "/apis/gcp.managed.openshift.io/v1/versions?watch=false", allow: true},
		{name: "create collection", method: http.MethodPost, path: "/apis/gcp.managed.openshift.io/v1/versions"},
		{name: "authorization-exempt create", method: http.MethodPost, path: "/apis/gcp.managed.openshift.io/v1/bootstraps", allow: true},
		{name: "authorization-exempt update", method: http.MethodPut, path: "/apis/gcp.managed.openshift.io/v1/bootstraps/example", allow: true},
		{name: "authorization-exempt patch", method: http.MethodPatch, path: "/apis/gcp.managed.openshift.io/v1/bootstraps/example", allow: true},
		{name: "authorization-exempt delete", method: http.MethodDelete, path: "/apis/gcp.managed.openshift.io/v1/bootstraps/example", allow: true},
		{name: "update item", method: http.MethodPut, path: "/apis/gcp.managed.openshift.io/v1/versions/4.22.1"},
		{name: "status subresource", method: http.MethodGet, path: "/apis/gcp.managed.openshift.io/v1/versions/4.22.1/status"},
		{name: "different group", method: http.MethodGet, path: "/apis/other.example.io/v1/versions/4.22.1"},
		{name: "unmarked resource", method: http.MethodGet, path: "/apis/gcp.managed.openshift.io/v1/unmarkedresources"},
		{name: "namespaced resource without namespace", method: http.MethodGet, path: "/apis/gcp.managed.openshift.io/v1/namespacedresources"},
		{name: "namespaced collection", method: http.MethodGet, path: "/apis/gcp.managed.openshift.io/v1/namespaces/project-a/namespacedresources", allow: true},
		{name: "namespaced item", method: http.MethodGet, path: "/apis/gcp.managed.openshift.io/v1/namespaces/project-a/namespacedresources/example", allow: true},
		{name: "namespace route", method: http.MethodGet, path: "/apis/gcp.managed.openshift.io/v1/namespaces/project-a/versions"},
		{name: "extra path segment", method: http.MethodGet, path: "/apis/gcp.managed.openshift.io/v1/versions/4.22.1/status/extra"},
		{name: "non-canonical path", method: http.MethodGet, path: "/apis/gcp.managed.openshift.io/v1//versions"},
		{name: "traversal path", method: http.MethodGet, path: "/apis/gcp.managed.openshift.io/v1/versions/../clusters"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequestWithContext(context.Background(), tt.method, tt.path, nil)
			if got := IsAuthorizationExemptRequest(request, resources); got != tt.allow {
				t.Fatalf("IsAuthorizationExemptRequest() = %v, want %v", got, tt.allow)
			}
		})
	}
}
