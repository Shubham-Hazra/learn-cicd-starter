package auth

import (
	"errors"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		"Valid Authorization Header": {
			headers:       http.Header{"Authorization": []string{"ApiKey abc123"}},
			expectedKey:   "abc123",
			expectedError: nil,
		},
		"No Authorization Header": {
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		"Malformed Authorization Header - Missing ApiKey": {
			headers:       http.Header{"Authorization": []string{"Bearer abc123"}},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		"Malformed Authorization Header - No Key Provided": {
			headers:       http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		"Empty Authorization Header": {
			headers:       http.Header{"Authorization": []string{""}},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		"Multiple Spaces in Authorization Header": {
			headers:       http.Header{"Authorization": []string{"ApiKey  abc123"}},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		"Case Sensitivity in Prefix": {
			headers:       http.Header{"Authorization": []string{"apikey abc123"}},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tc.headers)

			if diff := cmp.Diff(tc.expectedKey, gotKey); diff != "" {
				t.Errorf("unexpected key (-want +got):\n%s", diff)
			}

			if diff := cmp.Diff(tc.expectedError, gotErr, cmp.Comparer(func(x, y error) bool {
				if x == nil || y == nil {
					return x == y
				}
				return x.Error() == y.Error()
			})); diff != "" {
				t.Errorf("unexpected error (-want +got):\n%s", diff)
			}
		})
	}
}
