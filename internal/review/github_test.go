package review

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestPublishGitHubStickyComment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		comments     []GitHubComment
		wantAction   string
		wantCreates  int
		wantUpdates  int
		wantExisting bool
	}{
		{
			name:        "creates when missing",
			wantAction:  "created sticky comment",
			wantCreates: 1,
		},
		{
			name:         "updates existing marked comment",
			comments:     []GitHubComment{{ID: 42, Body: DefaultStickyCommentMarker + "\nold"}},
			wantAction:   "updated sticky comment",
			wantUpdates:  1,
			wantExisting: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := &fakeGitHubClient{comments: tt.comments}
			action, err := PublishGitHubStickyComment(context.Background(), client, GitHubReviewRequest{
				Repo:        "owner/repo",
				PullRequest: 7,
				Marker:      DefaultStickyCommentMarker,
				Body:        DefaultStickyCommentMarker + "\nbody",
			})
			if err != nil {
				t.Fatalf("publish comment: %v", err)
			}
			if action.Action != tt.wantAction || action.ExistingFound != tt.wantExisting {
				t.Fatalf("action = %+v, want action %q existing %v", action, tt.wantAction, tt.wantExisting)
			}
			if client.creates != tt.wantCreates || client.updates != tt.wantUpdates {
				t.Fatalf("creates/updates = %d/%d, want %d/%d", client.creates, client.updates, tt.wantCreates, tt.wantUpdates)
			}
		})
	}
}

func TestPublishGitHubStickyCommentDryRunDoesNotCallClient(t *testing.T) {
	t.Parallel()

	action, err := PublishGitHubStickyComment(context.Background(), nil, GitHubReviewRequest{
		Repo:        "owner/repo",
		PullRequest: 7,
		Marker:      DefaultStickyCommentMarker,
		Body:        DefaultStickyCommentMarker + "\nbody",
		DryRun:      true,
	})
	if err != nil {
		t.Fatalf("dry-run publish: %v", err)
	}
	if action.Action != "dry-run upsert sticky comment" || action.BodyBytes == 0 {
		t.Fatalf("unexpected dry-run action: %+v", action)
	}
}

func TestParseGitHubEventContext(t *testing.T) {
	t.Parallel()

	got, err := ParseGitHubEventContext(strings.NewReader(`{
  "number": 12,
  "pull_request": {
    "number": 12,
    "head": {"sha": "abcdef1234567890"}
  }
}`))
	if err != nil {
		t.Fatalf("parse event: %v", err)
	}
	if got.PullRequest != 12 || got.CommitSHA != "abcdef1234567890" {
		t.Fatalf("event context = %+v", got)
	}
}

func TestResolveTokenSpec(t *testing.T) {
	t.Parallel()

	token, err := ResolveTokenSpec("env:GITHUB_TOKEN", func(name string) string {
		if name == "GITHUB_TOKEN" {
			return "secret-token"
		}
		return ""
	})
	if err != nil {
		t.Fatalf("resolve token: %v", err)
	}
	if token != "secret-token" {
		t.Fatalf("token = %q", token)
	}
}

func TestHTTPGitHubClientRequests(t *testing.T) {
	t.Parallel()

	var requests []apiRequest
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&body)
		}
		mu.Lock()
		requests = append(requests, apiRequest{Method: r.Method, Path: r.URL.RequestURI(), Body: body})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(`[{"id":99,"body":"<!-- changegate-review -->\nold"}]`))
		case http.MethodPatch:
			_, _ = w.Write([]byte(`{"id":99,"body":"updated"}`))
		default:
			t.Fatalf("unexpected method: %s", r.Method)
		}
	}))
	defer server.Close()

	client := NewHTTPGitHubClient("token")
	client.SetBaseURL(server.URL)
	action, err := PublishGitHubStickyComment(context.Background(), client, GitHubReviewRequest{
		Repo:        "owner/repo",
		PullRequest: 5,
		Marker:      DefaultStickyCommentMarker,
		Body:        DefaultStickyCommentMarker + "\nnew body",
	})
	if err != nil {
		t.Fatalf("publish via HTTP client: %v", err)
	}
	if action.Action != "updated sticky comment" || action.CommentID != 99 {
		t.Fatalf("action = %+v", action)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []apiRequest{
		{Method: http.MethodGet, Path: "/repos/owner/repo/issues/5/comments?per_page=100&page=1"},
		{Method: http.MethodPatch, Path: "/repos/owner/repo/issues/comments/99", Body: map[string]string{"body": DefaultStickyCommentMarker + "\nnew body"}},
	}
	if len(requests) != len(want) {
		t.Fatalf("request count = %d, want %d: %+v", len(requests), len(want), requests)
	}
	for i := range want {
		if requests[i].Method != want[i].Method || requests[i].Path != want[i].Path {
			t.Fatalf("request %d = %+v, want %+v", i, requests[i], want[i])
		}
		if want[i].Body != nil && requests[i].Body["body"] != want[i].Body["body"] {
			t.Fatalf("request %d body = %+v, want %+v", i, requests[i].Body, want[i].Body)
		}
	}
}

type fakeGitHubClient struct {
	comments []GitHubComment
	creates  int
	updates  int
}

func (f *fakeGitHubClient) ListIssueComments(context.Context, string, int) ([]GitHubComment, error) {
	return append([]GitHubComment{}, f.comments...), nil
}

func (f *fakeGitHubClient) CreateIssueComment(_ context.Context, _ string, _ int, body string) (GitHubComment, error) {
	f.creates++
	return GitHubComment{ID: 100, Body: body}, nil
}

func (f *fakeGitHubClient) UpdateIssueComment(_ context.Context, _ string, commentID int64, body string) (GitHubComment, error) {
	f.updates++
	return GitHubComment{ID: commentID, Body: body}, nil
}

type apiRequest struct {
	Method string
	Path   string
	Body   map[string]string
}
