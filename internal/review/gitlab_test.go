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

func TestPublishGitLabStickyNote(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		notes        []GitLabNote
		wantAction   string
		wantCreates  int
		wantUpdates  int
		wantExisting bool
	}{
		{
			name:        "creates when missing",
			wantAction:  "created sticky note",
			wantCreates: 1,
		},
		{
			name:         "updates existing marked note",
			notes:        []GitLabNote{{ID: 42, Body: DefaultStickyCommentMarker + "\nold"}},
			wantAction:   "updated sticky note",
			wantUpdates:  1,
			wantExisting: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := &fakeGitLabClient{notes: tt.notes}
			action, err := PublishGitLabStickyNote(context.Background(), client, GitLabReviewRequest{
				Project:         "123",
				MergeRequestIID: 7,
				Marker:          DefaultStickyCommentMarker,
				Body:            DefaultStickyCommentMarker + "\nbody",
			})
			if err != nil {
				t.Fatalf("publish note: %v", err)
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

func TestPublishGitLabStickyNoteDryRunDoesNotCallClient(t *testing.T) {
	t.Parallel()

	action, err := PublishGitLabStickyNote(context.Background(), nil, GitLabReviewRequest{
		Project:         "123",
		MergeRequestIID: 7,
		Marker:          DefaultStickyCommentMarker,
		Body:            DefaultStickyCommentMarker + "\nbody",
		DryRun:          true,
	})
	if err != nil {
		t.Fatalf("dry-run publish: %v", err)
	}
	if action.Action != "dry-run upsert sticky note" || action.BodyBytes == 0 {
		t.Fatalf("unexpected dry-run action: %+v", action)
	}
}

func TestDetectGitLabEnvironmentAndCodeQualityURL(t *testing.T) {
	t.Parallel()

	env := DetectGitLabEnvironment(func(name string) string {
		values := map[string]string{
			"GITLAB_TOKEN":         "token",
			"CI_API_V4_URL":        "https://gitlab.example/api/v4",
			"CI_PROJECT_ID":        "123",
			"CI_PROJECT_URL":       "https://gitlab.example/group/project",
			"CI_MERGE_REQUEST_IID": "9",
			"CI_COMMIT_SHA":        "abcdef",
			"CI_JOB_ID":            "77",
		}
		return values[name]
	})
	if env.Token != "token" || env.ProjectID != "123" || env.MergeRequestIID != "9" {
		t.Fatalf("env = %+v", env)
	}
	got := GitLabCodeQualityArtifactURL(env, "reports/gl-code-quality.json")
	want := "https://gitlab.example/group/project/-/jobs/77/artifacts/file/reports/gl-code-quality.json"
	if got != want {
		t.Fatalf("code quality URL = %q, want %q", got, want)
	}
}

func TestHTTPGitLabClientRequests(t *testing.T) {
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
		case http.MethodPut:
			_, _ = w.Write([]byte(`{"id":99,"body":"updated"}`))
		default:
			t.Fatalf("unexpected method: %s", r.Method)
		}
	}))
	defer server.Close()

	client := NewHTTPGitLabClient("token")
	client.SetBaseURL(server.URL)
	action, err := PublishGitLabStickyNote(context.Background(), client, GitLabReviewRequest{
		Project:         "group/project",
		MergeRequestIID: 5,
		Marker:          DefaultStickyCommentMarker,
		Body:            DefaultStickyCommentMarker + "\nnew body",
	})
	if err != nil {
		t.Fatalf("publish via HTTP client: %v", err)
	}
	if action.Action != "updated sticky note" || action.NoteID != 99 {
		t.Fatalf("action = %+v", action)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []apiRequest{
		{Method: http.MethodGet, Path: "/projects/group%2Fproject/merge_requests/5/notes?per_page=100&page=1"},
		{Method: http.MethodPut, Path: "/projects/group%2Fproject/merge_requests/5/notes/99", Body: map[string]string{"body": DefaultStickyCommentMarker + "\nnew body"}},
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

func TestRenderGitLabReviewActions(t *testing.T) {
	t.Parallel()

	got := RenderGitLabReviewActions([]GitLabReviewAction{{
		Action:          "dry-run upsert sticky note",
		Project:         "123",
		MergeRequestIID: 9,
		BodyBytes:       44,
	}})
	for _, want := range []string{"ChangeGate GitLab review actions", "123!9", "body_bytes=44"} {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q:\n%s", want, got)
		}
	}
}

type fakeGitLabClient struct {
	notes   []GitLabNote
	creates int
	updates int
}

func (f *fakeGitLabClient) ListMergeRequestNotes(context.Context, string, int) ([]GitLabNote, error) {
	return append([]GitLabNote{}, f.notes...), nil
}

func (f *fakeGitLabClient) CreateMergeRequestNote(_ context.Context, _ string, _ int, body string) (GitLabNote, error) {
	f.creates++
	return GitLabNote{ID: 100, Body: body}, nil
}

func (f *fakeGitLabClient) UpdateMergeRequestNote(_ context.Context, _ string, _ int, noteID int64, body string) (GitLabNote, error) {
	f.updates++
	return GitLabNote{ID: noteID, Body: body}, nil
}
