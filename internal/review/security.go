package review

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

const (
	maxProviderRequestBodyBytes  = 256 * 1024
	maxProviderResponseBodyBytes = 1024 * 1024
	maxProviderErrorBodyBytes    = 4096
)

var sensitiveAssignmentPattern = regexp.MustCompile(`(?i)(authorization|private-token|token|access_token|client_secret|password)(["'\s:=]+)([^"'\s,}]+)`)

func marshalProviderRequest(provider string, body any) (io.Reader, error) {
	if body == nil {
		return nil, nil
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("encode %s request: %w", provider, err)
	}
	if len(buf) > maxProviderRequestBodyBytes {
		return nil, fmt.Errorf("%s request body is %d bytes; maximum is %d bytes", provider, len(buf), maxProviderRequestBodyBytes)
	}
	return bytes.NewReader(buf), nil
}

func decodeProviderResponse(provider string, r io.Reader, out any) error {
	if out == nil {
		return nil
	}
	body, err := readLimited(r, maxProviderResponseBodyBytes)
	if err != nil {
		return fmt.Errorf("read %s response: %w", provider, err)
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode %s response: %w", provider, err)
	}
	return nil
}

func providerError(provider string, method string, path string, status string, body io.Reader, secrets ...string) error {
	limited, err := readLimited(body, maxProviderErrorBodyBytes)
	if err != nil {
		return fmt.Errorf("%s API %s %s failed with %s: read error body: %w", provider, method, path, status, err)
	}
	message := redactSensitiveText(strings.TrimSpace(string(limited)), secrets...)
	return fmt.Errorf("%s API %s %s failed with %s: %s", provider, method, path, status, message)
}

func readLimited(r io.Reader, maxBytes int64) ([]byte, error) {
	if r == nil {
		return nil, nil
	}
	limited := io.LimitReader(r, maxBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("body exceeds %d bytes", maxBytes)
	}
	return body, nil
}

func redactSensitiveText(value string, secrets ...string) string {
	out := value
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		out = strings.ReplaceAll(out, secret, "(redacted)")
	}
	return sensitiveAssignmentPattern.ReplaceAllString(out, `${1}${2}(redacted)`)
}
