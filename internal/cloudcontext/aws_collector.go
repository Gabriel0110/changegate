package cloudcontext

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Gabriel0110/changegate/internal/model"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const (
	// CollectAll requests every available AWS cloud-context collector group.
	CollectAll = "all"
	// CollectIdentity requests caller identity and account metadata.
	CollectIdentity = "identity"
	// CollectNetwork requests network inventory.
	CollectNetwork = "network"
	// CollectEdge requests public edge inventory.
	CollectEdge = "edge"
	// CollectIAM requests IAM inventory.
	CollectIAM = "iam"
	// CollectData requests data-service inventory.
	CollectData = "data"
	// CollectCompute requests compute inventory.
	CollectCompute = "compute"
)

// Collector collects a redacted offline cloud-context snapshot.
type Collector interface {
	Collect(ctx context.Context, req AWSCollectRequest) (Snapshot, []model.Diagnostic, error)
}

// AWSCollectRequest configures AWS snapshot collection.
type AWSCollectRequest struct {
	Profile string
	Regions []string
	Groups  []string
	Now     time.Time
}

// AWSCallerIdentity is safe caller identity metadata returned by STS.
type AWSCallerIdentity struct {
	AccountID string
	ARN       string
}

// AWSClientSet wraps read-only AWS APIs used by the collector foundation.
type AWSClientSet interface {
	CallerIdentity(ctx context.Context) (AWSCallerIdentity, error)
	EnabledRegions(ctx context.Context) ([]Region, error)
}

// AWSCollector is the production AWS cloud-context collector.
type AWSCollector struct {
	clients AWSClientSet
}

// NewAWSCollector creates an AWS collector backed by AWS SDK for Go v2 clients.
func NewAWSCollector(ctx context.Context, req AWSCollectRequest) (*AWSCollector, error) {
	region := firstNonEmpty(first(req.Regions), "us-east-1")
	options := []func(*config.LoadOptions) error{config.WithRegion(region)}
	if req.Profile != "" {
		options = append(options, config.WithSharedConfigProfile(req.Profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	return &AWSCollector{clients: newSDKAWSClientSet(cfg)}, nil
}

// NewAWSCollectorWithClients creates a collector with fake or custom AWS clients.
func NewAWSCollectorWithClients(clients AWSClientSet) *AWSCollector {
	return &AWSCollector{clients: clients}
}

// ParseCollectGroups parses the --collect group selector.
func ParseCollectGroups(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	seen := make(map[string]bool, len(parts))
	groups := make([]string, 0, len(parts))
	for _, part := range parts {
		group := strings.ToLower(strings.TrimSpace(part))
		if group == "" {
			continue
		}
		if group == CollectAll {
			return []string{CollectIdentity, CollectNetwork, CollectEdge, CollectIAM, CollectData, CollectCompute}, nil
		}
		if !validCollectGroup(group) {
			return nil, fmt.Errorf("unsupported AWS collect group %q", group)
		}
		if !seen[group] {
			seen[group] = true
			groups = append(groups, group)
		}
	}
	sort.Strings(groups)
	return groups, nil
}

// ParseRegions parses a comma-delimited AWS region selector.
func ParseRegions(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	regions := make([]string, 0, len(parts))
	seen := make(map[string]bool, len(parts))
	for _, part := range parts {
		region := strings.TrimSpace(part)
		if region == "" || seen[region] {
			continue
		}
		seen[region] = true
		regions = append(regions, region)
	}
	sort.Strings(regions)
	return regions
}

// Collect builds a deterministic, redacted AWS cloud-context snapshot.
func (c *AWSCollector) Collect(ctx context.Context, req AWSCollectRequest) (Snapshot, []model.Diagnostic, error) {
	if c == nil || c.clients == nil {
		return Snapshot{}, nil, fmt.Errorf("AWS collector clients are not configured")
	}
	groups, err := normalizeRequestGroups(req.Groups)
	if err != nil {
		return Snapshot{}, nil, err
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	snapshot := NewAWSSnapshot(Identity{}, now)
	snapshot.Diagnostics = nil
	diagnostics := make([]model.Diagnostic, 0)
	if hasGroup(groups, CollectIdentity) {
		identity, err := c.clients.CallerIdentity(ctx)
		if err != nil {
			diagnostics = append(diagnostics, warningDiagnostic("AWS_COLLECT_IDENTITY_FAILED", "collect AWS identity: "+err.Error()))
		} else {
			snapshot.Account.ID = identity.AccountID
			snapshot.Account.ARN = redactValue("account.arn", identity.ARN)
			snapshot.Capabilities.Identity = true
		}
	}
	regions := req.Regions
	if len(regions) == 0 {
		discovered, err := c.clients.EnabledRegions(ctx)
		if err != nil {
			diagnostics = append(diagnostics, warningDiagnostic("AWS_COLLECT_REGIONS_FAILED", "collect AWS enabled regions: "+err.Error()))
		} else {
			snapshot.Regions = discovered
		}
	} else {
		snapshot.Regions = regionsFromNames(regions)
	}
	diagnostics = append(diagnostics, pendingGroupDiagnostics(groups)...)
	sortRegions(snapshot.Regions)
	snapshot.Diagnostics = diagnostics
	Normalize(&snapshot)
	return snapshot, diagnostics, nil
}

type sdkAWSClientSet struct {
	sts *sts.Client
	ec2 *ec2.Client
}

func newSDKAWSClientSet(cfg aws.Config) *sdkAWSClientSet {
	return &sdkAWSClientSet{
		sts: sts.NewFromConfig(cfg),
		ec2: ec2.NewFromConfig(cfg),
	}
}

func (c *sdkAWSClientSet) CallerIdentity(ctx context.Context) (AWSCallerIdentity, error) {
	out, err := c.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return AWSCallerIdentity{}, err
	}
	return AWSCallerIdentity{AccountID: aws.ToString(out.Account), ARN: aws.ToString(out.Arn)}, nil
}

func (c *sdkAWSClientSet) EnabledRegions(ctx context.Context) ([]Region, error) {
	out, err := c.ec2.DescribeRegions(ctx, &ec2.DescribeRegionsInput{AllRegions: aws.Bool(false)})
	if err != nil {
		return nil, err
	}
	regions := make([]Region, 0, len(out.Regions))
	for _, region := range out.Regions {
		if region.RegionName == nil {
			continue
		}
		regions = append(regions, Region{Name: aws.ToString(region.RegionName), Enabled: regionOptedIn(region)})
	}
	sortRegions(regions)
	return regions, nil
}

func regionOptedIn(region ec2types.Region) bool {
	switch aws.ToString(region.OptInStatus) {
	case "opted-in", "opt-in-not-required", "":
		return true
	default:
		return false
	}
}

func normalizeRequestGroups(groups []string) ([]string, error) {
	if len(groups) == 0 {
		return []string{CollectIdentity}, nil
	}
	return ParseCollectGroups(strings.Join(groups, ","))
}

func validCollectGroup(group string) bool {
	switch group {
	case CollectIdentity, CollectNetwork, CollectEdge, CollectIAM, CollectData, CollectCompute:
		return true
	default:
		return false
	}
}

func hasGroup(groups []string, target string) bool {
	for _, group := range groups {
		if group == target {
			return true
		}
	}
	return false
}

func pendingGroupDiagnostics(groups []string) []model.Diagnostic {
	diagnostics := make([]model.Diagnostic, 0)
	for _, group := range groups {
		switch group {
		case CollectIdentity, CollectNetwork:
			continue
		case CollectEdge, CollectIAM, CollectData, CollectCompute:
			diagnostics = append(diagnostics, warningDiagnostic("AWS_COLLECT_GROUP_PENDING", "collector group "+group+" is selected but implemented in a later tranche"))
		}
	}
	return diagnostics
}

func regionsFromNames(names []string) []Region {
	regions := make([]Region, 0, len(names))
	for _, name := range names {
		if name == "" {
			continue
		}
		regions = append(regions, Region{Name: name, Enabled: true})
	}
	sortRegions(regions)
	return regions
}

func sortRegions(regions []Region) {
	sort.Slice(regions, func(i int, j int) bool {
		return regions[i].Name < regions[j].Name
	})
}

func warningDiagnostic(code string, message string) model.Diagnostic {
	return model.Diagnostic{Severity: model.DiagnosticWarning, Code: code, Message: message}
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
