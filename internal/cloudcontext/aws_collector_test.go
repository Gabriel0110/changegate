package cloudcontext

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAWSCollectorCollectsIdentityAndRegions(t *testing.T) {
	t.Parallel()

	collector := NewAWSCollectorWithClients(fakeAWSClientSet{
		identity: AWSCallerIdentity{AccountID: "123456789012", ARN: "arn:aws:iam::123456789012:role/ChangeGateReadOnly"},
		regions:  []Region{{Name: "us-west-2", Enabled: true}, {Name: "us-east-1", Enabled: true}},
	})
	snapshot, diagnostics, err := collector.Collect(context.Background(), AWSCollectRequest{
		Groups: []string{CollectIdentity, CollectNetwork},
		Now:    time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(diagnostics) != 0 {
		t.Fatalf("diagnostics = %+v, want none", diagnostics)
	}
	if snapshot.Version != Version || snapshot.Provider != ProviderAWS {
		t.Fatalf("unexpected snapshot identity: %+v", snapshot)
	}
	if snapshot.Account.ID != "123456789012" || snapshot.Account.ARN == "" {
		t.Fatalf("account not collected: %+v", snapshot.Account)
	}
	if !snapshot.Capabilities.Identity {
		t.Fatalf("identity capability was not set")
	}
	if len(snapshot.Regions) != 2 || snapshot.Regions[0].Name != "us-east-1" {
		t.Fatalf("regions not sorted: %+v", snapshot.Regions)
	}
}

func TestAWSCollectorPermissionFailuresBecomeDiagnostics(t *testing.T) {
	t.Parallel()

	collector := NewAWSCollectorWithClients(fakeAWSClientSet{
		identityErr: errors.New("access denied"),
		regionsErr:  errors.New("unauthorized"),
	})
	snapshot, diagnostics, err := collector.Collect(context.Background(), AWSCollectRequest{
		Groups: []string{CollectIdentity, CollectNetwork, CollectIAM},
		Now:    time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if snapshot.Account.ID != "" || snapshot.Capabilities.Identity {
		t.Fatalf("failed identity should not set account/capability: %+v", snapshot)
	}
	if len(diagnostics) != 3 {
		t.Fatalf("diagnostics = %+v, want identity, regions, pending iam", diagnostics)
	}
	if snapshot.Diagnostics[0].Code != "AWS_COLLECT_IDENTITY_FAILED" {
		t.Fatalf("snapshot diagnostics not attached: %+v", snapshot.Diagnostics)
	}
}

func TestAWSCollectorCancellationBecomesDiagnostics(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	collector := NewAWSCollectorWithClients(fakeAWSClientSet{
		identityErr: context.Canceled,
		regionsErr:  context.Canceled,
	})
	_, diagnostics, err := collector.Collect(ctx, AWSCollectRequest{Groups: []string{CollectIdentity, CollectNetwork}})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(diagnostics) != 2 {
		t.Fatalf("diagnostics = %+v, want two cancellation diagnostics", diagnostics)
	}
}

func TestAWSCollectorUsesExplicitRegionsWithoutRegionDiscovery(t *testing.T) {
	t.Parallel()

	collector := NewAWSCollectorWithClients(fakeAWSClientSet{
		identity: AWSCallerIdentity{AccountID: "123456789012"},
		regions:  []Region{{Name: "should-not-be-used", Enabled: true}},
	})
	snapshot, diagnostics, err := collector.Collect(context.Background(), AWSCollectRequest{
		Groups:  []string{CollectIdentity},
		Regions: []string{"us-west-2", "us-east-1"},
	})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(diagnostics) != 0 {
		t.Fatalf("diagnostics = %+v, want none", diagnostics)
	}
	if len(snapshot.Regions) != 2 || snapshot.Regions[0].Name != "us-east-1" || snapshot.Regions[1].Name != "us-west-2" {
		t.Fatalf("explicit regions not normalized: %+v", snapshot.Regions)
	}
}

func TestParseCollectGroupsAndRegions(t *testing.T) {
	t.Parallel()

	groups, err := ParseCollectGroups("network,identity,network")
	if err != nil {
		t.Fatalf("ParseCollectGroups returned error: %v", err)
	}
	if strings.Join(groups, ",") != "identity,network" {
		t.Fatalf("groups = %v", groups)
	}
	all, err := ParseCollectGroups("all")
	if err != nil {
		t.Fatalf("ParseCollectGroups all returned error: %v", err)
	}
	if len(all) != 6 {
		t.Fatalf("all groups = %v", all)
	}
	if _, err := ParseCollectGroups("secrets"); err == nil {
		t.Fatalf("expected unsupported group error")
	}
	regions := ParseRegions("us-west-2, us-east-1,us-west-2")
	if strings.Join(regions, ",") != "us-east-1,us-west-2" {
		t.Fatalf("regions = %v", regions)
	}
}

type fakeAWSClientSet struct {
	identity    AWSCallerIdentity
	identityErr error
	regions     []Region
	regionsErr  error
}

func (f fakeAWSClientSet) CallerIdentity(context.Context) (AWSCallerIdentity, error) {
	if f.identityErr != nil {
		return AWSCallerIdentity{}, f.identityErr
	}
	return f.identity, nil
}

func (f fakeAWSClientSet) EnabledRegions(context.Context) ([]Region, error) {
	if f.regionsErr != nil {
		return nil, f.regionsErr
	}
	return f.regions, nil
}
