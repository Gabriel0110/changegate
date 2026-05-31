package cloudcontext

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Gabriel0110/changegate/internal/model"
	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

func TestAWSCollectorCollectsIdentityAndRegions(t *testing.T) {
	t.Parallel()

	collector := NewAWSCollectorWithClients(fakeAWSClientSet{
		identity: AWSCallerIdentity{AccountID: "123456789012", ARN: "arn:aws:iam::123456789012:role/ChangeGateReadOnly"},
		regions:  []Region{{Name: "us-west-2", Enabled: true}, {Name: "us-east-1", Enabled: true}},
		network: AWSInventory{Network: ResourceSet{Resources: map[string]Resource{
			"subnet-public": {
				ID:     "subnet-public",
				Type:   "aws_subnet",
				Region: "us-east-1",
				Public: boolPtr(true),
			},
		}}, Relationships: []Relationship{{From: "internet", To: "rtb-public", Type: "routes_to", Source: relationshipSourceEC2, Confidence: "high"}}},
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
	if !snapshot.Capabilities.Network || !snapshot.Capabilities.SecurityGroups {
		t.Fatalf("network capabilities were not set: %+v", snapshot.Capabilities)
	}
	if snapshot.Network.Resources["subnet-public"].Public == nil || !*snapshot.Network.Resources["subnet-public"].Public {
		t.Fatalf("network inventory was not merged: %+v", snapshot.Network.Resources)
	}
	if len(snapshot.Relationships) != 2 {
		t.Fatalf("relationships were not merged: %+v", snapshot.Relationships)
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
	if len(diagnostics) != 2 {
		t.Fatalf("diagnostics = %+v, want identity and regions", diagnostics)
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

func TestAWSCollectorMergesEdgeInventory(t *testing.T) {
	t.Parallel()

	albARN := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/admin/abc"
	collector := NewAWSCollectorWithClients(fakeAWSClientSet{
		identity: AWSCallerIdentity{AccountID: "123456789012"},
		edge: AWSInventory{Edge: ResourceSet{Resources: map[string]Resource{
			albARN: {
				ARN:    albARN,
				Type:   "aws_lb",
				Region: "us-east-1",
				Public: boolPtr(true),
			},
		}}, Relationships: []Relationship{{From: "internet", To: albARN, Type: "routes_to", Source: relationshipSourceELBV2, Confidence: "high"}}},
	})
	snapshot, diagnostics, err := collector.Collect(context.Background(), AWSCollectRequest{
		Groups:  []string{CollectIdentity, CollectEdge},
		Regions: []string{"us-east-1"},
	})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(diagnostics) != 0 {
		t.Fatalf("diagnostics = %+v, want none", diagnostics)
	}
	if snapshot.Edge.Resources[albARN].Public == nil || !*snapshot.Edge.Resources[albARN].Public {
		t.Fatalf("edge inventory was not merged: %+v", snapshot.Edge.Resources)
	}
	if len(snapshot.Relationships) != 1 || snapshot.Relationships[0].Source != relationshipSourceELBV2 {
		t.Fatalf("edge relationships were not merged: %+v", snapshot.Relationships)
	}
}

func TestAWSCollectorNetworkAndEdgeFailuresBecomeDiagnostics(t *testing.T) {
	t.Parallel()

	collector := NewAWSCollectorWithClients(fakeAWSClientSet{
		identity:   AWSCallerIdentity{AccountID: "123456789012"},
		networkErr: errors.New("ec2 denied"),
		edgeErr:    errors.New("elbv2 denied"),
	})
	snapshot, diagnostics, err := collector.Collect(context.Background(), AWSCollectRequest{
		Groups:  []string{CollectIdentity, CollectNetwork, CollectEdge},
		Regions: []string{"us-east-1"},
	})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if snapshot.Capabilities.Network || snapshot.Capabilities.SecurityGroups {
		t.Fatalf("failed collectors should not set capabilities: %+v", snapshot.Capabilities)
	}
	if len(diagnostics) != 2 {
		t.Fatalf("diagnostics = %+v, want network and edge diagnostics", diagnostics)
	}
	if diagnostics[0].Code != "AWS_COLLECT_EDGE_FAILED" && diagnostics[1].Code != "AWS_COLLECT_EDGE_FAILED" {
		t.Fatalf("missing edge diagnostic: %+v", diagnostics)
	}
}

func TestAWSCollectorMergesIAMComputeAndDataInventory(t *testing.T) {
	t.Parallel()

	roleARN := "arn:aws:iam::123456789012:role/Admin"
	functionARN := "arn:aws:lambda:us-east-1:123456789012:function:admin"
	dbARN := "arn:aws:rds:us-east-1:123456789012:db:customer-prod"
	collector := NewAWSCollectorWithClients(fakeAWSClientSet{
		identity: AWSCallerIdentity{AccountID: "123456789012"},
		iam: AWSInventory{IAM: ResourceSet{Resources: map[string]Resource{
			roleARN: {ARN: roleARN, Type: "aws_iam_role", ObservedPolicyActions: []string{"*"}},
		}}, Relationships: []Relationship{{From: roleARN, To: "action:*", Type: "grants_action", Source: relationshipSourceIAM, Confidence: "high"}}},
		compute: AWSInventory{Compute: ResourceSet{Resources: map[string]Resource{
			functionARN: {ARN: functionARN, Type: "aws_lambda_function"},
		}}, Relationships: []Relationship{{From: functionARN, To: roleARN, Type: "uses_role", Source: relationshipSourceLambda, Confidence: "high"}}},
		data: AWSInventory{Data: ResourceSet{Resources: map[string]Resource{
			dbARN: {ARN: dbARN, Type: "aws_db_instance", Sensitivity: Sensitivity{Data: true, Reason: "resource metadata"}},
		}}, Relationships: []Relationship{{From: dbARN, To: "arn:aws:kms:us-east-1:123456789012:key/abc", Type: "uses_kms_key", Source: relationshipSourceRDS, Confidence: "high"}}},
	})
	snapshot, diagnostics, err := collector.Collect(context.Background(), AWSCollectRequest{
		Groups:  []string{CollectIdentity, CollectIAM, CollectCompute, CollectData},
		Regions: []string{"us-east-1"},
	})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(diagnostics) != 0 {
		t.Fatalf("diagnostics = %+v, want none", diagnostics)
	}
	if !snapshot.Capabilities.IAM || !snapshot.Capabilities.RDS || !snapshot.Capabilities.S3 || !snapshot.Capabilities.KMS || !snapshot.Capabilities.SecretsManager || !snapshot.Capabilities.EKS {
		t.Fatalf("capabilities not set: %+v", snapshot.Capabilities)
	}
	if snapshot.IAM.Resources[roleARN].ARN == "" || snapshot.Compute.Resources[functionARN].ARN == "" || !snapshot.Data.Resources[dbARN].Sensitivity.Data {
		t.Fatalf("inventory was not merged: iam=%+v compute=%+v data=%+v", snapshot.IAM.Resources, snapshot.Compute.Resources, snapshot.Data.Resources)
	}
	if len(snapshot.Relationships) != 3 {
		t.Fatalf("relationships = %+v, want IAM, compute, data relationships", snapshot.Relationships)
	}
}

func TestAWSCollectorIAMComputeDataFailuresBecomeDiagnostics(t *testing.T) {
	t.Parallel()

	collector := NewAWSCollectorWithClients(fakeAWSClientSet{
		identity:   AWSCallerIdentity{AccountID: "123456789012"},
		iamErr:     errors.New("iam denied"),
		computeErr: errors.New("compute denied"),
		dataErr:    errors.New("data denied"),
	})
	_, diagnostics, err := collector.Collect(context.Background(), AWSCollectRequest{
		Groups:  []string{CollectIdentity, CollectIAM, CollectCompute, CollectData},
		Regions: []string{"us-east-1"},
	})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	for _, code := range []string{"AWS_COLLECT_IAM_FAILED", "AWS_COLLECT_COMPUTE_FAILED", "AWS_COLLECT_DATA_FAILED"} {
		if !hasDiagnosticCode(diagnostics, code) {
			t.Fatalf("diagnostics missing %s: %+v", code, diagnostics)
		}
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

func TestIAMPolicyParserHighSignalShapes(t *testing.T) {
	t.Parallel()

	raw := url.QueryEscape(`{
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["iam:PassRole", "lambda:UpdateFunctionCode", "secretsmanager:GetSecretValue", "kms:Decrypt"],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Principal": {"AWS": "*"},
      "Resource": "*"
    }
  ]
}`)
	shape := parsePolicyDocument(raw)
	if !shape.PassRole || !shape.ComputeMutate || !shape.SecretRead || !shape.KMSAccess || !shape.AssumeRole || !shape.BroadAllow || !shape.PrincipalBroad {
		t.Fatalf("policy shape missing high-signal flags: %+v", shape)
	}
	if len(shape.Actions) != 5 {
		t.Fatalf("actions = %+v", shape.Actions)
	}
}

func TestInferSensitivityFromTagsAndMetadata(t *testing.T) {
	t.Parallel()

	if !inferSensitivity("aws_s3_bucket", "logs", map[string]string{"data_classification": "restricted"}).Data {
		t.Fatalf("restricted tag should infer sensitivity")
	}
	if !inferSensitivity("aws_db_instance", "customer-prod", nil).Data {
		t.Fatalf("customer-prod metadata should infer sensitivity")
	}
	if inferSensitivity("aws_s3_bucket", "dev-cache", map[string]string{"env": "dev"}).Data {
		t.Fatalf("dev cache should not infer sensitivity")
	}
}

func TestNetworkExposureHelpersClassifyRoutesAndSecurityGroups(t *testing.T) {
	t.Parallel()

	publicTable := ec2types.RouteTable{Routes: []ec2types.Route{{
		DestinationCidrBlock: aws.String("0.0.0.0/0"),
		GatewayId:            aws.String("igw-123"),
	}}}
	if !routeTablePublic(publicTable) {
		t.Fatalf("IGW default route should be public")
	}
	privateTable := ec2types.RouteTable{Routes: []ec2types.Route{{
		DestinationCidrBlock: aws.String("0.0.0.0/0"),
		NatGatewayId:         aws.String("nat-123"),
	}}}
	if routeTablePublic(privateTable) {
		t.Fatalf("NAT-only default route should not be public")
	}
	ports := publicIngressPorts([]ec2types.IpPermission{{
		FromPort:   aws.Int32(443),
		ToPort:     aws.Int32(443),
		IpProtocol: aws.String("tcp"),
		IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
	}})
	if len(ports) != 1 || ports[0] != "443" {
		t.Fatalf("public ingress ports = %v", ports)
	}
	privatePorts := publicIngressPorts([]ec2types.IpPermission{{
		FromPort:   aws.Int32(443),
		ToPort:     aws.Int32(443),
		IpProtocol: aws.String("tcp"),
		IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("10.0.0.0/8")}},
	}})
	if len(privatePorts) != 0 {
		t.Fatalf("private ingress should not produce public ports: %v", privatePorts)
	}
}

func TestEdgeTargetResourceIDs(t *testing.T) {
	t.Parallel()

	instanceTarget := targetResourceID(elbtypes.TargetTypeEnumInstance, "us-east-1", "123456789012", elbtypes.TargetHealthDescription{Target: &elbtypes.TargetDescription{Id: aws.String("i-123")}})
	if instanceTarget != "i-123" {
		t.Fatalf("instance target = %q", instanceTarget)
	}
	ipTarget := targetResourceID(elbtypes.TargetTypeEnumIp, "us-east-1", "123456789012", elbtypes.TargetHealthDescription{Target: &elbtypes.TargetDescription{Id: aws.String("10.0.1.10"), Port: aws.Int32(8080)}})
	if ipTarget != "10.0.1.10:8080" {
		t.Fatalf("ip target = %q", ipTarget)
	}
}

func hasDiagnosticCode(diagnostics []model.Diagnostic, code string) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code {
			return true
		}
	}
	return false
}

type fakeAWSClientSet struct {
	identity    AWSCallerIdentity
	identityErr error
	regions     []Region
	regionsErr  error
	network     AWSInventory
	networkErr  error
	edge        AWSInventory
	edgeErr     error
	iam         AWSInventory
	iamErr      error
	compute     AWSInventory
	computeErr  error
	data        AWSInventory
	dataErr     error
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

func (f fakeAWSClientSet) NetworkInventory(context.Context, string, string) (AWSInventory, error) {
	if f.networkErr != nil {
		return AWSInventory{}, f.networkErr
	}
	return f.network, nil
}

func (f fakeAWSClientSet) EdgeInventory(context.Context, string, string) (AWSInventory, error) {
	if f.edgeErr != nil {
		return AWSInventory{}, f.edgeErr
	}
	return f.edge, nil
}

func (f fakeAWSClientSet) IAMInventory(context.Context, string) (AWSInventory, error) {
	if f.iamErr != nil {
		return AWSInventory{}, f.iamErr
	}
	return f.iam, nil
}

func (f fakeAWSClientSet) ComputeInventory(context.Context, string, string) (AWSInventory, error) {
	if f.computeErr != nil {
		return AWSInventory{}, f.computeErr
	}
	return f.compute, nil
}

func (f fakeAWSClientSet) DataInventory(context.Context, string, string) (AWSInventory, error) {
	if f.dataErr != nil {
		return AWSInventory{}, f.dataErr
	}
	return f.data, nil
}
