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
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
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
	if !snapshot.Capabilities.RouteTables || !snapshot.Capabilities.NetworkInterfaces || !snapshot.Capabilities.TransitGateways {
		t.Fatalf("v2 network capabilities were not set: %+v", snapshot.Capabilities)
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
	if !snapshot.Capabilities.Edge || !snapshot.Capabilities.ELBv2 || !snapshot.Capabilities.CloudFront || !snapshot.Capabilities.APIGateway {
		t.Fatalf("edge capabilities were not set: %+v", snapshot.Capabilities)
	}
	if !snapshot.Capabilities.LambdaFunctionURLs {
		t.Fatalf("lambda function URL capability was not set: %+v", snapshot.Capabilities)
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
	if !snapshot.Capabilities.IAM || !snapshot.Capabilities.Compute || !snapshot.Capabilities.EC2 || !snapshot.Capabilities.ECS || !snapshot.Capabilities.Lambda || !snapshot.Capabilities.RDS || !snapshot.Capabilities.S3 || !snapshot.Capabilities.KMS || !snapshot.Capabilities.SecretsManager || !snapshot.Capabilities.EKS {
		t.Fatalf("capabilities not set: %+v", snapshot.Capabilities)
	}
	if !snapshot.Capabilities.IAMPermissionBoundaries || !snapshot.Capabilities.S3Protection || !snapshot.Capabilities.RDSSubnetGroups || !snapshot.Capabilities.KMSPolicies || !snapshot.Capabilities.SecretsPolicies || !snapshot.Capabilities.OpenSearch || !snapshot.Capabilities.ElastiCache || !snapshot.Capabilities.EFS {
		t.Fatalf("v2 capabilities not set: %+v", snapshot.Capabilities)
	}
	if snapshot.IAM.Resources[roleARN].ARN == "" || snapshot.Compute.Resources[functionARN].ARN == "" || !snapshot.Data.Resources[dbARN].Sensitivity.Data {
		t.Fatalf("inventory was not merged: iam=%+v compute=%+v data=%+v", snapshot.IAM.Resources, snapshot.Compute.Resources, snapshot.Data.Resources)
	}
	if len(snapshot.Relationships) != 3 {
		t.Fatalf("relationships = %+v, want IAM, compute, data relationships", snapshot.Relationships)
	}
}

func TestAWSCollectorAppliesTagFilters(t *testing.T) {
	t.Parallel()

	albARN := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/payments/abc"
	dbARN := "arn:aws:rds:us-east-1:123456789012:db:orders"
	policyARN := "arn:aws:iam::123456789012:policy/payments"
	collector := NewAWSCollectorWithClients(fakeAWSClientSet{
		identity: AWSCallerIdentity{AccountID: "123456789012"},
		edge: AWSInventory{Edge: ResourceSet{Resources: map[string]Resource{
			albARN: {ARN: albARN, Type: "aws_lb", Tags: map[string]string{"team": "payments", "environment": "prod"}},
			"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/unowned/def": {
				Type: "aws_lb", Tags: map[string]string{"team": "platform"},
			},
		}}, Relationships: []Relationship{
			{From: "internet", To: albARN, Type: "routes_to", Source: relationshipSourceELBV2, Confidence: "high"},
			{From: albARN, To: dbARN, Type: "routes_to", Source: relationshipSourceELBV2, Confidence: "medium"},
		}},
		data: AWSInventory{Data: ResourceSet{Resources: map[string]Resource{
			dbARN: {ARN: dbARN, Type: "aws_db_instance", Tags: map[string]string{"team": "payments", "environment": "prod"}},
		}}},
		iam: AWSInventory{IAM: ResourceSet{Resources: map[string]Resource{
			policyARN: {ARN: policyARN, Type: "aws_iam_policy", Tags: map[string]string{"team": "payments", "environment": "prod"}},
		}}, Relationships: []Relationship{{From: policyARN, To: "action:s3:GetObject", Type: "grants_action", Source: relationshipSourceIAM, Confidence: "high"}}},
	})
	filters, err := ParseTagFilters([]string{"team=payments", "environment"})
	if err != nil {
		t.Fatalf("ParseTagFilters returned error: %v", err)
	}
	snapshot, diagnostics, err := collector.Collect(context.Background(), AWSCollectRequest{
		Groups:     []string{CollectIdentity, CollectEdge, CollectData, CollectIAM},
		Regions:    []string{"us-east-1"},
		TagFilters: filters,
	})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(diagnostics) != 0 {
		t.Fatalf("diagnostics = %+v, want none", diagnostics)
	}
	if len(snapshot.Edge.Resources) != 1 || snapshot.Edge.Resources[albARN].ARN == "" {
		t.Fatalf("edge resources were not filtered by tag: %+v", snapshot.Edge.Resources)
	}
	if len(snapshot.Data.Resources) != 1 || snapshot.Data.Resources[dbARN].ARN == "" {
		t.Fatalf("data resources were not filtered by tag: %+v", snapshot.Data.Resources)
	}
	if len(snapshot.IAM.Resources) != 1 || snapshot.IAM.Resources[policyARN].ARN == "" {
		t.Fatalf("IAM resources were not filtered by tag: %+v", snapshot.IAM.Resources)
	}
	if len(snapshot.Relationships) != 2 {
		t.Fatalf("relationships = %+v, want internet edge and kept resource edge only", snapshot.Relationships)
	}
	for _, relationship := range snapshot.Relationships {
		if strings.HasPrefix(relationship.To, "action:") {
			t.Fatalf("relationship to omitted action pseudo-node survived tag filtering: %+v", snapshot.Relationships)
		}
	}
}

func TestAWSCollectorDataPolicyDiagnosticsReduceCoverage(t *testing.T) {
	t.Parallel()

	collector := NewAWSCollectorWithClients(fakeAWSClientSet{
		identity: AWSCallerIdentity{AccountID: "123456789012"},
		data: AWSInventory{
			Data: ResourceSet{Resources: map[string]Resource{
				"arn:aws:s3:::logs": {ARN: "arn:aws:s3:::logs", Type: "aws_s3_bucket"},
			}},
			Diagnostics: []model.Diagnostic{
				warningDiagnostic("AWS_COLLECT_S3_POLICY_FAILED", "collect S3 bucket policy for logs: access denied"),
				warningDiagnostic("AWS_COLLECT_SECRET_POLICY_FAILED", "collect Secrets Manager resource policy for arn:aws:secretsmanager:us-east-1:123456789012:secret/customer: access denied"),
				warningDiagnostic("AWS_COLLECT_KMS_POLICY_FAILED", "collect KMS key policy for key: access denied"),
			},
		},
	})
	snapshot, diagnostics, err := collector.Collect(context.Background(), AWSCollectRequest{
		Groups:  []string{CollectIdentity, CollectData},
		Regions: []string{"us-east-1"},
	})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	for _, code := range []string{"AWS_COLLECT_S3_POLICY_FAILED", "AWS_COLLECT_SECRET_POLICY_FAILED", "AWS_COLLECT_KMS_POLICY_FAILED"} {
		if !hasDiagnosticCode(diagnostics, code) {
			t.Fatalf("diagnostics missing %s: %+v", code, diagnostics)
		}
	}
	if !snapshot.Capabilities.S3 || !snapshot.Capabilities.KMS || !snapshot.Capabilities.SecretsManager {
		t.Fatalf("data service capabilities should remain true: %+v", snapshot.Capabilities)
	}
	if snapshot.Capabilities.S3Protection || snapshot.Capabilities.SecretsPolicies || snapshot.Capabilities.KMSPolicies {
		t.Fatalf("policy coverage should be incomplete after policy read diagnostics: %+v", snapshot.Capabilities)
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
	tagFilters, err := ParseTagFilters([]string{"team=payments", "environment"})
	if err != nil {
		t.Fatalf("ParseTagFilters returned error: %v", err)
	}
	if len(tagFilters) != 2 || tagFilters[0].Key != "environment" || tagFilters[0].HasValue || tagFilters[1].Value != "payments" {
		t.Fatalf("tag filters = %+v", tagFilters)
	}
	if _, err := ParseTagFilters([]string{"=payments"}); err == nil {
		t.Fatalf("expected missing tag key error")
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

func TestAPIGatewayAndS3EnrichmentHelpers(t *testing.T) {
	t.Parallel()

	uri := "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:123456789012:function:admin/invocations"
	target := apiIntegrationTarget(uri)
	if target != "arn:aws:lambda:us-east-1:123456789012:function:admin" {
		t.Fatalf("api integration target = %q", target)
	}
	if got := apiRouteIntegrationID("api-123", "integrations/int-456"); got != "api-123/integrations/int-456" {
		t.Fatalf("api route integration id = %q", got)
	}
	enabled, algorithm, kmsKey := s3EncryptionSummary(&s3types.ServerSideEncryptionConfiguration{
		Rules: []s3types.ServerSideEncryptionRule{{
			ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{
				SSEAlgorithm:   s3types.ServerSideEncryptionAwsKms,
				KMSMasterKeyID: aws.String("arn:aws:kms:us-east-1:123456789012:key/abc"),
			},
		}},
	})
	if !enabled || algorithm != string(s3types.ServerSideEncryptionAwsKms) || kmsKey == "" {
		t.Fatalf("s3 encryption summary = %v %q %q", enabled, algorithm, kmsKey)
	}
}

func TestRicherCloudContextNormalizationRedactsPolicyMetadata(t *testing.T) {
	t.Parallel()

	snapshot := Snapshot{
		Version:  Version,
		Provider: ProviderAWS,
		Data: ResourceSet{Resources: map[string]Resource{
			"arn:aws:secretsmanager:us-east-1:123456789012:secret/customer": {
				Type:                  "aws_secretsmanager_secret",
				Attributes:            map[string]string{"resource_policy": "contains private token material"},
				ObservedPolicyActions: []string{"secretsmanager:GetSecretValue"},
				Sensitivity:           Sensitivity{Data: true, Reason: "private customer secret"},
			},
		}},
		Relationships: []Relationship{{
			From:   "arn:aws:secretsmanager:us-east-1:123456789012:secret/customer",
			To:     "*",
			Type:   "grants_resource",
			Source: "aws_secretsmanager_private_policy",
		}},
	}
	Normalize(&snapshot)
	resource := snapshot.Data.Resources["arn:aws:secretsmanager:us-east-1:123456789012:secret/customer"]
	if resource.Attributes["resource_policy"] != "(sensitive)" || resource.Sensitivity.Reason != "(sensitive)" {
		t.Fatalf("sensitive policy metadata was not redacted: %+v", resource)
	}
	if snapshot.Relationships[0].Source != "(sensitive)" {
		t.Fatalf("relationship source was not redacted: %+v", snapshot.Relationships)
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
