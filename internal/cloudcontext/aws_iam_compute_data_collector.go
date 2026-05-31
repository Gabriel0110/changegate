package cloudcontext

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	secretstypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

const (
	relationshipSourceIAM     = "aws_iam"
	relationshipSourceECS     = "aws_ecs"
	relationshipSourceLambda  = "aws_lambda"
	relationshipSourceEC2Role = "aws_ec2_instance_profile"
	relationshipSourceEKS     = "aws_eks"
	relationshipSourceRDS     = "aws_rds"
	relationshipSourceS3      = "aws_s3"
	relationshipSourceSecrets = "aws_secretsmanager"
	relationshipSourceKMS     = "aws_kms"
)

type policyShape struct {
	Actions        []string
	Resources      []string
	HasAllow       bool
	HasDeny        bool
	BroadAllow     bool
	AdminAccess    bool
	PassRole       bool
	AssumeRole     bool
	ComputeMutate  bool
	SecretRead     bool
	KMSAccess      bool
	Complex        bool
	PrincipalBroad bool
	PrincipalAWS   []string
}

func (c *sdkAWSClientSet) IAMInventory(ctx context.Context, accountID string) (AWSInventory, error) {
	inventory := AWSInventory{IAM: ResourceSet{Resources: map[string]Resource{}}}
	if err := c.collectIAMRoles(ctx, accountID, &inventory); err != nil {
		return AWSInventory{}, err
	}
	if err := c.collectIAMInstanceProfiles(ctx, accountID, &inventory); err != nil {
		return AWSInventory{}, err
	}
	if err := c.collectIAMOIDCProviders(ctx, accountID, &inventory); err != nil {
		return AWSInventory{}, err
	}
	return inventory, nil
}

func (c *sdkAWSClientSet) ComputeInventory(ctx context.Context, region string, accountID string) (AWSInventory, error) {
	inventory := AWSInventory{Compute: ResourceSet{Resources: map[string]Resource{}}}
	if err := c.collectEC2Instances(ctx, c.ec2ForRegion(region), region, accountID, &inventory); err != nil {
		return AWSInventory{}, err
	}
	if err := c.collectLambdaFunctions(ctx, c.lambdaForRegion(region), region, accountID, &inventory); err != nil {
		return AWSInventory{}, err
	}
	if err := c.collectECS(ctx, c.ecsForRegion(region), region, accountID, &inventory); err != nil {
		return AWSInventory{}, err
	}
	if err := c.collectEKS(ctx, c.eksForRegion(region), region, accountID, &inventory); err != nil {
		return AWSInventory{}, err
	}
	return inventory, nil
}

func (c *sdkAWSClientSet) DataInventory(ctx context.Context, region string, accountID string) (AWSInventory, error) {
	inventory := AWSInventory{Data: ResourceSet{Resources: map[string]Resource{}}}
	if err := c.collectRDS(ctx, c.rdsForRegion(region), region, accountID, &inventory); err != nil {
		return AWSInventory{}, err
	}
	if err := c.collectS3(ctx, c.s3ForRegion(region), region, accountID, &inventory); err != nil {
		return AWSInventory{}, err
	}
	if err := c.collectSecrets(ctx, c.secretsForRegion(region), region, accountID, &inventory); err != nil {
		return AWSInventory{}, err
	}
	if err := c.collectKMS(ctx, c.kmsForRegion(region), region, accountID, &inventory); err != nil {
		return AWSInventory{}, err
	}
	return inventory, nil
}

func (c *sdkAWSClientSet) collectIAMRoles(ctx context.Context, accountID string, inventory *AWSInventory) error {
	paginator := iam.NewListRolesPaginator(c.iam, &iam.ListRolesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("list IAM roles: %w", err)
		}
		for _, role := range page.Roles {
			arn := aws.ToString(role.Arn)
			if arn == "" {
				continue
			}
			shape := parsePolicyDocument(aws.ToString(role.AssumeRolePolicyDocument))
			resource := awsResource(arn, arn, aws.ToString(role.RoleId), accountID, "aws_iam_role", "global", iamTags(role.Tags), map[string]string{
				"name":               aws.ToString(role.RoleName),
				"path":               aws.ToString(role.Path),
				"trust_broad":        strconv.FormatBool(shape.PrincipalBroad),
				"trust_external_aws": strings.Join(shape.PrincipalAWS, ","),
			})
			resource.ObservedPolicyActions = append(resource.ObservedPolicyActions, shape.Actions...)
			inventory.IAM.Resources[arn] = resource
			addPolicyShapeRelationships(inventory, arn, shape, relationshipSourceIAM)
			if err := c.collectRolePolicies(ctx, accountID, role, &inventory.IAM, inventory); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *sdkAWSClientSet) collectRolePolicies(ctx context.Context, accountID string, role iamtypes.Role, resources *ResourceSet, inventory *AWSInventory) error {
	roleName := aws.ToString(role.RoleName)
	roleARN := aws.ToString(role.Arn)
	attached := iam.NewListAttachedRolePoliciesPaginator(c.iam, &iam.ListAttachedRolePoliciesInput{RoleName: role.RoleName})
	for attached.HasMorePages() {
		page, err := attached.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("list attached policies for role %s: %w", roleName, err)
		}
		for _, policy := range page.AttachedPolicies {
			policyARN := aws.ToString(policy.PolicyArn)
			if policyARN == "" {
				continue
			}
			addRelationship(inventory, roleARN, policyARN, "attached_policy", relationshipSourceIAM, "high")
			shape, attrs, err := c.managedPolicyShape(ctx, policyARN)
			if err != nil {
				return err
			}
			resource := awsResource(policyARN, policyARN, policyARN, accountID, "aws_iam_policy", "global", nil, attrs)
			resource.ObservedPolicyActions = shape.Actions
			resources.Resources[policyARN] = resource
			addPolicyShapeRelationships(inventory, policyARN, shape, relationshipSourceIAM)
		}
	}
	inline := iam.NewListRolePoliciesPaginator(c.iam, &iam.ListRolePoliciesInput{RoleName: role.RoleName})
	for inline.HasMorePages() {
		page, err := inline.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("list inline policies for role %s: %w", roleName, err)
		}
		for _, policyName := range page.PolicyNames {
			out, err := c.iam.GetRolePolicy(ctx, &iam.GetRolePolicyInput{RoleName: role.RoleName, PolicyName: aws.String(policyName)})
			if err != nil {
				return fmt.Errorf("get inline policy %s for role %s: %w", policyName, roleName, err)
			}
			policyID := roleARN + "/inline/" + policyName
			shape := parsePolicyDocument(aws.ToString(out.PolicyDocument))
			resource := awsResource(policyID, "", policyID, accountID, "aws_iam_role_policy", "global", nil, policyAttrs(policyName, shape))
			resource.ObservedPolicyActions = shape.Actions
			resources.Resources[policyID] = resource
			addRelationship(inventory, roleARN, policyID, "inline_policy", relationshipSourceIAM, "high")
			addPolicyShapeRelationships(inventory, policyID, shape, relationshipSourceIAM)
		}
	}
	return nil
}

func (c *sdkAWSClientSet) managedPolicyShape(ctx context.Context, policyARN string) (policyShape, map[string]string, error) {
	policy, err := c.iam.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: aws.String(policyARN)})
	if err != nil {
		return policyShape{}, nil, fmt.Errorf("get managed policy %s: %w", policyARN, err)
	}
	if policy.Policy == nil {
		return policyShape{}, nil, nil
	}
	versionID := policy.Policy.DefaultVersionId
	version, err := c.iam.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: aws.String(policyARN), VersionId: versionID})
	if err != nil {
		return policyShape{}, nil, fmt.Errorf("get managed policy version %s: %w", policyARN, err)
	}
	shape := policyShape{}
	if version.PolicyVersion != nil {
		shape = parsePolicyDocument(aws.ToString(version.PolicyVersion.Document))
	}
	attrs := policyAttrs(aws.ToString(policy.Policy.PolicyName), shape)
	attrs["attachment_count"] = strconv.Itoa(int(aws.ToInt32(policy.Policy.AttachmentCount)))
	return shape, attrs, nil
}

func (c *sdkAWSClientSet) collectIAMInstanceProfiles(ctx context.Context, accountID string, inventory *AWSInventory) error {
	paginator := iam.NewListInstanceProfilesPaginator(c.iam, &iam.ListInstanceProfilesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("list instance profiles: %w", err)
		}
		for _, profile := range page.InstanceProfiles {
			arn := aws.ToString(profile.Arn)
			if arn == "" {
				continue
			}
			inventory.IAM.Resources[arn] = awsResource(arn, arn, aws.ToString(profile.InstanceProfileId), accountID, "aws_iam_instance_profile", "global", nil, map[string]string{"name": aws.ToString(profile.InstanceProfileName)})
			for _, role := range profile.Roles {
				addRelationship(inventory, arn, aws.ToString(role.Arn), "contains_role", relationshipSourceIAM, "high")
			}
		}
	}
	return nil
}

func (c *sdkAWSClientSet) collectIAMOIDCProviders(ctx context.Context, accountID string, inventory *AWSInventory) error {
	out, err := c.iam.ListOpenIDConnectProviders(ctx, &iam.ListOpenIDConnectProvidersInput{})
	if err != nil {
		return fmt.Errorf("list OIDC providers: %w", err)
	}
	for _, provider := range out.OpenIDConnectProviderList {
		arn := aws.ToString(provider.Arn)
		if arn == "" {
			continue
		}
		inventory.IAM.Resources[arn] = awsResource(arn, arn, arn, accountID, "aws_iam_openid_connect_provider", "global", nil, nil)
	}
	return nil
}

func (c *sdkAWSClientSet) collectEC2Instances(ctx context.Context, client *ec2.Client, region string, accountID string, inventory *AWSInventory) error {
	paginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("describe EC2 instances: %w", err)
		}
		for _, reservation := range page.Reservations {
			for _, instance := range reservation.Instances {
				id := aws.ToString(instance.InstanceId)
				if id == "" {
					continue
				}
				attrs := map[string]string{
					"instance_type": string(instance.InstanceType),
					"state":         "",
					"subnet_id":     aws.ToString(instance.SubnetId),
					"vpc_id":        aws.ToString(instance.VpcId),
				}
				if instance.State != nil {
					attrs["state"] = string(instance.State.Name)
				}
				resource := awsResource(id, ec2ARN(region, accountID, "instance", id), id, accountID, "aws_instance", region, ec2Tags(instance.Tags), attrs)
				inventory.Compute.Resources[id] = resource
				for _, sg := range instance.SecurityGroups {
					addRelationship(inventory, aws.ToString(sg.GroupId), id, "protects", relationshipSourceEC2Role, "high")
				}
				if instance.IamInstanceProfile != nil {
					addRelationship(inventory, id, aws.ToString(instance.IamInstanceProfile.Arn), "uses_instance_profile", relationshipSourceEC2Role, "high")
				}
			}
		}
	}
	return nil
}

func (c *sdkAWSClientSet) collectLambdaFunctions(ctx context.Context, client *lambda.Client, region string, accountID string, inventory *AWSInventory) error {
	paginator := lambda.NewListFunctionsPaginator(client, &lambda.ListFunctionsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("list Lambda functions: %w", err)
		}
		for _, fn := range page.Functions {
			arn := aws.ToString(fn.FunctionArn)
			if arn == "" {
				continue
			}
			resource := awsResource(arn, arn, aws.ToString(fn.FunctionName), accountID, "aws_lambda_function", region, nil, map[string]string{
				"name":    aws.ToString(fn.FunctionName),
				"runtime": string(fn.Runtime),
				"role":    aws.ToString(fn.Role),
			})
			inventory.Compute.Resources[arn] = resource
			addRelationship(inventory, arn, aws.ToString(fn.Role), "uses_role", relationshipSourceLambda, "high")
			if fn.KMSKeyArn != nil {
				addRelationship(inventory, arn, aws.ToString(fn.KMSKeyArn), "uses_kms_key", relationshipSourceLambda, "high")
			}
		}
	}
	return nil
}

func (c *sdkAWSClientSet) collectECS(ctx context.Context, client *ecs.Client, region string, accountID string, inventory *AWSInventory) error {
	clusters, err := listAllECSClusters(ctx, client)
	if err != nil {
		return err
	}
	for _, clusterARN := range clusters {
		inventory.Compute.Resources[clusterARN] = awsResource(clusterARN, clusterARN, clusterARN, accountID, "aws_ecs_cluster", region, nil, nil)
		services, err := listAllECSServices(ctx, client, clusterARN)
		if err != nil {
			return err
		}
		for _, serviceBatch := range chunkStrings(services, 10) {
			out, err := client.DescribeServices(ctx, &ecs.DescribeServicesInput{Cluster: aws.String(clusterARN), Services: serviceBatch})
			if err != nil {
				return fmt.Errorf("describe ECS services: %w", err)
			}
			for _, service := range out.Services {
				serviceARN := aws.ToString(service.ServiceArn)
				if serviceARN == "" {
					continue
				}
				inventory.Compute.Resources[serviceARN] = awsResource(serviceARN, serviceARN, aws.ToString(service.ServiceName), accountID, "aws_ecs_service", region, nil, map[string]string{
					"cluster":         clusterARN,
					"task_definition": aws.ToString(service.TaskDefinition),
				})
				addRelationship(inventory, clusterARN, serviceARN, "contains", relationshipSourceECS, "high")
				addRelationship(inventory, serviceARN, aws.ToString(service.TaskDefinition), "runs_task_definition", relationshipSourceECS, "high")
				if err := c.collectECSTaskDefinition(ctx, client, serviceARN, aws.ToString(service.TaskDefinition), region, accountID, inventory); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (c *sdkAWSClientSet) collectECSTaskDefinition(ctx context.Context, client *ecs.Client, serviceARN string, taskDefinitionARN string, region string, accountID string, inventory *AWSInventory) error {
	if taskDefinitionARN == "" {
		return nil
	}
	out, err := client.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{TaskDefinition: aws.String(taskDefinitionARN)})
	if err != nil {
		return fmt.Errorf("describe ECS task definition %s: %w", taskDefinitionARN, err)
	}
	if out.TaskDefinition == nil {
		return nil
	}
	taskDef := out.TaskDefinition
	resource := awsResource(taskDefinitionARN, taskDefinitionARN, taskDefinitionARN, accountID, "aws_ecs_task_definition", region, nil, map[string]string{
		"family": aws.ToString(taskDef.Family),
	})
	inventory.Compute.Resources[taskDefinitionARN] = resource
	for _, role := range []string{aws.ToString(taskDef.ExecutionRoleArn), aws.ToString(taskDef.TaskRoleArn)} {
		addRelationship(inventory, taskDefinitionARN, role, "uses_role", relationshipSourceECS, "high")
	}
	for _, container := range taskDef.ContainerDefinitions {
		for _, secret := range container.Secrets {
			addRelationship(inventory, taskDefinitionARN, aws.ToString(secret.ValueFrom), "reads_secret", relationshipSourceECS, "high")
		}
	}
	return nil
}

func (c *sdkAWSClientSet) collectEKS(ctx context.Context, client *eks.Client, region string, accountID string, inventory *AWSInventory) error {
	paginator := eks.NewListClustersPaginator(client, &eks.ListClustersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("list EKS clusters: %w", err)
		}
		for _, clusterName := range page.Clusters {
			out, err := client.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: aws.String(clusterName)})
			if err != nil {
				return fmt.Errorf("describe EKS cluster %s: %w", clusterName, err)
			}
			if out.Cluster == nil {
				continue
			}
			arn := aws.ToString(out.Cluster.Arn)
			resource := awsResource(arn, arn, clusterName, accountID, "aws_eks_cluster", region, out.Cluster.Tags, map[string]string{"endpoint": aws.ToString(out.Cluster.Endpoint)})
			resource.EndpointPublicAccess = boolPtr(out.Cluster.ResourcesVpcConfig.EndpointPublicAccess)
			inventory.Compute.Resources[arn] = resource
			addRelationship(inventory, arn, aws.ToString(out.Cluster.RoleArn), "uses_role", relationshipSourceEKS, "high")
			if err := c.collectEKSNodegroups(ctx, client, clusterName, arn, region, accountID, inventory); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *sdkAWSClientSet) collectEKSNodegroups(ctx context.Context, client *eks.Client, clusterName string, clusterARN string, region string, accountID string, inventory *AWSInventory) error {
	paginator := eks.NewListNodegroupsPaginator(client, &eks.ListNodegroupsInput{ClusterName: aws.String(clusterName)})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("list EKS nodegroups for %s: %w", clusterName, err)
		}
		for _, nodegroupName := range page.Nodegroups {
			out, err := client.DescribeNodegroup(ctx, &eks.DescribeNodegroupInput{ClusterName: aws.String(clusterName), NodegroupName: aws.String(nodegroupName)})
			if err != nil {
				return fmt.Errorf("describe EKS nodegroup %s: %w", nodegroupName, err)
			}
			if out.Nodegroup == nil {
				continue
			}
			arn := aws.ToString(out.Nodegroup.NodegroupArn)
			inventory.Compute.Resources[arn] = awsResource(arn, arn, nodegroupName, accountID, "aws_eks_node_group", region, out.Nodegroup.Tags, nil)
			addRelationship(inventory, clusterARN, arn, "contains", relationshipSourceEKS, "high")
			addRelationship(inventory, arn, aws.ToString(out.Nodegroup.NodeRole), "uses_role", relationshipSourceEKS, "high")
		}
	}
	return nil
}

func (c *sdkAWSClientSet) collectRDS(ctx context.Context, client *rds.Client, region string, accountID string, inventory *AWSInventory) error {
	instances := rds.NewDescribeDBInstancesPaginator(client, &rds.DescribeDBInstancesInput{})
	for instances.HasMorePages() {
		page, err := instances.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("describe RDS instances: %w", err)
		}
		for _, instance := range page.DBInstances {
			arn := aws.ToString(instance.DBInstanceArn)
			if arn == "" {
				continue
			}
			tags := c.rdsTags(ctx, client, arn)
			resource := awsResource(arn, arn, aws.ToString(instance.DBInstanceIdentifier), accountID, "aws_db_instance", region, tags, map[string]string{
				"engine":                aws.ToString(instance.Engine),
				"db_instance_class":     aws.ToString(instance.DBInstanceClass),
				"publicly_accessible":   strconv.FormatBool(aws.ToBool(instance.PubliclyAccessible)),
				"storage_encrypted":     strconv.FormatBool(aws.ToBool(instance.StorageEncrypted)),
				"deletion_protection":   strconv.FormatBool(aws.ToBool(instance.DeletionProtection)),
				"backup_retention_days": strconv.Itoa(int(aws.ToInt32(instance.BackupRetentionPeriod))),
			})
			resource.Public = instance.PubliclyAccessible
			resource.EncryptionEnabled = instance.StorageEncrypted
			resource.DeletionProtection = instance.DeletionProtection
			resource.Sensitivity = inferSensitivity("aws_db_instance", aws.ToString(instance.DBInstanceIdentifier), tags)
			inventory.Data.Resources[arn] = resource
			addRelationship(inventory, arn, aws.ToString(instance.KmsKeyId), "uses_kms_key", relationshipSourceRDS, "high")
		}
	}
	clusters := rds.NewDescribeDBClustersPaginator(client, &rds.DescribeDBClustersInput{})
	for clusters.HasMorePages() {
		page, err := clusters.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("describe RDS clusters: %w", err)
		}
		for _, cluster := range page.DBClusters {
			arn := aws.ToString(cluster.DBClusterArn)
			if arn == "" {
				continue
			}
			tags := c.rdsTags(ctx, client, arn)
			resource := awsResource(arn, arn, aws.ToString(cluster.DBClusterIdentifier), accountID, "aws_rds_cluster", region, tags, map[string]string{
				"engine":              aws.ToString(cluster.Engine),
				"storage_encrypted":   strconv.FormatBool(aws.ToBool(cluster.StorageEncrypted)),
				"deletion_protection": strconv.FormatBool(aws.ToBool(cluster.DeletionProtection)),
			})
			resource.EncryptionEnabled = cluster.StorageEncrypted
			resource.DeletionProtection = cluster.DeletionProtection
			resource.Sensitivity = inferSensitivity("aws_rds_cluster", aws.ToString(cluster.DBClusterIdentifier), tags)
			inventory.Data.Resources[arn] = resource
			addRelationship(inventory, arn, aws.ToString(cluster.KmsKeyId), "uses_kms_key", relationshipSourceRDS, "high")
		}
	}
	return nil
}

func (c *sdkAWSClientSet) rdsTags(ctx context.Context, client *rds.Client, arn string) map[string]string {
	out, err := client.ListTagsForResource(ctx, &rds.ListTagsForResourceInput{ResourceName: aws.String(arn)})
	if err != nil {
		return nil
	}
	tags := make(map[string]string, len(out.TagList))
	for _, tag := range out.TagList {
		if tag.Key != nil {
			tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
		}
	}
	return compactMap(tags)
}

func (c *sdkAWSClientSet) collectS3(ctx context.Context, client *s3.Client, region string, accountID string, inventory *AWSInventory) error {
	out, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return fmt.Errorf("list S3 buckets: %w", err)
	}
	for _, bucket := range out.Buckets {
		name := aws.ToString(bucket.Name)
		if name == "" {
			continue
		}
		arn := "arn:aws:s3:::" + name
		tags := c.s3Tags(ctx, client, name)
		publicAccessBlocked := c.s3PublicAccessBlocked(ctx, client, name)
		resource := awsResource(name, arn, name, accountID, "aws_s3_bucket", region, tags, map[string]string{"name": name})
		resource.PublicAccessBlocked = publicAccessBlocked
		resource.Sensitivity = inferSensitivity("aws_s3_bucket", name, tags)
		inventory.Data.Resources[name] = resource
	}
	return nil
}

func (c *sdkAWSClientSet) s3Tags(ctx context.Context, client *s3.Client, bucket string) map[string]string {
	out, err := client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: aws.String(bucket)})
	if err != nil {
		return nil
	}
	tags := make(map[string]string, len(out.TagSet))
	for _, tag := range out.TagSet {
		tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}
	return compactMap(tags)
}

func (c *sdkAWSClientSet) s3PublicAccessBlocked(ctx context.Context, client *s3.Client, bucket string) *bool {
	out, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: aws.String(bucket)})
	if err != nil || out.PublicAccessBlockConfiguration == nil {
		return nil
	}
	cfg := out.PublicAccessBlockConfiguration
	blocked := aws.ToBool(cfg.BlockPublicAcls) && aws.ToBool(cfg.BlockPublicPolicy) && aws.ToBool(cfg.IgnorePublicAcls) && aws.ToBool(cfg.RestrictPublicBuckets)
	return boolPtr(blocked)
}

func (c *sdkAWSClientSet) collectSecrets(ctx context.Context, client *secretsmanager.Client, region string, accountID string, inventory *AWSInventory) error {
	paginator := secretsmanager.NewListSecretsPaginator(client, &secretsmanager.ListSecretsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("list Secrets Manager secrets: %w", err)
		}
		for _, secret := range page.SecretList {
			arn := aws.ToString(secret.ARN)
			if arn == "" {
				continue
			}
			tags := secretTags(secret.Tags)
			resource := awsResource(arn, arn, aws.ToString(secret.Name), accountID, "aws_secretsmanager_secret", region, tags, map[string]string{"name": aws.ToString(secret.Name)})
			resource.Sensitivity = Sensitivity{Data: true, Reason: "secretsmanager metadata"}
			resource.SensitiveData = true
			inventory.Data.Resources[arn] = resource
			addRelationship(inventory, arn, aws.ToString(secret.KmsKeyId), "uses_kms_key", relationshipSourceSecrets, "high")
		}
	}
	return nil
}

func (c *sdkAWSClientSet) collectKMS(ctx context.Context, client *kms.Client, region string, accountID string, inventory *AWSInventory) error {
	paginator := kms.NewListKeysPaginator(client, &kms.ListKeysInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("list KMS keys: %w", err)
		}
		for _, key := range page.Keys {
			keyID := aws.ToString(key.KeyId)
			if keyID == "" {
				continue
			}
			meta, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(keyID)})
			if err != nil {
				return fmt.Errorf("describe KMS key %s: %w", keyID, err)
			}
			if meta.KeyMetadata == nil {
				continue
			}
			arn := aws.ToString(meta.KeyMetadata.Arn)
			resource := awsResource(arn, arn, keyID, accountID, "aws_kms_key", region, nil, map[string]string{
				"description": aws.ToString(meta.KeyMetadata.Description),
				"key_manager": string(meta.KeyMetadata.KeyManager),
				"key_state":   string(meta.KeyMetadata.KeyState),
			})
			inventory.Data.Resources[arn] = resource
		}
	}
	return nil
}

func listAllECSClusters(ctx context.Context, client *ecs.Client) ([]string, error) {
	paginator := ecs.NewListClustersPaginator(client, &ecs.ListClustersInput{})
	var clusters []string
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list ECS clusters: %w", err)
		}
		clusters = append(clusters, page.ClusterArns...)
	}
	sort.Strings(clusters)
	return clusters, nil
}

func listAllECSServices(ctx context.Context, client *ecs.Client, clusterARN string) ([]string, error) {
	paginator := ecs.NewListServicesPaginator(client, &ecs.ListServicesInput{Cluster: aws.String(clusterARN)})
	var services []string
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list ECS services for %s: %w", clusterARN, err)
		}
		services = append(services, page.ServiceArns...)
	}
	sort.Strings(services)
	return services, nil
}

func chunkStrings(values []string, size int) [][]string {
	if size <= 0 {
		return nil
	}
	chunks := make([][]string, 0, (len(values)+size-1)/size)
	for start := 0; start < len(values); start += size {
		end := start + size
		if end > len(values) {
			end = len(values)
		}
		chunks = append(chunks, values[start:end])
	}
	return chunks
}

func iamTags(tags []iamtypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		out[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}
	return compactMap(out)
}

func secretTags(tags []secretstypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		out[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}
	return compactMap(out)
}

func policyAttrs(name string, shape policyShape) map[string]string {
	return compactMap(map[string]string{
		"name":           name,
		"actions":        strings.Join(shape.Actions, ","),
		"resources":      strings.Join(shape.Resources, ","),
		"broad_allow":    strconv.FormatBool(shape.BroadAllow),
		"admin_access":   strconv.FormatBool(shape.AdminAccess),
		"pass_role":      strconv.FormatBool(shape.PassRole),
		"assume_role":    strconv.FormatBool(shape.AssumeRole),
		"compute_mutate": strconv.FormatBool(shape.ComputeMutate),
		"secret_read":    strconv.FormatBool(shape.SecretRead),
		"kms_access":     strconv.FormatBool(shape.KMSAccess),
		"complex":        strconv.FormatBool(shape.Complex),
	})
}

func parsePolicyDocument(raw string) policyShape {
	decoded := decodePolicyDocument(raw)
	if decoded == "" {
		return policyShape{}
	}
	var document struct {
		Statement any `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(decoded), &document); err != nil {
		return policyShape{Complex: true}
	}
	statements := normalizePolicyStatements(document.Statement)
	shape := policyShape{}
	actions := make(map[string]bool)
	resources := make(map[string]bool)
	principals := make(map[string]bool)
	for _, statement := range statements {
		effect := strings.ToLower(statement.Effect)
		if effect == "deny" {
			shape.HasDeny = true
		}
		if effect == "allow" {
			shape.HasAllow = true
		}
		if len(statement.Condition) > 0 {
			shape.Complex = true
		}
		for _, action := range statement.Actions {
			action = strings.ToLower(action)
			actions[action] = true
			if effect == "allow" {
				shape.PassRole = shape.PassRole || actionMatches(action, "iam:PassRole")
				shape.AssumeRole = shape.AssumeRole || actionMatches(action, "sts:AssumeRole")
				shape.ComputeMutate = shape.ComputeMutate || actionMatchesAny(action, []string{"lambda:UpdateFunctionCode", "ecs:RunTask", "ecs:UpdateService"})
				shape.SecretRead = shape.SecretRead || actionMatches(action, "secretsmanager:GetSecretValue")
				shape.KMSAccess = shape.KMSAccess || actionMatches(action, "kms:Decrypt")
			}
		}
		for _, resource := range statement.Resources {
			resources[resource] = true
		}
		for _, principal := range statement.Principals {
			principals[principal] = true
		}
		if effect == "allow" && (actions["*"] || resources["*"]) {
			shape.BroadAllow = true
		}
	}
	shape.Actions = sortedKeys(actions)
	shape.Resources = sortedKeys(resources)
	shape.PrincipalAWS = sortedKeys(principals)
	shape.PrincipalBroad = principals["*"]
	shape.AdminAccess = shape.HasAllow && (actions["*"] || actions["iam:*"] || actions["administratoraccess"])
	return shape
}

type normalizedStatement struct {
	Effect     string
	Actions    []string
	Resources  []string
	Principals []string
	Condition  map[string]any
}

func normalizePolicyStatements(raw any) []normalizedStatement {
	switch current := raw.(type) {
	case []any:
		out := make([]normalizedStatement, 0, len(current))
		for _, item := range current {
			if statement, ok := normalizePolicyStatement(item); ok {
				out = append(out, statement)
			}
		}
		return out
	case map[string]any:
		if statement, ok := normalizePolicyStatement(current); ok {
			return []normalizedStatement{statement}
		}
	}
	return nil
}

func normalizePolicyStatement(raw any) (normalizedStatement, bool) {
	value, ok := raw.(map[string]any)
	if !ok {
		return normalizedStatement{}, false
	}
	statement := normalizedStatement{
		Effect:     fmt.Sprint(value["Effect"]),
		Actions:    stringList(value["Action"]),
		Resources:  stringList(value["Resource"]),
		Principals: principalList(value["Principal"]),
	}
	if cond, ok := value["Condition"].(map[string]any); ok {
		statement.Condition = cond
	}
	return statement, true
}

func stringList(value any) []string {
	switch current := value.(type) {
	case string:
		if current == "" {
			return nil
		}
		return []string{current}
	case []any:
		out := make([]string, 0, len(current))
		for _, item := range current {
			if text := fmt.Sprint(item); text != "" {
				out = append(out, text)
			}
		}
		sort.Strings(out)
		return out
	default:
		return nil
	}
}

func principalList(value any) []string {
	switch current := value.(type) {
	case string:
		return stringList(current)
	case map[string]any:
		out := make([]string, 0)
		for _, item := range current {
			out = append(out, stringList(item)...)
		}
		sort.Strings(out)
		return out
	default:
		return nil
	}
}

func decodePolicyDocument(raw string) string {
	if raw == "" {
		return ""
	}
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		return raw
	}
	return decoded
}

func actionMatchesAny(action string, targets []string) bool {
	for _, target := range targets {
		if actionMatches(action, target) {
			return true
		}
	}
	return false
}

func actionMatches(pattern string, action string) bool {
	pattern = strings.ToLower(pattern)
	action = strings.ToLower(action)
	if pattern == "*" || pattern == action {
		return true
	}
	if strings.HasSuffix(pattern, ":*") {
		return strings.HasPrefix(action, strings.TrimSuffix(pattern, "*"))
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(action, strings.TrimSuffix(pattern, "*"))
	}
	return false
}

func addPolicyShapeRelationships(inventory *AWSInventory, policyID string, shape policyShape, source string) {
	for _, action := range shape.Actions {
		addRelationship(inventory, policyID, "action:"+action, "grants_action", source, confidenceForPolicy(shape))
	}
	for _, resource := range shape.Resources {
		addRelationship(inventory, policyID, resource, "grants_resource", source, confidenceForPolicy(shape))
	}
}

func confidenceForPolicy(shape policyShape) string {
	if shape.Complex {
		return "medium"
	}
	return "high"
}

func inferSensitivity(resourceType string, name string, tags map[string]string) Sensitivity {
	lowerName := strings.ToLower(name)
	for key, value := range tags {
		combined := strings.ToLower(key + "=" + value)
		if strings.Contains(combined, "sensitive") || strings.Contains(combined, "restricted") || strings.Contains(combined, "confidential") || strings.Contains(combined, "customer") || strings.Contains(combined, "prod") {
			return Sensitivity{Data: true, Reason: "tag:" + key}
		}
	}
	if strings.Contains(lowerName, "prod") || strings.Contains(lowerName, "customer") || strings.Contains(lowerName, "payment") || resourceType == "aws_secretsmanager_secret" {
		return Sensitivity{Data: true, Reason: "resource metadata"}
	}
	return Sensitivity{}
}

func sortedKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		if key != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}
