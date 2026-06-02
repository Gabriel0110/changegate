package rules

import "github.com/Gabriel0110/changegate/internal/model"

// PolicyPack groups built-in rules under a versioned default bundle.
type PolicyPack struct {
	ID          string       `json:"id"`
	Version     string       `json:"version"`
	Description string       `json:"description"`
	Rules       []string     `json:"rules"`
	Defaults    PackDefaults `json:"defaults"`
}

// PackDefaults defines default enforcement thresholds for a policy pack.
type PackDefaults struct {
	BlockOn model.Threshold `json:"block_on"`
}

// DefaultRegistry returns the built-in rule registry.
func DefaultRegistry() (*Registry, error) {
	registry := NewRegistry()
	for _, rule := range defaultRules() {
		if err := registry.Register(rule); err != nil {
			return nil, err
		}
	}
	return registry, nil
}

// DefaultPolicyPacks returns the built-in policy packs.
func DefaultPolicyPacks() []PolicyPack {
	return []PolicyPack{
		{
			ID:          "aws-core",
			Version:     "0.1.0",
			Description: "Core AWS high-confidence risk rules.",
			Rules: []string{
				"AWS_RDS_REPLACEMENT_PROD",
				"AWS_STATEFUL_REPLACEMENT",
				"AWS_SENSITIVE_STORAGE_ENCRYPTION_DISABLED",
				"AWS_RDS_BACKUP_RETENTION_DISABLED_PROD",
				"AWS_RDS_BACKUP_RETENTION_REDUCED_PROD",
				"AWS_RDS_DELETION_PROTECTION_DISABLED_PROD",
				"AWS_RDS_FINAL_SNAPSHOT_DISABLED_PROD",
				"AWS_DYNAMODB_PITR_DISABLED_PROD",
				"AWS_S3_SENSITIVE_BUCKET_LOGGING_DISABLED",
				"AWS_S3_SENSITIVE_BUCKET_VERSIONING_DISABLED",
				"AWS_CLOUDTRAIL_LOGGING_DISABLED_PROD",
				"AWS_CLOUDTRAIL_LOG_FILE_VALIDATION_DISABLED_PROD",
				"AWS_CONFIG_RECORDER_DISABLED_PROD",
				"AWS_ECR_REPOSITORY_MUTABLE_OR_SCAN_DISABLED_PROD",
			},
			Defaults: defaultPackDefaults(),
		},
		{
			ID:          "aws-public-exposure",
			Version:     "0.1.0",
			Description: "AWS public exposure rules.",
			Rules: []string{
				"AWS_PUBLIC_ADMIN_SERVICE",
				"AWS_PUBLIC_ADMIN_SERVICE_PATH",
				"AWS_PUBLIC_INTERNAL_SERVICE",
				"AWS_SG_WORLD_OPEN_ADMIN_PORT",
				"AWS_SG_WORLD_OPEN_DB_PORT",
				"AWS_SECURITY_GROUP_WORLD_OPEN_ALL_PORTS",
				"AWS_EC2_PUBLIC_IP_ADMIN_INGRESS",
				"AWS_PUBLIC_RDS_INSTANCE",
				"AWS_RDS_PUBLIC_SUBNET_GROUP",
				"AWS_EFS_OPEN_SECURITY_GROUP",
				"AWS_ELASTICACHE_OPEN_SECURITY_GROUP",
				"AWS_PUBLIC_OPENSEARCH_DOMAIN",
				"AWS_PUBLIC_EKS_ENDPOINT_PROD",
				"AWS_S3_PUBLIC_ACCESS_BLOCK_DISABLED_PROD",
				"AWS_S3_BUCKET_PUBLIC_POLICY",
				"AWS_S3_BUCKET_PUBLIC_ACL",
				"AWS_CLOUDFRONT_S3_PUBLIC_MISMATCH",
				"AWS_LAMBDA_PUBLIC_FUNCTION_URL",
				"AWS_API_GATEWAY_PUBLIC_ADMIN_ROUTE",
				"AWS_LOAD_BALANCER_WEAK_TLS_OR_HTTP",
				"AWS_PUBLIC_TO_SENSITIVE_DATASTORE",
				"AWS_PUBLIC_TO_SENSITIVE_DATA_PATH",
				"AWS_PRIVATE_SUBNET_ROUTE_TO_IGW",
				"AWS_PRIVATE_WORKLOAD_EXPOSED_BY_NAT_OR_SG",
				"AWS_TGW_ROUTE_TO_SENSITIVE_SUBNET",
				"AWS_EGRESS_OPEN_FROM_SENSITIVE_WORKLOAD",
			},
			Defaults: defaultPackDefaults(),
		},
		{
			ID:          "aws-iam-escalation",
			Version:     "0.1.0",
			Description: "AWS IAM privilege escalation rules.",
			Rules: []string{
				"AWS_IAM_PASSROLE_FUNCTION_ESCALATION",
				"AWS_IAM_ASSUME_ADMIN_PATH",
				"AWS_PASSROLE_WITH_COMPUTE_MUTATION",
				"AWS_IAM_WILDCARD_ADMIN",
				"AWS_IAM_NOTACTION_ALLOW_BROAD",
				"AWS_IAM_SENSITIVE_ACTIONS_RESOURCE_WILDCARD",
				"AWS_ROLE_ASSUME_ADMIN_PATH",
				"AWS_IAM_ADMIN_POLICY_ATTACHMENT",
				"AWS_EXTERNAL_ACCOUNT_TRUST",
				"AWS_GITHUB_OIDC_TRUST_BROAD",
				"AWS_KMS_DECRYPT_BROAD",
				"AWS_KMS_KEY_POLICY_PUBLIC_OR_EXTERNAL_ADMIN",
				"AWS_SECRETS_READ_BROAD",
			},
			Defaults: defaultPackDefaults(),
		},
	}
}

func defaultPackDefaults() PackDefaults {
	return PackDefaults{
		BlockOn: model.Threshold{
			MinSeverity:   model.SeverityHigh,
			MinConfidence: model.ConfidenceHigh,
		},
	}
}

func defaultRules() []Rule {
	out := make([]Rule, 0)
	out = append(out, awsRules()...)
	out = append(out, attackPathRules()...)
	return out
}
