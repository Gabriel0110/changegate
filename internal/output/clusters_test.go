package output

import (
	"testing"

	"github.com/Gabriel0110/changegate/internal/model"
)

func TestBuildRiskClustersGroupsPublicAdminSensitivePath(t *testing.T) {
	t.Parallel()

	findings := []model.Finding{
		clusterFinding("AWS_PUBLIC_ADMIN_SERVICE", "aws_lb.admin", model.RiskCategoryPublicExposure, model.SeverityHigh, model.ConfidenceHigh),
		clusterFinding("AWS_PUBLIC_ADMIN_SERVICE", "aws_ecs_service.admin", model.RiskCategoryPublicExposure, model.SeverityHigh, model.ConfidenceHigh),
		clusterFinding("AWS_PUBLIC_TO_SENSITIVE_DATASTORE", "aws_lb.admin", model.RiskCategorySensitiveData, model.SeverityHigh, model.ConfidenceHigh),
		clusterFinding("AWS_PUBLIC_TO_SENSITIVE_DATA_PATH", "aws_db_instance.customer", model.RiskCategorySensitiveData, model.SeverityCritical, model.ConfidenceHigh),
		clusterFinding("AWS_RDS_BACKUP_RETENTION_DISABLED_PROD", "aws_db_instance.customer", model.RiskCategoryAvailability, model.SeverityHigh, model.ConfidenceHigh),
		clusterFinding("AWS_RDS_DELETION_PROTECTION_DISABLED_PROD", "aws_db_instance.customer", model.RiskCategoryAvailability, model.SeverityHigh, model.ConfidenceHigh),
	}

	clusters := BuildRiskClusters(findings)
	if len(clusters) != 2 {
		t.Fatalf("len(clusters) = %d, want 2: %#v", len(clusters), clusters)
	}
	publicCluster := clusters[0]
	if publicCluster.Title != "Public admin service reaches sensitive data" {
		t.Fatalf("public cluster title = %q", publicCluster.Title)
	}
	if publicCluster.Severity != model.SeverityCritical || publicCluster.Confidence != model.ConfidenceHigh || publicCluster.Decision != model.DecisionBlock {
		t.Fatalf("public cluster rollup = %s/%s/%s", publicCluster.Severity, publicCluster.Confidence, publicCluster.Decision)
	}
	if len(publicCluster.SupportingFindings) != 4 {
		t.Fatalf("public supporting findings = %d, want 4", len(publicCluster.SupportingFindings))
	}
	if len(publicCluster.AffectedResources) != 3 {
		t.Fatalf("public affected resources = %#v, want 3 unique resources", publicCluster.AffectedResources)
	}
	rdsCluster := clusters[1]
	if rdsCluster.Title != "Production RDS resilience controls disabled" {
		t.Fatalf("rds cluster title = %q", rdsCluster.Title)
	}
	if len(rdsCluster.SupportingFindings) != 2 {
		t.Fatalf("rds supporting findings = %d, want 2", len(rdsCluster.SupportingFindings))
	}
}

func TestBuildRiskClustersFallsBackToRuleCluster(t *testing.T) {
	t.Parallel()

	findings := []model.Finding{
		clusterFinding("AWS_SG_WORLD_OPEN_ADMIN_PORT", "aws_security_group.admin", model.RiskCategoryPublicExposure, model.SeverityHigh, model.ConfidenceHigh),
	}

	clusters := BuildRiskClusters(findings)
	if len(clusters) != 1 {
		t.Fatalf("len(clusters) = %d, want 1", len(clusters))
	}
	if clusters[0].Title != "AWS_SG_WORLD_OPEN_ADMIN_PORT" {
		t.Fatalf("fallback title = %q", clusters[0].Title)
	}
	if clusters[0].PrimaryFindingID != findings[0].ID {
		t.Fatalf("primary finding = %q, want %q", clusters[0].PrimaryFindingID, findings[0].ID)
	}
}

func TestBuildRiskClustersRanksAllDecisionReasons(t *testing.T) {
	t.Parallel()

	finding := clusterFinding("AWS_PUBLIC_TO_SENSITIVE_DATA_PATH", "aws_db_instance.customer", model.RiskCategorySensitiveData, model.SeverityCritical, model.ConfidenceHigh)
	finding.DecisionReasonCodes = []model.DecisionReasonCode{
		model.ReasonCorrelated,
		model.ReasonMeetsBlockThreshold,
	}

	clusters := BuildRiskClusters([]model.Finding{finding})
	if len(clusters) != 1 {
		t.Fatalf("len(clusters) = %d, want 1", len(clusters))
	}
	if clusters[0].Decision != model.DecisionBlock {
		t.Fatalf("cluster decision = %q, want %q", clusters[0].Decision, model.DecisionBlock)
	}
}

func clusterFinding(ruleID string, resource string, category model.RiskCategory, severity model.Severity, confidence model.Confidence) model.Finding {
	finding := model.NormalizeFinding(model.Finding{
		RuleID:          ruleID,
		Title:           ruleID,
		ResourceAddress: resource,
		Provider:        "aws",
		Category:        category,
		Severity:        severity,
		Confidence:      confidence,
		Evidence: []model.Evidence{{
			Type:     "attribute",
			Resource: resource,
			Path:     "example",
			Message:  "example evidence",
		}},
		Remediation: model.Remediation{Summary: "Review and remediate."},
	})
	finding.DecisionReasonCodes = []model.DecisionReasonCode{model.ReasonMeetsBlockThreshold}
	return finding
}
