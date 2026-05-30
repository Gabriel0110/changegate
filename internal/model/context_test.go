package model

import "testing"

func TestContextualDecisionModesAndExplanations(t *testing.T) {
	t.Parallel()

	finding := NormalizeFinding(sampleFinding())

	blocked := EvaluatePolicy([]Finding{finding}, DefaultPolicyConfig())
	if blocked.Decision != DecisionBlock {
		t.Fatalf("Decision = %q, want block", blocked.Decision)
	}
	if len(blocked.Reasons) == 0 || blocked.Reasons[0].FindingID == "" {
		t.Fatalf("blocked outcome lacks explainable reasons: %#v", blocked.Reasons)
	}

	warnConfig := DefaultPolicyConfig()
	warnConfig.Mode = PolicyModeWarn
	warned := EvaluatePolicy([]Finding{finding}, warnConfig)
	if warned.Decision != DecisionWarn || warned.ReasonCodes[0] != ReasonWarnMode {
		t.Fatalf("warned outcome = %#v", warned)
	}

	auditConfig := DefaultPolicyConfig()
	auditConfig.Mode = PolicyModeAudit
	audited := EvaluatePolicy([]Finding{finding}, auditConfig)
	if audited.Decision != DecisionWarn || audited.ReasonCodes[0] != ReasonAuditMode {
		t.Fatalf("audit outcome = %#v", audited)
	}
}

func TestContextualSuppressions(t *testing.T) {
	t.Parallel()

	finding := NormalizeFinding(sampleFinding())

	changedOnly := DefaultPolicyConfig()
	changedOnly.ChangedResourcesOnly = true
	changedOnly.ChangedResources = map[string]bool{"aws_lb.other": true}
	outcome := EvaluatePolicy([]Finding{finding}, changedOnly)
	if outcome.Decision != DecisionAllow {
		t.Fatalf("Decision = %q, want allow", outcome.Decision)
	}
	if outcome.Summary.Suppressed != 1 {
		t.Fatalf("Suppressed = %d, want 1", outcome.Summary.Suppressed)
	}
	if outcome.Summary.SuppressedByReason["changed_resource_only"] != 1 {
		t.Fatalf("suppressed reasons = %#v", outcome.Summary.SuppressedByReason)
	}

	newOnly := DefaultPolicyConfig()
	newOnly.NewRiskOnly = true
	newOnly.ExistingFingerprints = map[string]bool{finding.Fingerprint: true}
	outcome = EvaluatePolicy([]Finding{finding}, newOnly)
	if outcome.Decision != DecisionAllow {
		t.Fatalf("Decision = %q, want allow for existing risk", outcome.Decision)
	}
	if outcome.Summary.SuppressedByReason["existing_risk"] != 1 {
		t.Fatalf("suppressed reasons = %#v", outcome.Summary.SuppressedByReason)
	}
}

func TestNewOnlyDoesNotSuppressWorsenedExistingRisk(t *testing.T) {
	t.Parallel()

	oldFinding := sampleFinding()
	oldFinding.Evidence = []Evidence{{
		Type:     "graph_path",
		Resource: oldFinding.ResourceAddress,
		Path:     "graph.path",
		Value:    []string{"internet", oldFinding.ResourceAddress},
		Message:  "old graph path",
	}}
	oldFinding = NormalizeFinding(oldFinding)
	oldContext := RiskContextFromFinding(oldFinding)

	worsened := sampleFinding()
	worsened.Evidence = []Evidence{{
		Type:     "graph_path",
		Resource: worsened.ResourceAddress,
		Path:     "graph.path",
		Value:    []string{"internet", worsened.ResourceAddress, "aws_db_instance.customer"},
		Message:  "new graph path reaches sensitive data",
	}}
	worsened = NormalizeFinding(worsened)
	if oldFinding.Fingerprint != worsened.Fingerprint {
		t.Fatalf("test requires stable fingerprint lineage, got %s and %s", oldFinding.Fingerprint, worsened.Fingerprint)
	}

	config := DefaultPolicyConfig()
	config.NewRiskOnly = true
	config.ExistingFingerprints = map[string]bool{worsened.Fingerprint: true}
	config.ExistingRisks = map[string]RiskContext{worsened.Fingerprint: oldContext}
	outcome := EvaluatePolicy([]Finding{worsened}, config)
	if outcome.Decision != DecisionBlock {
		t.Fatalf("Decision = %q, want block for worsened existing risk", outcome.Decision)
	}
	if outcome.Summary.Suppressed != 0 {
		t.Fatalf("Suppressed = %d, want 0", outcome.Summary.Suppressed)
	}
	if outcome.Summary.Upgraded != 1 {
		t.Fatalf("Upgraded = %d, want 1", outcome.Summary.Upgraded)
	}
	if len(outcome.Findings) == 0 || !hasReason(outcome.Findings[0], ReasonUpgraded) {
		t.Fatalf("worsened finding missing upgraded reason: %#v", outcome.Findings)
	}
}

func TestContextualUpgradeDowngradeAndCorrelation(t *testing.T) {
	t.Parallel()

	lowConfidence := sampleFinding()
	lowConfidence.RuleID = "LOW_CONFIDENCE"
	lowConfidence.Confidence = ConfidenceMedium
	lowConfidence.Environment = "production"
	lowConfidence = NormalizeFinding(lowConfidence)

	config := DefaultPolicyConfig()
	config.EnvironmentThresholds = map[string]Thresholds{
		"production": {
			BlockOn: Threshold{MinSeverity: SeverityHigh, MinConfidence: ConfidenceHigh},
		},
	}
	outcome := EvaluatePolicy([]Finding{lowConfidence}, config)
	if outcome.Summary.Upgraded != 1 {
		t.Fatalf("Upgraded = %d, want 1", outcome.Summary.Upgraded)
	}

	downgradedSeverity := SeverityLow
	downgradedConfidence := ConfidenceLow
	config = DefaultPolicyConfig()
	config.Overrides = map[string]Override{
		lowConfidence.Fingerprint: {
			Severity:   &downgradedSeverity,
			Confidence: &downgradedConfidence,
			Reason:     "accepted in sandbox",
		},
	}
	outcome = EvaluatePolicy([]Finding{lowConfidence}, config)
	if outcome.Summary.Downgraded != 1 {
		t.Fatalf("Downgraded = %d, want 1", outcome.Summary.Downgraded)
	}
	if outcome.Decision == DecisionBlock {
		t.Fatalf("downgraded finding should not block")
	}

	related := sampleFinding()
	related.RuleID = "RELATED_RULE"
	related = NormalizeFinding(related)
	outcome = EvaluatePolicy([]Finding{sampleFinding(), related}, DefaultPolicyConfig())
	for _, finding := range outcome.Findings {
		if len(finding.CorrelatedFindingIDs) == 0 {
			t.Fatalf("finding %s was not correlated", finding.RuleID)
		}
	}
}

func TestBranchThresholds(t *testing.T) {
	t.Parallel()

	finding := sampleFinding()
	finding.Severity = SeverityMedium
	finding.Confidence = ConfidenceMedium

	config := DefaultPolicyConfig()
	config.Branch = "main"
	config.BranchThresholds = map[string]Thresholds{
		"main": {
			BlockOn: Threshold{MinSeverity: SeverityMedium, MinConfidence: ConfidenceMedium},
		},
	}
	outcome := EvaluatePolicy([]Finding{finding}, config)
	if outcome.Decision != DecisionBlock {
		t.Fatalf("Decision = %q, want block from branch threshold", outcome.Decision)
	}
}
