package changegate

findings contains finding if {
	change := input.changes[_]
	change.type == "aws_sqs_queue"
	finding := {
		"rule_id": "ORG_QUEUE_REVIEW",
		"title": "SQS queue changes require platform review",
		"resource_address": change.address,
		"category": "compliance",
		"severity": "high",
		"confidence": "high",
		"remediation": "Confirm queue access policy, encryption, and ownership before apply.",
	}
}
