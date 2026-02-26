package guardrails

default decision = {"eligible": false, "reasons": ["deny-by-default"], "action_id": null, "risk_tier": "LOW"}

# A closed action catalog: allow only known actions (extend this list).
allowed_actions := {
  "aws_ec2_stop_dev_out_of_hours",
  "aws_release_unused_eip",
  "aws_delete_orphan_ebs_volume",
  "aws_quarantine_sg_open_ssh_world_nonprod",
  "aws_block_public_s3_nonprod"
}

# Example: stop dev/test instances out of hours
decision := {
  "eligible": true,
  "reasons": ["dev instance out of hours"],
  "action_id": "aws_ec2_stop_dev_out_of_hours",
  "risk_tier": "LOW"
} {
  input.env == "dev" or input.env == "test"
  input.finding.category == "finops"
  input.resource.type == "ec2_instance"
  not input.resource.tags.do_not_stop
  input.resource.tags.owner != ""
  "aws_ec2_stop_dev_out_of_hours" in allowed_actions
}
