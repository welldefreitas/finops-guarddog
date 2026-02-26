# Runbook: EC2 Stop (dev out-of-hours)

## Purpose
Stop a dev/test EC2 instance to reduce cost.

## Required IAM permissions (least privilege)
- ec2:StopInstances (resource-scoped to approved instances)

## Inputs
- instance_id
- region
