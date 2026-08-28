# Tests for the MITRE tactic policies. Kept outside policy/ on purpose: the
# engine loads every .rego under its policy path and boolean test rules would
# break its result parsing.
#
# Run with: make test  (opa test policy policy_test)
package mitre_test

import rego.v1

event(method, permission) := {
	"insertId": "abc123",
	"timestamp": "2026-08-27T00:00:00Z",
	"resource": {"labels": {"project_id": "test-project"}},
	"protoPayload": {
		"authenticationInfo": {"principalEmail": "test@example.com"},
		"methodName": method,
		"authorizationInfo": [{
			"permission": permission,
			"granted": true,
			"resource": "projects/test-project/some/resource",
		}],
	},
}

denied_msg := "permission denied - possible privilege escalation attempt"

test_collection_fires_on_disk_snapshot if {
	count(data.mitre_collection.violation) > 0 with input as event("v1.compute.disks.createSnapshot", "compute.disks.createSnapshot")
}

test_collection_ignores_unrelated_event if {
	count(data.mitre_collection.violation) == 0 with input as event("v1.compute.instances.get", "compute.instances.get")
}

test_collection_ignores_ungranted_permission if {
	e := json.remove(event("v1.compute.disks.createSnapshot", "compute.disks.createSnapshot"), ["protoPayload/authorizationInfo/0/granted"])
	count(data.mitre_collection.violation) == 0 with input as e
}

# regression: a method match must alert once, not once per granted entry
test_method_match_does_not_fan_out_per_entry if {
	e := object.union(event("v1.compute.disks.createSnapshot", "compute.instances.get"), {"protoPayload": {"authorizationInfo": [
		{"permission": "compute.instances.get", "granted": true, "resource": "r1"},
		{"permission": "compute.zones.get", "granted": true, "resource": "r2"},
		{"permission": "compute.disks.get", "granted": true, "resource": "r3"},
	]}})
	count(data.mitre_collection.violation) == 1 with input as e
}

test_discovery_fires_on_test_iam_permissions_glob if {
	count(data.mitre_discovery.violation) > 0 with input as event("storage.buckets.testIamPermissions", "storage.buckets.testIamPermissions")
}

test_evasion_fires_on_sink_deletion_method if {
	count(data.mitre_evasion.violation) > 0 with input as event("google.logging.v2.ConfigServiceV2.DeleteSink", "logging.sinks.delete")
}

test_lateral_movement_fires_on_instance_metadata if {
	count(data.mitre_lateral_movement.violation) > 0 with input as event("v1.compute.instances.setMetadata", "compute.instances.setMetadata")
}

# bare iamcredentials method name, deliberately different casing from the
# pattern, with a permission that matches nothing
test_persistence_matches_bare_method_case_insensitively if {
	count(data.mitre_persistence.violation) > 0 with input as event("GenerateAccessToken", "iam.serviceAccounts.get")
}

test_impact_fires_on_kms_key_destroy if {
	count(data.mitre_impact.violation) > 0 with input as event("DestroyCryptoKeyVersion", "cloudkms.cryptoKeyVersions.destroy")
}

test_privilege_escalation_fires_on_set_iam_policy if {
	count(data.mitre_privilege_escalation.violation) > 0 with input as event("SetIamPolicy", "resourcemanager.projects.setIamPolicy")
}

# org- and folder-level events carry no project_id label but must still alert
test_privilege_escalation_fires_on_org_level_event if {
	e := json.remove(event("SetIamPolicy", "resourcemanager.organizations.setIamPolicy"), ["resource/labels/project_id"])
	count(data.mitre_privilege_escalation.violation) > 0 with input as e
}

test_permission_denied_fires_on_escalation_attempt if {
	e := object.union(event("SetIamPolicy", "resourcemanager.projects.setIamPolicy"), {"protoPayload": {"status": {"code": 7}}})
	some v in data.mitre_privilege_escalation.violation with input as e
	v.msg == denied_msg
}

# GCP redacts the caller identity on many denied calls
test_permission_denied_fires_without_principal_email if {
	e := object.union(event("GenerateAccessToken", "iam.serviceAccounts.getAccessToken"), {"protoPayload": {"status": {"code": 7}}})
	redacted := json.remove(e, ["protoPayload/authenticationInfo", "protoPayload/authorizationInfo"])
	some v in data.mitre_privilege_escalation.violation with input as redacted
	v.details.actor == "unknown"
}

# resource manager emits the bare SetIamPolicy method name; a denied call with
# authorizationInfo redacted must still alert
test_permission_denied_fires_on_bare_method_name if {
	e := object.union(event("SetIamPolicy", "resourcemanager.projects.setIamPolicy"), {"protoPayload": {"status": {"code": 7}}})
	redacted := json.remove(e, ["protoPayload/authorizationInfo"])
	some v in data.mitre_privilege_escalation.violation with input as redacted
	v.msg == denied_msg
}

# a sparse authorizationInfo entry degrades the alert details, not the alert
test_public_binding_fires_with_sparse_auth_entry if {
	e := object.union(event("SetIamPolicy", "storage.buckets.setIamPolicy"), {"protoPayload": {
		"authorizationInfo": [{"permission": "storage.buckets.setIamPolicy"}],
		"serviceData": {"policyDelta": {"bindingDeltas": [{"action": "ADD", "role": "roles/storage.objectViewer", "member": "allUsers"}]}},
	}})
	some v in data.mitre_exfiltration.violation with input as e
	v.msg == "possible data exfiltration attempt - public exposure"
	v.details.resource == ""
}

# a denial of something unrelated to escalation is not a privesc alert
test_permission_denied_ignores_unrelated_denial if {
	e := object.union(event("storage.objects.get", "storage.objects.get"), {"protoPayload": {"status": {"code": 7}}})
	count(data.mitre_privilege_escalation.violation) == 0 with input as e
}

# a granted escalation event must not also produce the denied message
test_granted_escalation_is_not_labeled_denied if {
	denied := {v | some v in data.mitre_privilege_escalation.violation; v.msg == denied_msg} with input as event("SetIamPolicy", "resourcemanager.projects.setIamPolicy")
	count(denied) == 0
}

# org policy denials get the dedicated message, not the generic denied one
test_org_policy_denial_excluded_from_generic_denied_rule if {
	e := object.union(event("SetIamPolicy", "resourcemanager.projects.setIamPolicy"), {"protoPayload": {"status": {
		"code": 7,
		"details": [{"violations": [{"type": "constraints/iam.allowedPolicyMemberDomains", "subject": "orgpolicy:projects/test-project", "description": "domain restricted"}]}],
	}}})
	msgs := {v.msg | some v in data.mitre_privilege_escalation.violation} with input as e
	"possible privilege escalation attempt denied - org policy violation" in msgs
	not denied_msg in msgs
}

test_exfiltration_fires_on_bigquery_export if {
	count(data.mitre_exfiltration.violation) > 0 with input as event("google.cloud.bigquery.v2.JobService.InsertJob", "bigquery.tables.export")
}

test_exfiltration_fires_on_public_binding if {
	e := object.union(event("SetIamPolicy", "storage.buckets.setIamPolicy"), {"protoPayload": {"serviceData": {"policyDelta": {"bindingDeltas": [{
		"action": "ADD",
		"role": "roles/storage.objectViewer",
		"member": "allUsers",
	}]}}}})
	some v in data.mitre_exfiltration.violation with input as e
	v.msg == "possible data exfiltration attempt - public exposure"
}

# regression: ADD and allUsers on different deltas must not combine into a match
test_exfiltration_public_binding_requires_same_delta if {
	e := object.union(event("v1.compute.instances.get", "compute.instances.get"), {"protoPayload": {"serviceData": {"policyDelta": {"bindingDeltas": [
		{"action": "ADD", "role": "roles/viewer", "member": "user:test@example.com"},
		{"action": "REMOVE", "role": "roles/viewer", "member": "allUsers"},
	]}}}})
	count(data.mitre_exfiltration.violation) == 0 with input as e
}
