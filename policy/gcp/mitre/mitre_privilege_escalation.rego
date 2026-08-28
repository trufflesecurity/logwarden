package mitre_privilege_escalation

# MITRE ATT&CK Privilege Escalation (TA0004)

import data.mitre_helpers as helpers
import rego.v1

# A function rather than a rule so the list stays out of the engine's data
# query, which only tolerates violation sets.
escalation_patterns(_) := [
	"cloudfunctions.functions.create", # run code as an attached service account
	"cloudfunctions.functions.update",
	"**.updateFunction", # cloud functions v1/v2 method form
	"run.services.create",
	"run.routes.invoke",
	"dataproc.clusters.create",
	"dataflow.jobs.create",
	"dataflow.jobs.updateContents",
	"composer.environments.create",
	"deploymentmanager.deployments.create",
	"iam.serviceAccounts.actAs",
	"iam.serviceAccounts.getAccessToken",
	"iam.serviceAccounts.implicitDelegation",
	"iam.serviceAccountKeys.create",
	"iam.serviceAccounts.signBlob",
	"iam.serviceAccounts.signJwt",
	"generateAccessToken", # iamcredentials logs use bare method names
	"signBlob",
	"signJwt",
	"iam.roles.update",
	"orgpolicy.policy.set",
	"**.setIamPolicy",
	"setIamPolicy", # resource manager logs use the bare method name
]

violation contains {"msg": "possible privilege escalation attempt", "details": details} if {
	some auth in helpers.matched_entries(escalation_patterns(true))
	details := helpers.details(auth)
}

# Requests denied while attempting an escalation-relevant action. GCP omits
# granted:false from authorizationInfo in the log JSON, so key on the request's
# PERMISSION_DENIED status; the caller identity is often redacted on denied
# calls, so default the optional fields. Org-policy denials are excluded —
# the dedicated rule below reports those with the policy details.
violation contains {"msg": "permission denied - possible privilege escalation attempt", "details": details} if {
	input.protoPayload.status.code == 7
	helpers.match_any(escalation_patterns(true))
	count([v | some d in input.protoPayload.status.details; some v in d.violations]) == 0
	project := object.get(input, ["resource", "labels", "project_id"], "")
	details := {
		"project": project,
		"actor": object.get(input.protoPayload, ["authenticationInfo", "principalEmail"], "unknown"),
		"method": input.protoPayload.methodName,
		"resource": object.get(input.protoPayload, "resourceName", ""),
		"link": helpers.link(project),
	}
}

violation contains {"msg": "possible privilege escalation attempt denied - org policy violation", "details": details} if {
	v := input.protoPayload.status.details[_].violations[_]
	project := object.get(input, ["resource", "labels", "project_id"], "")
	details := {
		"project": project,
		"actor": input.protoPayload.authenticationInfo.principalEmail,
		"method": input.protoPayload.methodName,
		"org_policy": v.type,
		"org_policy_subject": v.subject,
		"org_policy_description": v.description,
		"link": helpers.link(project),
	}
}
