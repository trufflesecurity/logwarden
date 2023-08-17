package gke_rbac_deny

violation[{"msg": msg, "details": {"cluster": cluster, "actor": actor, "method": method}}] {
	input.labels["authorization.k8s.io/decision"] == "deny"

	project = input.resource.labels.project_id
	actor = input.protoPayload.authenticationInfo.principalEmail
	cluster = input.resource.labels.cluster_name
	method = input.protoPayload.methodName

	msg = "GKE RBAC deny"
}
