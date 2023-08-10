package mitre_privilege_escalation

import future.keywords.in

violation[{"msg": msg, "details": {"project": project, "actor": actor, "method": method, "permission": permission, "granted": granted, "resource": resource, "link": link}}] {
	actor = input.protoPayload.authenticationInfo.principalEmail

	permissions_and_methods = [
		"cloudfunctions.functions.create",
		"cloudfunctions.functions.update",
		"projects.locations.functions.patch",
		"run.services.create",
		"run.routes.invoke",
		"dataproc.clusters.create,",
		"dataflow.jobs.create,",
		"dataflow.jobs.updateContentsiam,",
		"composer.environments.create",
		"iam.serviceAccounts.actAs",
		"iam.serviceAccounts.getAccessToken",
		"iam.serviceAccountKeys.implicitDelegation",
		"iam.serviceAccountKeys.create",
		"iam.serviceAccounts.signJwt",
		"iam.roles.update",
		"**.setIamPolicy",
		"**.setIamPermissions",
	]

	permission = input.protoPayload.authorizationInfo[_].permission
	method = input.protoPayload.methodName
	true in [glob.match(permissions_and_methods[_], [], permission), glob.match(permissions_and_methods[_], [], method)]

	granted = input.protoPayload.authorizationInfo[_].granted
	resource = input.protoPayload.authorizationInfo[_].resource
	project = input.resource.labels.project_id

	insertId = input.insertId
	timestamp = input.timestamp
	link = sprintf("https://console.cloud.google.com/logs/query;query=%s;timeRange=PT1H;cursorTimestamp=%s?project=%s", [urlquery.encode(sprintf("insertId=\"%s\"\ntimestamp=\"%s\"", [insertId, timestamp])), timestamp, project])
	msg = "possible privilege escalation attempt"
}

violation[{"msg": msg, "details": {"project": project, "actor": actor, "method": method, "permission": permission, "granted": granted, "resource": resource, "link": link}}] {
	actor = input.protoPayload.authenticationInfo.principalEmail
	permission = input.protoPayload.authorizationInfo[_].permission
	method = input.protoPayload.methodName
	granted = input.protoPayload.authorizationInfo[_].granted
	resource = input.protoPayload.authorizationInfo[_].resource
	project = input.resource.labels.project_id

	granted == false

	insertId = input.insertId
	timestamp = input.timestamp
	link = sprintf("https://console.cloud.google.com/logs/query;query=%s;timeRange=PT1H;cursorTimestamp=%s?project=%s", [urlquery.encode(sprintf("insertId=\"%s\"\ntimestamp=\"%s\"", [insertId, timestamp])), timestamp, project])
	msg = "possible privilege escalation attempt denied"
}

violation[{"msg": msg, "details": {"project": project, "actor": actor, "method": method, "resource": resource, "org_policy": org_policy, "org_policy_subject": org_policy_subject, "org_policy_description": org_policy_description, "link": link}}] {
	actor = input.protoPayload.authenticationInfo.principalEmail
	method = input.protoPayload.methodName
	resource = input.protoPayload.authorizationInfo[_].resource
	project = input.resource.labels.project_id
	org_policy = input.protoPayload.status.details[_].violations[_].type
	org_policy_subject = input.protoPayload.status.details[_].violations[_].subject
	org_policy_description = input.protoPayload.status.details[_].violations[_].description

	insertId = input.insertId
	timestamp = input.timestamp
	link = sprintf("https://console.cloud.google.com/logs/query;query=%s;timeRange=PT1H;cursorTimestamp=%s?project=%s", [urlquery.encode(sprintf("insertId=\"%s\"\ntimestamp=\"%s\"", [insertId, timestamp])), timestamp, project])
	msg = "possible privilege escalation attempt denied - org policy violation"
}
