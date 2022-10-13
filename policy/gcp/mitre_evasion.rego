package mitre_evasion

import future.keywords.in

violation[{"msg": msg, "details": {"project": project, "actor": actor, "method": method, "permission": permission, "granted": granted, "resource": resource}}] {
	actor = input.protoPayload.authenticationInfo.principalEmail

	permissions_and_methods = [
		"google.logging.v2.ConfigServiceV2.DeleteSink", # disrupt log monitoring
		"google.logging.v2.ConfigServiceV2.CreateExclusion", # exclusions from log monitoring
		"google.identity.accesscontextmanager.v1beta.AccessContextManager.DeleteServicePerimeter", # open up API access
		"google.identity.accesscontextmanager.v1beta.AccessContextManager.UpdateServicePerimeter",
	]

	permission = input.protoPayload.authorizationInfo[_].permission
	method = input.protoPayload.methodName
	true in [glob.match(permissions_and_methods[_], [], permission), glob.match(permissions_and_methods[_], [], method)]

	granted = input.protoPayload.authorizationInfo[_].granted
	resource = input.protoPayload.authorizationInfo[_].resource
	project = input.resource.labels.project_id

	msg = "possible impact / disruption attempt"
}
