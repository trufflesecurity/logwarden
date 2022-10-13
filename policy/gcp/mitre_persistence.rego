package mitre_persistence

import future.keywords.in

violation[{"msg": msg, "details": {"project": project, "actor": actor, "method": method, "permission": permission, "granted": granted, "resource": resource}}] {
	actor = input.protoPayload.authenticationInfo.principalEmail

	permissions_and_methods = [
		"cloudfunctions.functions.create",
		"projects.locations.funtions.create",
		"projects.locations.functions.patch",
		"**.generateAccessToken",
		"**.getAccessToken",
		"**.createToken",
		"container.serviceAccounts.create",
		"compute.instances.osAdminLogin",
		"compute.instances.osLogin",
		"users.importSshPublicKey",
		"users.sshPublicKeys.patch",
		"instances.insert",
	]

	permission = input.protoPayload.authorizationInfo[_].permission
	method = input.protoPayload.methodName
	true in [glob.match(permissions_and_methods[_], [], permission), glob.match(permissions_and_methods[_], [], method)]

	granted = input.protoPayload.authorizationInfo[_].granted
	resource = input.protoPayload.authorizationInfo[_].resource
	project = input.resource.labels.project_id

	msg = "possible persistence attempt"
}
