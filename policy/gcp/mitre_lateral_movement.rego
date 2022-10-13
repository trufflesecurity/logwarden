package mitre_lateral_movement

import future.keywords.in

# violation[{"msg": msg, "details": {"project": project, "actor": actor, "method": method, "permission": permission, "granted": granted, "resource": resource}}] {
# 	actor = input.protoPayload.authenticationInfo.principalEmail
# 	permissions_and_methods = []

# 	permission = input.protoPayload.authorizationInfo[_].permission

# 	# see https://github.com/googleapis/google-cloudevents/blob/main/json/audit/service_catalog.json
# 	method = input.protoPayload.methodName
# 	true in [glob.match(permissions_and_methods[_], [], permission), glob.match(permissions_and_methods[_], [], method)]

# 	granted = input.protoPayload.authorizationInfo[_].granted
# 	resource = input.protoPayload.authorizationInfo[_].resource
# 	project = input.resource.labels.project_id
# 	msg = "possible lateral movement attempt"
# }
