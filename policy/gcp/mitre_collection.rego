package mitre_collection

import future.keywords.in

violation[{"msg": msg, "details": {"project": project, "actor": actor, "method": method, "permission": permission, "granted": granted, "resource": resource, "link": link}}] {
	actor = input.protoPayload.authenticationInfo.principalEmail

	permissions_and_methods = [
		"disks.createSnapshots",
		"snapshots.get",
		"compute.instances.export",
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
	msg = "possible data collection attempt"
}
