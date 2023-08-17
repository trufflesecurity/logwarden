package firewall_rule_created

violation[{"msg": msg, "details": {"project": project, "actor": actor, "name": name}}] {
	input.protoPayload.request["@type"] == "type.googleapis.com/compute.firewalls.insert"

	project = input.resource.labels.project_id
	name = input.protoPayload.request.name
	actor = input.protoPayload.authenticationInfo.principalEmail

	msg = "firewall rule created"
}
