package firewall_rule_created

import rego.v1

violation contains {"msg": msg, "details": {"project": project, "actor": actor, "name": name}} if {
	input.protoPayload.request["@type"] == "type.googleapis.com/compute.firewalls.insert"

	project = input.resource.labels.project_id
	name = input.protoPayload.request.name
	actor = input.protoPayload.authenticationInfo.principalEmail

	msg = "firewall rule created"
}
