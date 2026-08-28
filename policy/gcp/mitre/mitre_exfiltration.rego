package mitre_exfiltration

# MITRE ATT&CK Exfiltration (TA0010)

import data.mitre_helpers as helpers
import rego.v1

violation contains {"msg": "possible data exfiltration attempt", "details": details} if {
	# moving or exposing data; data-copy patterns live in mitre_collection
	patterns := [
		"storage.buckets.create", # staging data
		"cloudsql.instances.export",
		"bigquery.tables.export",
		"storage.buckets.setIamPolicy", # opening up access to data
		"storage.objects.setIamPolicy",
	]

	some auth in helpers.matched_entries(patterns)
	details := helpers.details(auth)
}

violation contains {"msg": "possible data exfiltration attempt - public exposure", "details": details} if {
	delta := input.protoPayload.serviceData.policyDelta.bindingDeltas[_]
	delta.action == "ADD"
	delta.member in {"allUsers", "allAuthenticatedUsers"}

	auth := input.protoPayload.authorizationInfo[0]
	details := object.union(helpers.details(auth), {"member": delta.member, "role": delta.role})
}
