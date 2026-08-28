package mitre_discovery

# MITRE ATT&CK Discovery (TA0007)

import data.mitre_helpers as helpers
import rego.v1

violation contains {"msg": "possible discovery attempt", "details": details} if {
	patterns := [
		"**.testIamPermissions",
		"testIamPermissions", # resource manager logs use the bare method name
		"storage.buckets.list",
		"**.searchAllResources", # cloud asset inventory recon
		"**.searchAllIamPolicies",
	]

	some auth in helpers.matched_entries(patterns)
	details := helpers.details(auth)
}
