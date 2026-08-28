package mitre_persistence

# MITRE ATT&CK Persistence (TA0003)

import data.mitre_helpers as helpers
import rego.v1

violation contains {"msg": "possible persistence attempt", "details": details} if {
	patterns := [
		"cloudfunctions.functions.create",
		"cloudfunctions.functions.update",
		"**.updateFunction", # cloud functions v1/v2 method form
		"**.generateAccessToken",
		"generateAccessToken", # iamcredentials logs use bare method names
		"**.getAccessToken",
		"iam.serviceAccounts.create",
		"container.serviceAccounts.create",
		"compute.instances.osAdminLogin",
		"compute.instances.osLogin",
		"**.importSshPublicKey",
		"**.updateSshPublicKey",
		"**.instances.insert",
	]

	some auth in helpers.matched_entries(patterns)
	details := helpers.details(auth)
}
