package mitre_lateral_movement

# MITRE ATT&CK Lateral Movement (TA0008)

import data.mitre_helpers as helpers
import rego.v1

violation contains {"msg": "possible lateral movement attempt", "details": details} if {
	patterns := [
		"resourcemanager.projects.setIamPolicy",
		"compute.instances.setMetadata", # SSH key injection
		"compute.projects.setCommonInstanceMetadata", # project-wide SSH keys
	]

	some auth in helpers.matched_entries(patterns)
	details := helpers.details(auth)
}
