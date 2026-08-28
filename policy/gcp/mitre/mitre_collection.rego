package mitre_collection

# MITRE ATT&CK Collection (TA0009)

import data.mitre_helpers as helpers
import rego.v1

violation contains {"msg": "possible data collection attempt", "details": details} if {
	# copies of data at rest; export/staging patterns live in mitre_exfiltration
	patterns := [
		"**.disks.createSnapshot",
		"**.machineImages.create", # full VM copy
		"compute.snapshots.useReadOnly", # snapshot data read back into a disk/image
	]

	some auth in helpers.matched_entries(patterns)
	details := helpers.details(auth)
}
