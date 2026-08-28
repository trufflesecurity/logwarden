package mitre_impact

# MITRE ATT&CK Impact (TA0040)

import data.mitre_helpers as helpers
import rego.v1

violation contains {"msg": "possible impact attempt", "details": details} if {
	patterns := [
		"cloudkms.cryptoKeyVersions.destroy", # destroy encryption keys
		"storage.buckets.delete",
		"**.snapshots.delete", # destroy backups
		"cloudsql.backupRuns.delete",
		"cloudsql.instances.delete",
		"container.clusters.delete",
		"bigquery.datasets.delete",
	]

	some auth in helpers.matched_entries(patterns)
	details := helpers.details(auth)
}
