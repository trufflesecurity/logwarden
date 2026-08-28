package mitre_evasion

# MITRE ATT&CK Defense Evasion (TA0005)

import data.mitre_helpers as helpers
import rego.v1

violation contains {"msg": "possible defense evasion attempt", "details": details} if {
	patterns := [
		"google.logging.v2.ConfigServiceV2.DeleteSink", # disrupt log monitoring
		"google.logging.v2.ConfigServiceV2.UpdateSink", # disrupt log monitoring
		"google.logging.v2.ConfigServiceV2.CreateExclusion", # exclusions from log monitoring
		"google.logging.v2.ConfigServiceV2.UpdateExclusion",
		"google.logging.v2.ConfigServiceV2.DeleteBucket", # delete log storage
		"google.logging.v2.LoggingServiceV2.DeleteLog", # delete logs
		"**.AccessContextManager.DeleteServicePerimeter", # open up API access
		"**.AccessContextManager.UpdateServicePerimeter",
		"google.pubsub.v1.Subscriber.DeleteSubscription", # disrupt pubsub logging sinks
		"google.pubsub.v1.Publisher.DeleteTopic", # disrupt pubsub logging sinks
	]

	some auth in helpers.matched_entries(patterns)
	details := helpers.details(auth)
}
