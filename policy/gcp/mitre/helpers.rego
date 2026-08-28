package mitre_helpers

# Shared building blocks for the MITRE tactic policies. This package contains
# only functions, so the engine's `data` query sees it only as an empty object
# — any non-function rule added here would crash the daemon's result parsing.

import rego.v1

# authorizationInfo entries to alert on: every granted entry whose permission
# matches a pattern, or the first granted entry when the request's method name
# matches. Entry-scoped so alert details never mix fields from different
# access checks, and a method match yields one alert instead of one per entry.
# Globs use "." as the delimiter (e.g. "**.setIamPolicy") and are matched
# case-insensitively, since GCP method names mix casing (GenerateAccessToken).
matched_entries(patterns) := permission_hits(patterns) | method_hits(patterns)

permission_hits(patterns) := {auth |
	some auth in input.protoPayload.authorizationInfo
	auth.granted
	some pattern in patterns
	glob.match(lower(pattern), [], lower(auth.permission))
}

default method_hits(_) := set()

method_hits(patterns) := {auth} if {
	match_method(patterns)
	auth := [a | some a in input.protoPayload.authorizationInfo; a.granted][0]
}

# The request's method name matches a pattern.
match_method(patterns) if {
	some pattern in patterns
	glob.match(lower(pattern), [], lower(input.protoPayload.methodName))
}

# The method name or any checked permission matches, granted or not. For
# denied requests, whose authorizationInfo entries never carry granted.
match_any(patterns) if match_method(patterns)

match_any(patterns) if {
	some auth in input.protoPayload.authorizationInfo
	some pattern in patterns
	glob.match(lower(pattern), [], lower(auth.permission))
}

# Alert details built from a single authorizationInfo entry, so permission,
# granted, and resource all describe the same access check. project is empty
# for org- and folder-level events, which must still alert.
details(auth) := d if {
	project := object.get(input, ["resource", "labels", "project_id"], "")
	d := {
		"project": project,
		"actor": input.protoPayload.authenticationInfo.principalEmail,
		"method": input.protoPayload.methodName,
		"permission": auth.permission,
		"granted": auth.granted,
		"resource": auth.resource,
		"link": link(project),
	}
}

# Cloud console link to the source log entry.
link(project) := sprintf("https://console.cloud.google.com/logs/query;query=%s;timeRange=PT1H;cursorTimestamp=%s?project=%s", [urlquery.encode(sprintf("insertId=\"%s\"\ntimestamp=\"%s\"", [input.insertId, input.timestamp])), input.timestamp, project])
