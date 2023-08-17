package cloud_sql_connect

violation[{"msg": msg, "details": {"project": project, "actor": actor, "instance": instance}}] {
	input.protoPayload.methodName == "cloudsql.instances.connect"
	
	project = input.resource.labels.project_id
	project == "example"

    instance = input.resource.labels.database_id

	actor = input.protoPayload.authenticationInfo.principalEmail
	actor != "service-account-example@example.iam.gserviceaccount.com"

	msg = "unexpected connection to cloudsql instance"
}
