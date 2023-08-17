package service_account_keys

violation[{"msg": msg, "details": {"actor": actor, "service_account": svcAcct}}] {
	input.protoPayload.methodName == "google.iam.admin.v1.CreateServiceAccountKey"

	svcAcct = input.resource.labels.email_id
	actor = input.protoPayload.authenticationInfo.principalEmail

	msg = "service account key created"
}
