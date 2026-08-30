package probe

import rego.v1

violation contains {"msg": msg, "details": {"actor": actor, "method": method}} if {
	method = input.protoPayload.methodName
	method == "test.probe.Fire"
	actor = input.protoPayload.authenticationInfo.principalEmail
	msg = "probe fired"
}
