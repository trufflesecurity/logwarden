# gcp-auditor

Process all of your GCP audit logs against OPA Rego policies and alert for violations in real-time.

Some amount of policy coverage for MITRE ATT&CK Tactics are included.

## MITRE ATT&CK Tactics

[Source](https://attack.mitre.orghttps://attack.mitre.org/tactics/enterprise/)

|ID|Name|Description|
|:----|:----|:----|
|[TA0043](https://attack.mitre.org/tactics/TA0043)|[Reconnaissance](https://attack.mitre.org/tactics/TA0043)|The adversary is trying to gather information they can use to plan future operations.|
|[TA0042](https://attack.mitre.org/tactics/TA0042)|[Resource Development](https://attack.mitre.org/tactics/TA0042)|The adversary is trying to establish resources they can use to support operations.|
|[TA0001](https://attack.mitre.org/tactics/TA0001)|[Initial Access](https://attack.mitre.org/tactics/TA0001)|The adversary is trying to get into your network.|
|[TA0002](https://attack.mitre.org/tactics/TA0002)|[Execution](https://attack.mitre.org/tactics/TA0002)|The adversary is trying to run malicious code.|
|[TA0003](https://attack.mitre.org/tactics/TA0003)|[Persistence](https://attack.mitre.org/tactics/TA0003)|The adversary is trying to maintain their foothold.|
|[TA0004](https://attack.mitre.org/tactics/TA0004)|[Privilege Escalation](https://attack.mitre.org/tactics/TA0004)|The adversary is trying to gain higher-level permissions.|
|[TA0005](https://attack.mitre.org/tactics/TA0005)|[Defense Evasion](https://attack.mitre.org/tactics/TA0005)|The adversary is trying to avoid being detected.|
|[TA0006](https://attack.mitre.org/tactics/TA0006)|[Credential Access](https://attack.mitre.org/tactics/TA0006)|The adversary is trying to steal account names and passwords.|
|[TA0007](https://attack.mitre.org/tactics/TA0007)|[Discovery](https://attack.mitre.org/tactics/TA0007)|The adversary is trying to figure out your environment.|
|[TA0008](https://attack.mitre.org/tactics/TA0008)|[Lateral Movement](https://attack.mitre.org/tactics/TA0008)|The adversary is trying to move through your environment.|
|[TA0009](https://attack.mitre.org/tactics/TA0009)|[Collection](https://attack.mitre.org/tactics/TA0009)|The adversary is trying to gather data of interest to their goal.|
|[TA0011](https://attack.mitre.org/tactics/TA0011)|[Command and Control](https://attack.mitre.org/tactics/TA0011)|The adversary is trying to communicate with compromised systems to control them.|
|[TA0010](https://attack.mitre.org/tactics/TA0010)|[Exfiltration](https://attack.mitre.org/tactics/TA0010)|The adversary is trying to steal data.|
|[TA0040](https://attack.mitre.org/tactics/TA0040)|[Impact](https://attack.mitre.org/tactics/TA0040)|The adversary is trying to manipulate, interrupt, or destroy your systems and data.|

## Rego reference

- [Rego Policy Reference](https://www.openpolicyagent.org/docs/latest/policy-reference/)
- Policy blocks are ORed, but evaluations within a policy are ANDed
- Use the policy block signature provided in the example policies for compatability, and see the [template](policy/gcp/template.rego) for a starting point

## Todo (help wanted!)

Implement findings from
- https://github.com/garrettwong/gcp-mitre-attack-external
- https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation
- implement additional GCP permission and method coverage
