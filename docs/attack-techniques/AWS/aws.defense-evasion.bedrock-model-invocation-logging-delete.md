---
title: Delete Bedrock Model Invocation Logging
---

# Delete Bedrock Model Invocation Logging




Platform: AWS

## MITRE ATT&CK Tactics


- Defense Evasion

## Description


Delete Amazon Bedrock model invocation logging configuration. Simulates an attacker disrupting AI activity monitoring.

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create a Bedrock model invocation logging configuration.

<span style="font-variant: small-caps;">Detonation</span>: 

- Delete the Bedrock model invocation logging configuration.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.defense-evasion.bedrock-model-invocation-logging-delete
```
## Detection


Identify when Bedrock model invocation logging is deleted, through CloudTrail's <code>DeleteModelInvocationLogging</code> event.


