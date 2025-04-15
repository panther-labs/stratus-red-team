---
title: Trigger Bedrock Guardrail via Converse API
---

# Trigger Bedrock Guardrail via Converse API


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Impact

## Description


Trigger an Amazon Bedrock guardrail using the Converse API with harmful content. Simulates testing the limits of AI safety controls through conversational model interaction.

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create a Bedrock guardrail.

<span style="font-variant: small-caps;">Detonation</span>: 

- Send a harmful prompt to a Bedrock model using the Converse API with guardrail parameters.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.impact.bedrock-converse-guardrail-trigger
```
## Detection


Identify when a Bedrock guardrail is triggered by monitoring Bedrock Model Invocation logs. Guardrail triggers 
are not visible in CloudTrail events as they appear as successful API calls.

To detect guardrail triggers, you need to enable and examine Bedrock's model invocation logging capabilities, 
which will show when guardrails have intercepted potentially harmful content. Look for the guardrail action 
field in these logs indicating intervention.


