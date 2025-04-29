---
title: Trigger Bedrock Guardrail
---

# Trigger Bedrock Guardrail


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Impact

## Description


Trigger an Amazon Bedrock guardrail with harmful content. Simulates testing the limits of AI safety controls.

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create a Bedrock guardrail.

<span style="font-variant: small-caps;">Detonation</span>: 

- Send a prompt to a Bedrock model that should trigger the guardrail.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.impact.bedrock-guardrail-trigger
```
## Detection


Identify when a Bedrock guardrail is triggered, through CloudTrail's <code>InvokeModel</code> event with a blocked response.


