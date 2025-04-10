---
title: Trigger Bedrock Guardrail via InvokeModel API
---

# Trigger Bedrock Guardrail via InvokeModel API


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Impact

## Description


Trigger an Amazon Bedrock guardrail using the InvokeModel API with harmful content. Simulates testing the limits of AI safety controls through direct model invocation.

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create a Bedrock guardrail.

<span style="font-variant: small-caps;">Detonation</span>: 

- Send a harmful prompt to a Bedrock model using the InvokeModel API with guardrail parameters.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.impact.bedrock-invoke-model-guardrail-trigger
```
## Detection


Identify when a Bedrock guardrail is triggered by monitoring CloudTrail for <code>InvokeModel</code> events with a 
guardrail identifier in the <code>requestParameters</code>. Unlike some other services, successful guardrail 
triggers still appear as successful API calls in CloudTrail, not as errors.

To detect guardrail triggers, you should examine the model responses or set up additional guardrail
monitoring through Bedrock's model invocation logging capabilities.


