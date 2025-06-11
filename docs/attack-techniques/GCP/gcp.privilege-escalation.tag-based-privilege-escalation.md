---
title: Privilege Escalation via GCP Tag Bindings
---

# Privilege Escalation via GCP Tag Bindings


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: GCP

## MITRE ATT&CK Tactics


- Privilege Escalation

## Description


Simulates a privilege escalation attack in Google Cloud Platform (GCP) by exploiting IAM Conditions that use resource tags.

<span style="font-variant: small-caps;">Warm-up</span>:

- Creates a tag key and value (env=sandbox)
- Creates a Compute Engine VM instance
- Sets up an IAM policy with a conditional binding that grants compute.admin role when a resource has the env=sandbox tag
- Grants the current user roles/resourcemanager.tagUser and roles/viewer permissions

<span style="font-variant: small-caps;">Detonation</span>:

- Enumerates IAM policies to discover conditional role bindings
- Lists available tag keys and values in the environment
- Creates a tag binding to attach the env=sandbox tag to the VM instance
- Attempts a privileged operation (modifying the VM's description) that should succeed after the tag is attached

References:

- https://www.mitiga.io/blog/tag-your-way-in-new-privilege-escalation-technique-in-gcp


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.privilege-escalation.tag-based-privilege-escalation
```
## Detection


Using GCP Admin Activity audit logs, look for the sequence of events that indicates this attack pattern:

1. Enumeration of IAM policies (GetIamPolicy)
2. Listing tag keys and values (TagKeys.ListTagKeys, TagKeys.ListTagValues)
3. Creating a tag binding (TagBindings.CreateTagBinding)
4. Performing a privileged operation shortly after the tag binding is created

Sample Sigma rule to detect this activity:

```yaml
title: GCP Privilege Escalation via TagBinding
id: GCP-PRIVESC-TAGBINDING
description: >
  Detects a sequence in GCP logs where a user enumerates IAM policies and tags,
  binds a tag to a resource, and then performs a privileged action on that resource.
logsource:
  category: cloud.audit
  product: gcp
detection:
  selection_enum_iam_tags:
    methodName|contains:
      - "GetIamPolicy"
      - "TagKeys.ListTagKeys"
      - "TagKeys.ListTagValues"
      - "TagBindings.ListEffectiveTags"

  selection_tag_binding:
    methodName: "TagBindings.CreateTagBinding"

  selection_privileged:
    methodName|in: # List of privileged API methods
      - "beta.compute.instances.setIamPolicy"
      - "compute.instances.update"
      - "compute.instances.setMetadata"
      # Add more privileged operations

  timeframe: 15m

  condition: selection_enum_iam_tags followed by 
             selection_tag_binding followed by 
             selection_privileged
fields:
  - principalEmail
  - resourceName
  - methodName
  - timestamp
  - project_id
level: high
```

Mitigation strategies:

- Treat tag management as privileged - only grant roles/resourcemanager.tagUser to trusted entities
- Separate tagging and access boundaries - ensure identities cannot both set a tag and benefit from that tag
- Use deny policies or organization policies to block risky combinations
- Restrict tag inheritance scope through proper folder and project structure


