[![made-with-Go](https://img.shields.io/badge/Made%20with-Go-1f425f.svg)](http://golang.org)  [![Tests](https://github.com/DataDog/stratus-red-team/actions/workflows/test.yml/badge.svg)](https://github.com/DataDog/stratus-red-team/actions/workflows/test.yml) [![static analysis](https://github.com/DataDog/stratus-red-team/actions/workflows/static-analysis.yml/badge.svg)](https://github.com/DataDog/stratus-red-team/actions/workflows/static-analysis.yml) ![Maintainer](https://img.shields.io/badge/maintainer-@christophetd-blue) [![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/DataDog/stratus-red-team/badge)](https://api.securityscorecards.dev/projects/github.com/DataDog/stratus-red-team) [![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/6530/badge)](https://bestpractices.coreinfrastructure.org/projects/6530)

## Panther-enhanced fork of Stratus Red Team
[Stratus Red Team](https://github.com/DataDog/stratus-red-team) is an open-source adversary emulation tool that lets you validate the security of your cloud environments by replicating offensive attack techniques in a granular and self-contained manner. It can be thought of as [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)™ for the cloud. 

This repository is a Panther-enhanced fork of Stratus Red Team that adds **end-to-end integration testing for detection engineering**. Instead of using fabricated test cases that may not match production logs, you can use this fork to generate authentic log data, allowing for better attack simulation and detection validation.

<p align="center">
  <a href="https://github.com/DataDog/stratus-red-team/raw/main/docs/demo.gif">
    <img src="./docs/demo.gif" alt="Terminal recording" />
  </a>
</p>


### Why perform end-to-end testing?

Traditional detection testing uses theoretical log samples that may differ from real-world patterns. This approach:
- **Generates authentic logs** from actual attack simulations  
- **Tests the complete pipeline** from log collection to alerting
- **Enables test-driven detection development** with real attack patterns
- **Provides confidence** that idle detection rules will work when attacks occur

### Panther enhancements

#### Custom prefix support
Use `--prefix` to avoid "stratus-red-team" detection by AI systems:
```bash
stratus detonate aws.persistence.iam-create-admin-user --prefix "security-test"
```

**New Attack Techniques** - Enhanced AI/Bedrock security testing:
- `aws.defense-evasion.bedrock-guardrail-delete` - Delete AI safety guardrails
- `aws.defense-evasion.bedrock-model-invocation-logging-delete` - Disrupt AI activity monitoring
- `aws.impact.bedrock-converse-guardrail-trigger` - Test guardrail limits via Converse API
- `aws.impact.bedrock-invoke-model-guardrail-trigger` - Test guardrail limits via InvokeModel API
- `aws.persistence.iam-create-admin-user` - customized to print access key ID
- `gcp.privilege-escalation.tag-based-privilege-escalation` - Escalate GCP compute privileges via conditional access tags

#### Detection Workflow
1. Run attack simulations → Generate authentic logs
2. Export CloudTrail/app logs → Create test fixtures  
3. Write detections → Based on real attack patterns
4. Re-run simulations → Validate end-to-end pipeline

### Related Projects & Talks

**Sister Project**: [Grimoire](https://github.com/panther-labs/grimoire) - Panther's fork of Grimoire for end-to-end detection testing automation

**Talks**:
- [Incorporating End to End Integration Testing into your Detection Engineering Workflow - Open Cloud Security Conference (short version)](https://youtu.be/4Ijyc2JW-3w)
- Incorporating End to End Integration Testing into your Detection Engineering Workflow - BSides Boulder (full version) - link TBD

Read the announcement blog posts:
- https://www.datadoghq.com/blog/cyber-attack-simulation-with-stratus-red-team/
- https://blog.christophetd.fr/introducing-stratus-red-team-an-adversary-emulation-tool-for-the-cloud/

## Getting Started

Stratus Red Team is a self-contained Go binary.

See the documentation at **[stratus-red-team.cloud](https://stratus-red-team.cloud/)**:
- [Stratus Red Team Concepts](https://stratus-red-team.cloud/user-guide/getting-started/#concepts)

- [Installing Stratus Red Team](https://stratus-red-team.cloud/user-guide/getting-started/#installation) - Homebrew formula, Docker image and pre-built binaries available

- [Available Attack Techniques](https://stratus-red-team.cloud/attack-techniques/list/), mapped to MITRE ATT&CK

## Installation

### Direct install

Requires Go 1.22+

```
go install -v github.com/datadog/stratus-red-team/v2/cmd/stratus@latest
```

### Homebrew

```
brew tap datadog/stratus-red-team https://github.com/DataDog/stratus-red-team
brew install datadog/stratus-red-team/stratus-red-team
```

### Pre-build binaries

For Linux / Windows / Mac OS: download one of the [pre-built binaries](https://github.com/datadog/stratus-red-team/releases).

### Docker

```bash
IMAGE="ghcr.io/datadog/stratus-red-team"
alias stratus="docker run --rm -v $HOME/.stratus-red-team/:/root/.stratus-red-team/ -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN -e AWS_DEFAULT_REGION $IMAGE"
```

### asdf

You can install specific versions (or latest) of stratus-red-team using [asdf](https://asdf-vm.com/) and this [stratus-red-team plugin](https://github.com/asdf-community/asdf-stratus-red-team):

```bash
asdf plugin add stratus-red-team https://github.com/asdf-community/asdf-stratus-red-team.git
asdf install stratus-red-team latest
```

## Community

The following section lists posts and projects from the community leveraging Stratus Red Team.

Open-source projects:
- [Threatest](https://github.com/DataDog/threatest)
- [AWS Threat Detection with Stratus Red Team](https://github.com/sbasu7241/AWS-Threat-Simulation-and-Detection)


Videos:
- [Reproducing common attacks in the cloud with Stratus Red Team](https://www.youtube.com/watch?v=M5DGXWF2ld0)
- [Stratus Red Team: AWS EC2 Instance Credential Theft | Threat SnapShot](https://www.youtube.com/watch?v=TVS-M6DrSPw)
- [Automated Attack Simulation in AWS for Red Teaming](https://www.youtube.com/watch?v=O_vNAKLnSc0)

Blog posts:
- [AWS threat emulation and detection validation with Stratus Red Team and Datadog Cloud SIEM](https://www.datadoghq.com/blog/aws-threat-emulation-detection-validation-datadog/)
- [Adversary emulation on AWS with Stratus Red Team and Wazuh](https://wazuh.com/blog/adversary-emulation-on-aws-with-stratus-red-team-and-wazuh/)
- [Sky’s the Limit: Stratus Red Team for Azure](https://blog.detect.dev/posts/azure_for_stratus.html)
- [Detecting realistic AWS cloud-attacks using Azure Sentinel](https://medium.com/falconforce/falconfriday-detecting-realistic-aws-cloud-attacks-using-azure-sentinel-0xff1c-b62fd45c87dc)
- [A Data Driven Comparison of Open Source Adversary Emulation Tools](https://www.picussecurity.com/resource/blog/data-driven-comparison-between-open-source-adversary-emulation-tools)
- [Making Security Relevant in the Cloud](https://www.cloudreach.com/en/technical-blog/making-security-relevant-in-the-cloud/)
- [Detonating attacks with Datadog Stratus Red Team](https://chrisdunne.com/post/detonating-attacks-with-datadog-stratus-red-team)
- [AWS CloudTrail cheatsheet](https://invictus-ir.medium.com/aws-cloudtrail-cheat-sheet-dcf2b92e37e2)
- [Adversary emulation on GCP with Stratus Red Team and Wazuh](https://wazuh.com/blog/adversary-emulation-on-gcp-with-stratus-red-team-and-wazuh/)
- [Automated First-Response in AWS using Sigma and Athena](https://invictus-ir.medium.com/automated-first-response-in-aws-using-sigma-and-athena-615940bedc56)
- [AWS Cloud Detection Lab: Cloud Pen-testing with Stratus Red Team](https://medium.com/@goodycyb/aws-cloud-detection-lab-1%EF%B8%8F%E2%83%A3-%EF%B8%8F-cloud-pen-testing-with-stratus-red-team-tool-69b4fab24743)

Talks:
- [Purple Teaming & Adversary Emulation in the Cloud with Stratus Red Team, DEF CON Cloud Village 2022](https://www.youtube.com/watch?v=rXFFuYbkntU) (recorded after the event as the talks were not recorded)
- [Threat-Driven Development with Stratus Red Team](https://www.youtube.com/watch?v=AbWwcqLwcYI) by Ryan Marcotte Cobb
- [Cloudy With a Chance of Purple Rain: Leveraging Stratus Red Team - BSides Portland 2022](https://www.youtube.com/watch?v=Oq9ObzATZDI)

Papers:
- [A Purple Team Approach to Attack Automation in the Cloud Native Environment](https://aaltodoc.aalto.fi/bitstream/handle/123456789/116425/master_Chaplinska_Svitlana_2022.pdf?sequence=1&isAllowed=y)

## Using Stratus Red Team as a Go Library

See [Examples](./examples) and [Programmatic Usage](https://stratus-red-team.cloud/user-guide/programmatic-usage/).

## Development

### Building Locally

``` bash
make
./bin/stratus --help
```

### Running Locally

```bash
go run cmd/stratus/*.go list
```

### Running the Tests

```bash
make test
```

### Building the Documentation

For local usage:
```
pip install mkdocs-material mkdocs-awesome-pages-plugin

make docs
mkdocs serve
```

### Acknowledgments

Maintainer: [@christophetd](https://twitter.com/christophetd)

Similar projects (see [how Stratus Red Team compares](https://stratus-red-team.cloud/comparison/)):
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) by Red Canary
- [Leonidas](https://github.com/FSecureLABS/leonidas) by F-Secure
- [pacu](https://github.com/RhinoSecurityLabs/pacu) by Rhino Security Labs
- [Amazon GuardDuty Tester](https://github.com/awslabs/amazon-guardduty-tester)
- [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) by Rhino Security Labs

Inspiration and relevant resources:
- https://expel.io/blog/mind-map-for-aws-investigations/
- https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
- https://github.com/elastic/detection-rules/tree/main/rules/integrations/aws
