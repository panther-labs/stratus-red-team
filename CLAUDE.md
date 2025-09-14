# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Panther-enhanced fork of Stratus Red Team, a cloud adversary emulation tool for end-to-end detection engineering testing. The tool generates authentic attack logs across AWS, GCP, Azure, Kubernetes, and Entra ID platforms to validate security detection rules.

## Common Development Commands

### Building
```bash
make build              # Build the stratus binary to ./bin/stratus
cd v2 && go build -o ../bin/stratus cmd/stratus/*.go
```

### Testing
```bash
make test               # Run all Go tests
cd v2 && go test ./... -v
```

### Running Locally
```bash
# Run without building
go run cmd/stratus/*.go list
cd v2 && go run cmd/stratus/*.go <command>

# After building
./bin/stratus --help
```

### Code Quality
```bash
make lint               # Lint Terraform files
make fmt                # Format Terraform files
make mocks              # Generate mocks using mockery
```

### Documentation
```bash
make docs               # Generate attack technique documentation
cd v2 && go run ./tools/ ../docs
```

## Architecture

### Core Structure
- **v2/**: Main Go module containing all source code
- **cmd/stratus/**: CLI entry point and command definitions
- **internal/attacktechniques/**: Attack technique implementations organized by platform (aws, gcp, azure, k8s, entra-id)
- **pkg/stratus/**: Core libraries and shared functionality
- **examples/**: Usage examples and programmatic API demonstrations
- **docs/**: Generated documentation for attack techniques

### Key Components

#### Attack Techniques Registry
Attack techniques are auto-registered via blank imports in `v2/internal/attacktechniques/main.go`. Each technique is implemented as a separate Go package under its platform directory.

#### CLI Commands
- `list`: Show available attack techniques
- `show`: Display technique details
- `warmup`: Prepare technique prerequisites
- `detonate`: Execute the attack
- `revert`: Undo technique execution
- `status`: Check technique state
- `cleanup`: Remove technique resources
- `version`: Show version info

#### Prefix Customization
The `--prefix` flag allows customizing resource names to avoid detection by AI systems (default: "stratus-red-team").

### Platform Support
- **AWS**: EC2, IAM, S3, Lambda, Bedrock, CloudTrail, etc.
- **GCP**: Compute, IAM, Secret Manager
- **Azure**: VMs, resource management
- **Kubernetes**: RBAC, secrets, privilege escalation
- **EKS**: AWS-specific Kubernetes features
- **Entra ID**: Azure AD persistence techniques

### State Management
Techniques maintain state in `~/.stratus-red-team/` using a combination of JSON files and Terraform state for infrastructure management.

## Development Notes

### Adding New Attack Techniques
1. Create technique package under appropriate platform directory
2. Add blank import to `v2/internal/attacktechniques/main.go`
3. Implement the technique interface in `main.go` of the technique package
4. Include Terraform infrastructure files if needed
5. Run `make docs` to regenerate documentation

### Testing Infrastructure
Many techniques use Terraform for infrastructure provisioning. The codebase uses `hashicorp/terraform-exec` for programmatic Terraform management.

### Panther Enhancements
This fork includes additional techniques for AI/Bedrock security testing and tag-based privilege escalation scenarios not found in the upstream version.
- Don't use emojis