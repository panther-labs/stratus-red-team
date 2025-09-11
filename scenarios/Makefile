# Stratus Red Team Scenarios Makefile

.PHONY: all clean help iam-to-s3-training-data

# Default target
all: iam-to-s3-training-data

# Build IAM-to-S3 training data exfiltration scenario
iam-to-s3-training-data:
	@echo "Building IAM-to-S3 training data scenario..."
	go build -o iam-s3-scenario iam-to-s3-training-data/main.go
	@echo "Built: ./iam-s3-scenario"

# Clean all built binaries
clean:
	@echo "Cleaning scenario binaries..."
	rm -f iam-s3-scenario
	@echo "Clean complete"

# Test build all scenarios without creating binaries
test:
	@echo "Testing all scenario builds..."
	go build -o /tmp/test-iam-s3 iam-to-s3-training-data/main.go
	rm -f /tmp/test-iam-s3
	@echo "All scenarios build successfully"

# Help target
help:
	@echo "Available targets:"
	@echo "  all                      - Build all scenarios"
	@echo "  iam-to-s3-training-data  - Build IAM-to-S3 training data scenario"
	@echo "  test                     - Test build all scenarios"
	@echo "  clean                    - Remove all built binaries"
	@echo "  help                     - Show this help message"
	@echo ""
	@echo "Usage examples:"
	@echo "  make iam-to-s3-training-data && ./iam-s3-scenario"
	@echo "  make all"
	@echo "  make clean"