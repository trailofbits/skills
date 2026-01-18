.PHONY: validate build zip dev release clean help

# Default target
help:
	@echo "Available targets:"
	@echo "  validate  - Check that discovery files are up to date (CI mode)"
	@echo "  build     - Generate AGENTS.md, skills-index.json, and symlinks"
	@echo "  zip       - Create zip distributions for each skill"
	@echo "  dev       - Run validate + build"
	@echo "  release   - Run validate + build + zip"
	@echo "  clean     - Remove generated zip files"

# Validate that generated files match what's on disk (for CI)
validate:
	uv run scripts/build-discovery.py --check

# Generate discovery files
build:
	uv run scripts/build-discovery.py

# Create zip distributions for each skill
zip: build
	@echo "Creating zip distributions..."
	@mkdir -p dist
	@for skill in skills/*/; do \
		name=$$(basename "$$skill"); \
		echo "  Packaging $$name..."; \
		(cd skills && zip -rq "../dist/$$name.zip" "$$name/"); \
	done
	@echo "Zip files created in dist/"
	@ls -la dist/*.zip 2>/dev/null || true

# Development workflow: validate and rebuild
dev: validate build

# Full release workflow: validate, build, and package
release: validate build zip
	@echo "Release artifacts ready in dist/"

# Clean generated zip files
clean:
	rm -rf dist/*.zip
	@echo "Cleaned zip distributions"
