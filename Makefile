# Copyright (c) 2026 Chainguard Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Local runner for the checks that gate this repo.
#
# `make` / `make ci`  - run every check CI runs (static checks + Docker-based
#                       Control Tests).
# `make fast`         - static checks only, no Docker (quick inner loop).
# `make help`         - list all targets.
#
# Each target mirrors a CI step (see .github/workflows/) or a pre-commit hook,
# so a green `make ci` locally should mean a green CI run. Full `rubocop` is a
# separate, opt-in target: it is not a CI gate (the controls carry many known
# Style offenses), so it is intentionally excluded from `ci`.

SHELL := bash

# cinc-auditor image for profile validation and control tests (matches CI).
CINC_AUDITOR_IMAGE ?= cincproject/auditor:latest
export CINC_AUDITOR_IMAGE

# Workflow files actionlint checks (excludes dependabot, mirroring actionlint.yaml).
WORKFLOWS := $(shell find .github/workflows -name '*.y*ml' 2>/dev/null | grep -v dependabot.)

.DEFAULT_GOAL := ci

.PHONY: ci fast lint test pre-commit actionlint zizmor rubocop cinc-check tools-test controls help

ci: lint test ## Run every check CI runs (default)

fast: lint ## Static checks only — no Docker (quick inner loop)

lint: pre-commit actionlint zizmor ## All static gating checks

pre-commit: ## Default-stage pre-commit hooks (shellcheck, ruby syntax, whitespace, yaml)
	pre-commit run --all-files

actionlint: ## Lint GitHub workflows (mirrors actionlint.yaml)
	SHELLCHECK_OPTS="--exclude=SC2129" actionlint $(WORKFLOWS)

zizmor: ## Audit GitHub workflows (mirrors zizmor.yaml; uses .github/zizmor.yml)
	zizmor .github/workflows/

rubocop: ## Full rubocop style review (opt-in; not a CI gate)
	pre-commit run --hook-stage manual rubocop --all-files

test: cinc-check tools-test controls ## Docker-based Control Tests (mirrors control-tests.yml)

cinc-check: ## Validate a clean staged profile with cinc-auditor
	@stage="$$(mktemp -d)"; \
	trap 'rm -rf "$$stage"' EXIT; \
	cp inspec.yml "$$stage/"; \
	cp -a controls libraries "$$stage/"; \
	docker run --rm --platform linux/amd64 -v "$$stage:/profile:ro" "$(CINC_AUDITOR_IMAGE)" check /profile

tools-test: ## Run tools/ shell tests (test/tools/*_test.sh)
	@shopt -s nullglob; \
	tests=(test/tools/*_test.sh); \
	if [ $${#tests[@]} -eq 0 ]; then echo "No tools shell tests found (test/tools/*_test.sh)"; exit 0; fi; \
	for t in "$${tests[@]}"; do echo "== $$t =="; bash "$$t" || exit 1; done

controls: ## InSpec control suite (prefers system rspec, falls back to bundled)
	@cd test && if command -v rspec >/dev/null 2>&1; then \
		echo "Using system rspec"; rspec; \
	else \
		echo "system rspec not found; using bundle exec rspec"; bundle exec rspec; \
	fi

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
