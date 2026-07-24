.PHONY: setup-hooks smoke smoke-verbose verify-push

setup-hooks:
	git config core.hooksPath bin/hooks

smoke:
	bin/e2e/smoke-agent

smoke-verbose:
	bin/e2e/smoke-all

verify-push:
	bin/ci/verify-agent-push
