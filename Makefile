.PHONY: setup-hooks smoke verify-push

setup-hooks:
	git config core.hooksPath bin/hooks

smoke:
	bin/e2e/smoke-all

verify-push:
	bin/ci/verify-agent-push
