.PHONY: setup-hooks smoke

setup-hooks:
	git config core.hooksPath bin/hooks

smoke:
	bin/e2e/smoke-all
