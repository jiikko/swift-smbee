.PHONY: setup-hooks smoke smoke-verbose verify-push lint-analyze

setup-hooks:
	git config core.hooksPath bin/hooks

# unused_declaration / unused_import (analyzer rules)。build tool plugin の lint では走らない。
lint-analyze:
	bin/ci/lint-analyze

smoke:
	bin/e2e/smoke-agent

smoke-verbose:
	bin/e2e/smoke-all

verify-push:
	bin/ci/verify-agent-push
