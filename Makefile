# make test は重いコマンドの待ち列 (dotfiles の serial-run。既定はこの repo の中で 1 本ずつ。SERIAL_RUN_SCOPE=machine ならマシン全体) に並んでから走る。
# 待ち列の断片は dotfiles のもので、無い機械 (CI・dotfiles を入れていない人) では -include が読み飛ばし、包まずに走る。
# 外すときは SERIAL_RUN_MAKE_DISABLE=1。組み込み方は ~/dotfiles/docs/tools/serial-run.md
-include $(HOME)/dotfiles/make/serial-run.mk

.PHONY: setup-hooks smoke smoke-verbose verify-push lint-analyze build test test-all

build:
	swift build

# unit (サーバ不要)。CI の macOS の build-test (.github/workflows/test.yml) と同じ swift build → swift test --skip SMBeeE2ETests
test:
	@+$(serial_run) $(MAKE) --no-print-directory test-all

# 本体。test の中で $(MAKE) test を呼ばない (包まないときに自分を呼び続ける)
test-all: build
	swift test --skip SMBeeE2ETests

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
