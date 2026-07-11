VERSION := $(shell node -p "require('./package.json').version")
BIN_DIR := bin

.PHONY: build release clean

build:
	bun install --linker isolated
	bun run build:bin

clean:
	rm -rf $(BIN_DIR)
