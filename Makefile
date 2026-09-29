VERSION := $(shell python3 -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')

.PHONY: release
release:
	@test -z "$$(git status --porcelain)" || { echo "working tree is not clean"; exit 1; }
	git tag -s $(VERSION) -m $(VERSION)
	git push origin $(VERSION)
	gh release create $(VERSION) --verify-tag --title $(VERSION) --generate-notes
