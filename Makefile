VERSION := $(shell python3 -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')

.PHONY: release
release:
	@test -z "$$(git status --porcelain)" || { echo "working tree is not clean"; exit 1; }
	git tag -s v$(VERSION) -m v$(VERSION)
	git push origin v$(VERSION)
	gh release create v$(VERSION) --verify-tag --title v$(VERSION) --generate-notes
