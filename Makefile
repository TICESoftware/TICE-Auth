default: dev

clean:
	swift package clean
	swift package reset

update: Package.resolved
Package.resolved: Package.swift
	swift package update

lint: Sources Package.swift
	./lint.sh $(version)

version: lint
	git push
	git push --tags
