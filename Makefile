default:

clean:
	swift package clean
	swift package reset

lint: Sources
	./lint.sh $(version)

version: lint
	git push
	git push --tags
