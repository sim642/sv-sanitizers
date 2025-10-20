.PHONY: sv-comp-build sv-comp-smoketest-ubuntu sv-comp-smoketest-competition sv-comp-smoketest sv-comp

sv-comp-build:
	./sv-comp-archive.sh

sv-comp-smoketest-ubuntu: sv-comp-build
	docker build . --target smoketest-ubuntu

sv-comp-smoketest-competition: sv-comp-build
	docker build . --target smoketest-competition

sv-comp-smoketest: sv-comp-smoketest-ubuntu sv-comp-smoketest-competition;
sv-comp: sv-comp-smoketest sv-comp-build;
