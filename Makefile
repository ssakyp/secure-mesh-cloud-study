.PHONY: build keys manifests test local-smoke article clean
build:            ## build the service binary used by local tests
	cd svc && CGO_ENABLED=0 go build -o ../meshsvc .
keys:
	python3 tools/gen_keys.py
manifests: keys
	python3 tools/gen_manifests.py
test: build manifests   ## everything that can be verified without a cluster
	cd svc && go vet ./... && go test ./...
	python3 tests/test_jwt_crosscheck.py
	opa test policy
	@for s in c d; do conftest test --combine -p policy k8s/generated/$$s.yaml || exit 1; python3 tools/policy_intent_check.py k8s/generated/$$s.yaml || exit 1; done
	python3 seeded/mutate.py
	python3 scripts/attack_matrix.py --model --out /tmp/e2_model
	python3 tests/synth_e1.py
	python3 tests/test_cert_parse.py
local-smoke: build keys ## real k6 load + fault on a local 12-process stack
	python3 tests/local_resilience_demo.py
article:          ## copy generated tables/figures next to main.tex
	cp results/analysis/tables.tex article/ ; mkdir -p article/figures ; cp results/analysis/figures/*.pdf article/figures/ 2>/dev/null || true
clean:
	rm -rf results/* seeded/out k8s/generated/*.yaml meshsvc
