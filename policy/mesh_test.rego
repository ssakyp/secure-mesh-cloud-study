package main

import rego.v1

ns_c := {"contents": {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "t", "labels": {"istio-injection": "enabled"}}}}

dep(sa, image) := {"contents": {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "x", "namespace": "t", "labels": {"app": "x"}}, "spec": {"template": {"spec": {
	"serviceAccountName": sa,
	"securityContext": {"runAsNonRoot": true},
	"containers": [{"name": "app", "image": image, "securityContext": {"allowPrivilegeEscalation": false}, "resources": {"limits": {"cpu": "1", "memory": "1Gi"}}}],
}}}}}

test_default_sa_denied if {
	some m in deny with input as [dep("default", "i:1")]
	startswith(m, "R1 ")
}

test_own_sa_ok_for_r1 if {
	count({m | some m in deny with input as [dep("sa-x", "i:1")]; startswith(m, "R1 ")}) == 0
}

test_latest_denied if {
	some m in deny with input as [dep("sa-x", "i:latest")]
	startswith(m, "R6 ")
}

test_untagged_denied if {
	some m in deny with input as [dep("sa-x", "i")]
	startswith(m, "R6 ")
}

test_digest_ok if {
	count({m | some m in deny with input as [dep("sa-x", "i@sha256:abc")]; startswith(m, "R6 ")}) == 0
}

test_mesh_namespace_requires_strict if {
	some m in deny with input as [ns_c]
	startswith(m, "R2 ")
}

test_mesh_namespace_requires_egress_restriction if {
	some m in deny with input as [ns_c]
	startswith(m, "R10 ")
}

test_unprotected_workload_denied if {
	some m in deny with input as [ns_c, dep("sa-x", "i:1")]
	startswith(m, "R3 ")
}

test_literal_secret_env_denied if {
	d := {"contents": {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "x", "namespace": "t", "labels": {"app": "x"}}, "spec": {"template": {"spec": {
		"serviceAccountName": "sa-x",
		"containers": [{"name": "app", "image": "i:1", "env": [{"name": "GROQ_API_KEY", "value": "gsk_abc"}], "securityContext": {"runAsNonRoot": true, "allowPrivilegeEscalation": false}, "resources": {"limits": {"cpu": "1", "memory": "1Gi"}}}],
	}}}}}
	some m in deny with input as [d]
	startswith(m, "R9 ")
}
