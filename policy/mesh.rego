# Policy-as-code gate for the secure-mesh study. Run with:
#   conftest test --combine -p policy k8s/generated/c.yaml
# Every message starts with a rule id (R1..R11) so the seeded-misconfiguration
# benchmark can attribute each detection to a rule.
package main

import rego.v1

docs := [d.contents | some d in input]

kind(k) := [d | some d in docs; d.kind == k]

ns_of(d) := object.get(d.metadata, "namespace", "default")

mesh_namespaces := {n.metadata.name |
	some n in kind("Namespace")
	object.get(object.get(n.metadata, "labels", {}), "istio-injection", "") == "enabled"
}

expect_mesh_namespaces := {n.metadata.name |
	some n in kind("Namespace")
	object.get(object.get(n.metadata, "annotations", {}), "policy.study/expect-mesh", "") == "true"
}

pod_spec(d) := d.spec.template.spec

containers(d) := pod_spec(d).containers

is_edge(p) if object.get(object.get(p.metadata, "annotations", {}), "policy.study/edge", "") == "true"

# R1 every workload has its own ServiceAccount (identity is the basis of AuthZ)
deny contains msg if {
	some d in kind("Deployment")
	object.get(pod_spec(d), "serviceAccountName", "default") == "default"
	msg := sprintf("R1 %s/%s uses the default ServiceAccount", [ns_of(d), d.metadata.name])
}

# R2 mesh namespaces enforce STRICT mTLS namespace-wide
deny contains msg if {
	some ns in mesh_namespaces
	not strict_peer_auth(ns)
	msg := sprintf("R2 namespace %s has no namespace-wide STRICT PeerAuthentication", [ns])
}

strict_peer_auth(ns) if {
	some p in kind("PeerAuthentication")
	ns_of(p) == ns
	not p.spec.selector
	p.spec.mtls.mode == "STRICT"
}

# R3 every workload in a mesh namespace is selected by an AuthorizationPolicy
deny contains msg if {
	some d in kind("Deployment")
	ns_of(d) in mesh_namespaces
	not covered_by_authz(d)
	msg := sprintf("R3 %s/%s is not covered by any AuthorizationPolicy", [ns_of(d), d.metadata.name])
}

covered_by_authz(d) if {
	some p in kind("AuthorizationPolicy")
	ns_of(p) == ns_of(d)
	p.spec.selector.matchLabels.app == d.metadata.labels.app
}

# R4 no allow-all ALLOW policy unless explicitly marked as the public edge
deny contains msg if {
	some p in kind("AuthorizationPolicy")
	object.get(p.spec, "action", "ALLOW") == "ALLOW"
	not is_edge(p)
	some r in p.spec.rules
	count(object.keys(r)) == 0
	msg := sprintf("R4 AuthorizationPolicy %s/%s contains an allow-all rule", [ns_of(p), p.metadata.name])
}

# R5 no wildcard caller identities
deny contains msg if {
	some p in kind("AuthorizationPolicy")
	not is_edge(p)
	some r in p.spec.rules
	some f in r.from
	some pr in f.source.principals
	contains(pr, "*")
	msg := sprintf("R5 AuthorizationPolicy %s/%s allows wildcard principal %q", [ns_of(p), p.metadata.name, pr])
}

# R6 images are pinned (no :latest / untagged)
deny contains msg if {
	some d in kind("Deployment")
	some c in containers(d)
	not pinned(c.image)
	msg := sprintf("R6 %s/%s image %q is not pinned to a tag or digest", [ns_of(d), d.metadata.name, c.image])
}

pinned(img) if contains(img, "@sha256:")

pinned(img) if {
	parts := split(img, ":")
	count(parts) > 1
	parts[count(parts) - 1] != "latest"
}

# R7 container hardening
deny contains msg if {
	some d in kind("Deployment")
	some c in containers(d)
	object.get(object.get(c, "securityContext", {}), "privileged", false) == true
	msg := sprintf("R7 %s/%s runs a privileged container", [ns_of(d), d.metadata.name])
}

deny contains msg if {
	some d in kind("Deployment")
	some c in containers(d)
	sc := object.get(c, "securityContext", {})
	not sc.runAsNonRoot == true
	not object.get(pod_spec(d), "securityContext", {}).runAsNonRoot == true
	msg := sprintf("R7 %s/%s does not enforce runAsNonRoot", [ns_of(d), d.metadata.name])
}

deny contains msg if {
	some d in kind("Deployment")
	some c in containers(d)
	object.get(object.get(c, "securityContext", {}), "runAsUser", 1) == 0
	msg := sprintf("R7 %s/%s runs as UID 0", [ns_of(d), d.metadata.name])
}

deny contains msg if {
	some d in kind("Deployment")
	some c in containers(d)
	object.get(object.get(c, "securityContext", {}), "allowPrivilegeEscalation", true) == true
	msg := sprintf("R7 %s/%s allows privilege escalation", [ns_of(d), d.metadata.name])
}

# R8 resource limits are set (noisy-neighbour / DoS containment)
deny contains msg if {
	some d in kind("Deployment")
	some c in containers(d)
	not c.resources.limits.cpu
	msg := sprintf("R8 %s/%s has no CPU limit", [ns_of(d), d.metadata.name])
}

deny contains msg if {
	some d in kind("Deployment")
	some c in containers(d)
	not c.resources.limits.memory
	msg := sprintf("R8 %s/%s has no memory limit", [ns_of(d), d.metadata.name])
}

# R9 no secret material in ConfigMaps or literal env values
secret_name_re := `(?i)(api[_-]?key|secret|passwd|password|token|private[_-]?key|credential)`

deny contains msg if {
	some cm in kind("ConfigMap")
	some k, v in object.get(cm, "data", {})
	regex.match(`PRIVATE KEY`, v)
	msg := sprintf("R9 ConfigMap %s/%s key %q embeds private key material", [ns_of(cm), cm.metadata.name, k])
}

deny contains msg if {
	some cm in kind("ConfigMap")
	some k, v in object.get(cm, "data", {})
	regex.match(secret_name_re, k)
	v != ""
	msg := sprintf("R9 ConfigMap %s/%s key %q looks like a credential", [ns_of(cm), cm.metadata.name, k])
}

deny contains msg if {
	some d in kind("Deployment")
	some c in containers(d)
	some e in object.get(c, "env", [])
	regex.match(secret_name_re, e.name)
	e.value != ""
	msg := sprintf("R9 %s/%s env %q carries a literal credential", [ns_of(d), d.metadata.name, e.name])
}

# R10 mesh namespaces restrict egress to the service registry
deny contains msg if {
	some ns in mesh_namespaces
	not registry_only(ns)
	msg := sprintf("R10 namespace %s does not restrict egress (REGISTRY_ONLY Sidecar missing)", [ns])
}

registry_only(ns) if {
	some s in kind("Sidecar")
	ns_of(s) == ns
	s.spec.outboundTrafficPolicy.mode == "REGISTRY_ONLY"
}

# R11 namespaces that must be meshed really are injected
deny contains msg if {
	some ns in expect_mesh_namespaces
	not ns in mesh_namespaces
	msg := sprintf("R11 namespace %s is expected to be meshed but sidecar injection is off", [ns])
}

# R12 no workload- or port-level mTLS downgrade except on the annotated public edge
deny contains msg if {
	some p in kind("PeerAuthentication")
	ns_of(p) in mesh_namespaces
	not is_edge(p)
	p.spec.mtls.mode in {"PERMISSIVE", "DISABLE"}
	p.spec.selector
	msg := sprintf("R12 PeerAuthentication %s/%s downgrades mTLS for a workload", [ns_of(p), p.metadata.name])
}

deny contains msg if {
	some p in kind("PeerAuthentication")
	ns_of(p) in mesh_namespaces
	not is_edge(p)
	some port, cfg in object.get(p.spec, "portLevelMtls", {})
	cfg.mode in {"PERMISSIVE", "DISABLE"}
	msg := sprintf("R12 PeerAuthentication %s/%s downgrades mTLS on port %s", [ns_of(p), p.metadata.name, port])
}
