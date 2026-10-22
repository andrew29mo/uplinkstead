# Four-exploration validation

Final run: **0a60c943b1429c7f**. Source fingerprint:
`2d59b046105fdbcebb5903e0c906fc5de17bd2c30f8135e2ac11ae4969b9dba0`.
The manifest covers product, tools, tests/fixture JSON, shipping service and package
metadata. Documentation and retained receipts are outside that manifest.

[JSON](../reviews/audit/evidence.json) · [HTML](../reviews/audit/report.html)
· [macOS](../reviews/audit/native-unit.json) · [Linux](../reviews/audit/linux-unit.json)
· [Initial attempt ledger](../reviews/attempts.json) · [Audit attempts](../reviews/audit/attempts.json)

## Observed outcomes

- **56/56 portable tests on macOS and 56/56 on Linux**, identical test IDs and
  source fingerprints, zero skips/failures/errors. Mocked writer unit tests are
  separate from actual backend execution in the VM.
- **19 real Linux namespace scenarios** using the production probe, policy,
  Writer and iproute2 backend. The fixture invokes the same formal agent cycle with actual
  TLS outcomes and measured timestamps; this is not a claim that every case runs through the systemd loop.
- Actual shipped agent service under systemd, SIGKILL restart with a different
  InvocationID, preserved latch, and an **orderly VM stop/start** with a new boot ID.
- **20 report corruption controls** rejected, including failed stages/timeouts,
  mismatched source/tests, reboot or cleanup contradictions, unsupported power-loss
  claims, wrong probe peers/counts/links, escaped internal/local traffic, fabricated
  probe timing or budget transitions, stale-health writes and wrong installed unit.
  Explicit report checks also remain active under Python optimization; assertion-
  based validation fixtures refuse optimized execution.
- Private source snapshot removed, owned services/namespaces removed, VM stopped.
  Root routes/rules and nft/iptables/ip6tables semantics matched before/after.

These are distinct evidence categories; do not add them into a single test count.

## The nineteen scenarios

| Scenario | Evidence |
|---|---|
| Healthy pinned probes | A and B each 3/3; remote server observes different expected egress SNAT addresses |
| Blackhole/missing route/down | Both directions tested, other path healthy, wrong-egress source counter delta zero, terminal lookup rejects fallthrough |
| Binding failure | Invalid device produces UNKNOWN, never an ordinary unbound fallback |
| LAN scope | Fresh LAN TLS requests change A -> B; ordinary router and other-LAN requests remain A; main table unchanged; declared internal route lookup stays A |
| External RPDB | Intersecting rule blocks entry with no rule mutation; plainly disjoint other-ingress rule survives selection |
| OUTPUT vs FORWARD | B probe succeeds 3/3 while LAN request fails under a forward drop; not counted as recovery |
| Reverse-path contract | Effective strict rp_filter rejected; service does not rewrite the setting |
| Routed fixture | Both uplinks serve non-NAT LAN source with explicit fixture-provisioned return routes; those are not auto-repaired by the service |
| Interface recovery | Actual selected-route removal on link-down reconciles; B serves a new request; owned probe/connected routes reconstruct on A up without preference failback |
| Old pre-lock request | Cached old epoch rejected after successor selection; B continues serving |
| Live old writer | Stopped lock holder blocks successor; successor permitted only after retirement |
| Inherited helper lock | Real mutation subprocess stopped before exec; parent killed; inherited descriptor still blocks successor until child retirement |
| Three SIGKILL boundaries | Before write restores actual A; after write and before receipt reconcile actual B; no blind stale replay |
| Live probe/policy faults | Actual TLS outcomes drive formal policy through A/B alternating faults; exactly three admitted selections, no default failback, then persistent latch; every LAN result retained |
| One target down | Actual upstream port block leaves 2/3 quorum successes |
| Inverted RPDB | Real negated lookup/prohibit rules rejected, route/rule snapshots unchanged |
| Missing local lookup | Missing priority-zero lookup rejected without mutation; restored fixture serves router-local TLS |
| Expired health | Real cycle selects B, delayed preflight expires its proof, formal Writer rejects before route mutation |
| Malformed target | One real TLS endpoint returns JSON null; formal cycle survives with 2/3 quorum |


The helper test injects a stop at the subprocess boundary using an external wrapper;
it does not claim a real hung kernel netlink operation. The other fault wrappers
pause the actual Writer methods before/after route writes or before durable receipt.
No wrapper is installed as the normal agent after reboot.

## Restart proof and measurements

Before shutdown, the real Writer has persisted B intent and changed the active
route to B, while the completed selection receipt remains A. At the next boot,
the fixture topology unit reads that same pending token **before Agent startup**.
The normal agent reconstructs B, reconciles pending to none, retains the budget
latch, and a real LAN TLS request observes B. Its first new-boot health observations
are RECOVERING for both links, not reused HEALTHY evidence. This excludes a
shutdown-before-test rollback as the explanation.

The VM is Colima VZ Linux ARM64, four CPUs and 6 GiB configured memory, Linux
6.8.0-117-generic, Python 3.12.3, systemd 255. macOS runs the portable suite only.
All six namespaces share one kernel and VM failure domain. Three TLS target ports
share one fixture server; they do not model independent Internet providers.

After reboot the agent's `/proc/<pid>/status` VmRSS snapshot was **23,704 KiB**.
It is not peak/PSS/whole-VM memory. Scenario `seconds` includes fixture actions,
probes, failures and validation; it is not failover latency or an SLO. No throughput,
speedup, physical-WAN, repeated-trial confidence or capacity claim is made.

## Lessons that changed the design

- Actual iproute2 JSON differs from its textual display: normalize string table
  IDs, split address/prefix lengths and suppress-prefix naming without accepting
  unknown rule semantics. A captured-format regression is in the portable suite.
- Link-down removes routes. Probe/connected-route maintenance restores only missing
  owned routes after link-up. Disappearance of the selected route is accepted only
  when its interface is observed down; arbitrary route disappearance still blocks.
- Loose reverse-path filtering still needs a route back to the remote source.
  The fixture's external network provisioner configures main-table primary and
  fallback routes; Uplinkstead never creates or repairs those main routes. Removing
  the only reverse route can make an otherwise valid B probe fail. Deployment must
  qualify this condition; rp_filter=2 alone is not proof of compatibility.
- Configuration identity and generations must be enforced while holding the actual
  mutation lock. A dead parent does not prove its child lost mutation ownership.
- Firewall counters and object handles legitimately change across boots. Root
  preservation checks retain expressions, operands, actions and rule order; they
  ignore only nft handles/counter values and iptables chain counters/generated
  comments. iptables-save is also checked because nft JSON alone can omit details
  of compatibility expressions. Regression tests retain meaningful byte operands,
  rule comments and action/order differences.

## Failed attempts and limitations

Seven earlier attempts failed and remain failed in the ledger. They exposed setup,
JSON representation, link-route reconstruction, reverse-route and cleanup problems.
Attempt six reached all 14 then-existing scenarios and reboot but failed cleanup
comparison; manual semantic verification/removal followed. Attempt seven additionally
found a cleanup variable-shadowing error; its separate manual cleanup receipt is
retained. Only initial attempt eight passed its then-current source, cleanup and verifier
(commit db00f52; historical 39-test/15-case schema). Two audit runs subsequently
passed, with the latest source adding the corrections in [AUDIT.md](AUDIT.md).
The first audit pass is retained as superseded after the malformed-response follow-up.
Private logs are local and excluded from Git. Intermediate source hashes are retained,
but not every failed source revision is a Git commit; exact old-source replay is limited.

Untested: sudden power loss, storage corruption/write-failure recovery, actual
kernel-stuck I/O, boot-zero-gap, physical NIC/ISP failures, IPv6, dynamic addressing,
long-duration/saturated load, live optional automatic failback and full privilege
separation. No actual VM wall-clock adjustment was performed; clock/freshness logic
is covered by portable policy inputs. This is exploration evidence, not a complete
operational MVP or production qualification.
