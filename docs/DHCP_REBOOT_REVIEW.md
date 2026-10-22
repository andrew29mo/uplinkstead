# DHCP VM restart evidence review

Baseline: `7f836de`. Two independent read-only reviews covered production lifecycle
and installed-service behavior, and receipt/report provenance and contradictions.
Actual tests and the fresh VM receipt determine the result; reviewer agreement is
not additional experimental evidence.

## Findings and corrections

1. **Foreign priority-rule evidence could pass.** The prior report required the
   six owned rules but tolerated additional rules. A synthetic priority-1 rule to
   an unprobed destination could borrow the main route without changing the
   measured target's counter. The original VM receipt contained no such rule;
   this does not establish an actual leak in that run. Validation now requires
   exactly the six owned rules and three builtins, each once, matching the formal
   backend's supported rule scope. The bypass counterexample is explicitly tested.
2. **Stale-authority timestamp checks were incomplete.** The original challenge
   timestamps were valid, but changing the old-boot/revision tests to a past or
   future timestamp could still satisfy the report verifier. That made the
   recorded `Blocked` error ambiguous. Each request now retains dispatch and
   completion boot-time readings and a prior journal event timestamp. The verifier
   requires a legal allocation, current time/order, a live lease and the three-second
   admission window, while varying only the authority field under challenge.
3. **Client deconfiguration could obscure the startup observation.** The formal
   lifecycle already clears allocations before client creation, and portable tests
   check that logic. The older VM receipt observed state after the client started;
   it did not by itself exclude the client's initial deconfig as the cleanup source.
   The formal service now checks empty allocation/health and actual Linux backend
   state before launching BusyBox. A structured startup record is emitted only
   after that read-only check passes. Its journal PID, boot and invocation match
   the installed service; its revision is exactly the pre-boot revision plus one,
   before any client callback. This adds evidence at a defined boundary, not a
   continuous trace or protection before service startup.
4. **Partial setup cleanup could remove an existing identical fixture.** The prior
   code claimed planned objects before checking for conflicts. It now checks all
   reserved objects before freezing the service, creates exclusively, and records
   only actual creations with owner/device/inode. Existing equal-content units,
   equal-target symlinks and a concurrent link creator are preserved in tests.
   A file is recorded immediately after exclusive creation, before writing; an
   injected partial write is cleaned by identity rather than requiring complete
   contents. Failure to persist the cleanup ledger itself remains a failed/unknown
   cleanup condition, not a general disk-failure recovery claim.
5. **RSS identity was sampled too early.** No evidence showed a wrong process in
   the baseline run. The new receipt additionally requires unchanged active service
   identity immediately before and after reading `/proc/<MainPID>/status`.

6. **The positive control shared a live packet counter.** A review VM run failed
   on a nonzero backup counter immediately after the root TCP positive control.
   There was no packet trace proving whether it was delayed control teardown or
   another flow; that run remains failed and is not labeled a confirmed LAN leak.
   The revised check excludes only the observed root control's full TCP tuple.
   All other flows to the target, including declared LAN and DHCP-source probes,
   remain counted. Actual nftables hook/exemption/counter expressions are read back
   and checked; excluding a LAN source or adding an exemption cannot pass. This
   avoids relying on a sleep to assume the earlier connection has drained.

The first isolated monitor rerun completed all VM phases but failed final report
validation: nftables grouped the TCP port comparisons in its actual readback,
while the verifier expected the earlier input order. The exact generated/expected
order was corrected against retained raw expressions, without dropping any
condition or verdict. That failed receipt was not relabeled as passed; a fresh
full run establishes the current manifest.

## What remains valid from the baseline

The unchanged journal captured after a different boot and before production
ExecStart, plus the explicit shutdown-only SIGKILL override, excludes graceful
pre-shutdown lease clearing as the explanation for that run. Installed unit hashes,
source fingerprints, JSON/HTML correspondence and the stated power-loss limits
were consistent. Original receipts are preserved as historical observations;
the new checks are established only by the new source/run.

## Verification and scope

[Current receipt](../reviews/dhcp-reboot-review/README.md) records the actual
portable tests, installed-service Linux scenarios, VM restart, corruption controls,
measurements and cleanup. Missing startup evidence, unknown/extra rules, invalid
challenge timing, PID/invocation drift, timeouts, missing stages and failed cleanup
cannot pass. The startup record comes from the shipping service, not a replacement
client, mock recovery or an injected ExecStart wrapper.

The VM shutdown is orderly, with an explicit runtime-only process-termination
fault to retain the live lease. Sudden power loss, torn writes, hardware storage
failure, continuous early-boot protection and real ISP behavior remain untested.
Root ownership is a cooperation boundary, not containment of a malicious privileged
writer. No recovery SLO, peak RSS, throughput gain or uninterrupted connection
claim is derived from these results.
