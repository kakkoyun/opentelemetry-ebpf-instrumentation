# eBPF Auto-Instrumentation (OBI) vs Go Compile-Time Instrumentation (otelc)

**A deep comparison report** — based on source-level analysis of
`opentelemetry-ebpf-instrumentation` (OBI, formerly Grafana Beyla) and live-source research on
`open-telemetry/opentelemetry-go-compile-instrumentation` (otelc) and its production-grade
upstream `alibaba/loongsuite-go-agent`. All OBI claims cite files in this repository;
otelc claims were verified against the live repo, ADRs, and OTel/CNCF blog posts as of July 2026.

---

## 0. Executive summary

The two projects answer the same question — "how do I get traces without writing instrumentation
code?" — from opposite ends of the stack, and their failure modes are mirror images:

- **OBI observes from outside the process** (kernel probes + userspace-memory uprobes). It gets you
  fleet-wide, language-agnostic, zero-touch coverage — at the price of *reconstructing* application
  semantics from syscalls and reverse-engineered memory layouts. Every hard part of OBI (context
  propagation, TLS, protocol detection, async correlation) is hard *because the process won't
  cooperate*, and the workarounds are heuristics with documented, bounded windows in which they
  work. When they miss, you get silently wrong or missing telemetry — or, in the worst case
  (`bpf_probe_write_user` with a stale offset), a crashed target process.

- **otelc rewrites your code at build time** so the *real* OpenTelemetry SDK runs in-process. Context
  propagation, sampling, baggage, and manual-span interop are simply *correct*, because they are the
  SDK, not a reconstruction. The price: Go only, every service must adopt a build wrapper and
  rebuild, a per-library rule/version matrix to maintain, compile-time overhead, and a new
  supply-chain surface in your build. Its failure mode is silent *non*-instrumentation and build
  friction — never a crashed process.

**Validated headline finding on the TLS question:** the user's intuition is confirmed, with one
important nuance. When TLS terminates *inside* the instrumented process, OBI can still **capture**
the traffic (via OpenSSL/Go-tls/Java-agent plaintext hooks) but can **inject trace context into it
for exactly one runtime: Go** — because only there does OBI hook the plaintext write path *before*
encryption. For everything else (Python, Java, Node, Ruby, .NET, nginx, …), header injection into
TLS traffic is impossible and OBI falls back to a **proprietary TCP option (kind 25)** that only
another OBI agent can read and that any L7 proxy, LB, or TLS-terminating middlebox silently strips.
gRPC/HTTP2-over-TLS from non-Go apps has **no injection path at all** (`SUPPORT_MATRIX.md:64-65`).

**Maturity asymmetry matters:** OBI is a production system (Beyla lineage, OTel-donated, broad
vendor adoption). otelc is **v0.5.0 and explicitly "not ready for production use"** with ~12
instrumented libraries and a broken `go get` install (issue #665); the production-grade
compile-time option today is `alibaba/loongsuite-go-agent` v1.12.0 (~60 libraries) or Datadog's
Orchestrion. Comparisons below distinguish "the architecture" (sound, converging) from "the OTel
repo today" (immature).

---

## 1. How each approach works (recap)

### 1.1 OBI

```
discovery (/proc + k8s) → per-process probe attach → in-kernel protocol parsing
  → ringbuffer → userspace span reconstruction → decoration → head sampling → OTLP
```

- **Spans are born in the kernel**: eBPF programs correlate request/response pairs and emit events
  carrying payload excerpts + `tp_info_t{trace_id, span_id, parent_id, ts, flags}`
  (`bpf/common/tp_info.h`). IDs are minted in kernel space with `bpf_get_prandom_u32()`.
- **Two capture strategies**: a generic tracer (kprobes on `tcp_sendmsg`/`tcp_recvmsg`, heuristic
  protocol classification) for any language, and a Go tracer (uprobes on runtime/stdlib/library
  functions, goroutine tracking) for Go.
- **Context propagation** is a four-layer machine: kprobe header parsing on ingress, `sk_msg`
  packet extension + sockops TCP options + Go `bpf_probe_write_user` on egress, and a "black-box"
  thread/goroutine-keyed parent search for intra-process request linking
  (`devdocs/context-propagation.md`, `bpf/common/trace_parent.h`).
- **Sampling is head-only, at export time, in userspace** (`pkg/export/otel/tracesgen/tracesgen.go:99`).

### 1.2 otelc (compile-time)

```
otelc go build → phase 1: pin instrumentation deps into go.mod (otelc pin / tool file)
             → phase 2: -toolexec intercepts each `compile`; AST-weaves trampolines
               into matched functions → real OTel SDK runs in-process
```

- Uses Go's standard `-toolexec` hook: `otelc` shims every compiler invocation, parses matched
  packages' ASTs, injects **trampoline calls** at function entry/exit bound via `//go:linkname`,
  writes modified sources to `.otelc-build/`, and compiles those. Panics in hook code are caught
  by the trampoline — hooks can't crash the app.
- **Rules** (`*.otelc.yml`) select join points (import path + version range + function/receiver
  matchers) and advice (`inject_hooks`, `wrap_call`, `add_struct_fields`, `inject_code`, …).
  Instrumentation dependencies become ordinary, auditable `go.mod` entries (ADR-0005).
- **Cross-goroutine context** is the standout engineering: a runtime hook copies a goroutine-local
  storage (GLS) structure from parent to child on `go` statements, so spans parent correctly even
  when `context.Context` isn't threaded through (v0.4.0, inherited from Alibaba's SkyWalking-style
  design; tunable via `OTEL_GLS_MAX_SPANS`).
- Lineage: joint SIG of Alibaba (opentelemetry-go-auto-instrumentation → loongsuite-go-agent),
  Datadog (Orchestrion), and Quesma (instrgen); new codebase, not a fork.

---

## 2. Shortcomings of the eBPF approach — deep dive with evidence

### 2.1 The TLS question, validated in code

**Claim: "If TLS termination happens inside the process, context propagation is problematic." →
CONFIRMED, except for Go.**

*Capture* vs *injection* must be separated:

**Capture (reading plaintext) mostly works — via an ever-growing pile of per-stack hooks:**

| TLS stack | Capture mechanism | Evidence |
|---|---|---|
| OpenSSL/BoringSSL (`libssl.so`) | uprobes on `SSL_read/_ex`, `SSL_write/_ex/_ex2` — read-only | `pkg/internal/ebpf/generictracer/generictracer.go:355-385`, `bpf/generictracer/libssl.c` |
| Go `crypto/tls` | struct-offset unwrapping of `persistConn.tlsState` etc. | `bpf/gotracer/go_nethttp.c:273-284, 1466-1473` |
| .NET | uprobes on `CryptoNative_Ssl*` in the .NET OpenSSL wrapper | `generictracer.go:386-401` |
| Java (pure-Java JSSE — invisible to libssl) | a **Java agent that smuggles decrypted payloads to eBPF via `ioctl(0, 0x0b10b1, ptr)`**, caught by a `sys_ioctl` kprobe | `bpf/generictracer/java_tls.c:29-56,169-236`; security caveats in `devdocs/java-tls-ioctl-security.md` |
| Node.js | OpenSSL probes + an agent signalling fd ownership through fake `uv_fs_access("/dev/null/obi/…")` calls | `bpf/generictracer/nodejs.c:74-118` |
| **rustls, GnuTLS, NSS, mbedTLS, wolfSSL, statically-linked TLS** | **nothing** — no matching `.so`, no symbol fallback; zero hits for these names in `pkg/` | absence verified by search |

So even *capture* is a whitelist of reverse-engineered integrations; a Rust service using rustls, or
anything statically linking its TLS, is entirely dark.

**Injection (writing traceparent) into TLS traffic works only for Go:**

- The Go tracer writes the literal `"Traceparent: …\r\n"` into the app's plaintext `bufio.Writer`
  **before `crypto/tls` encrypts**, using `bpf_probe_write_user`
  (`bpf/gotracer/go_nethttp.c:809-915`, HTTP/2 at `:1313-1341`, gRPC at `bpf/gotracer/go_grpc.c:919-950`).
- For OpenSSL-based runtimes there is **no plaintext-rewrite path**: the `SSL_write` uprobe only
  records the buffer pointer and reads it on return (`libssl.c:151-195`). Growing the buffer to add
  a header from eBPF is not implemented (and is arguably not implementable safely — the caller owns
  that memory and its length).
- The kernel-side mechanism marks SSL connections invalid for header injection: the tracer stores
  `tp_info` with `valid=0`; tpinjector schedules a TCP option, then deletes the entry and skips HTTP
  injection (`bpf/tpinjector/tpinjector.c:856-886, 552`); HPACK injection explicitly "Skip[s] SSL
  sockets — payload is encrypted" (`tpinjector.c:833`). The design doc states it plainly:
  *"SSL/TLS uses TCP options, not HTTP headers: Can't inject into encrypted payload"*
  (`devdocs/context-propagation.md:293-297`).

**The fallback is proprietary and fragile:** TCP option kind 25 (an *unassigned* IANA codepoint,
`tpinjector.c:99-101`) carries only trace_id+span_id at L4. Only another OBI agent parses it
(`tpinjector.c:466-504`); any TLS-terminating proxy, L7 LB, NAT that rewrites segments, or non-OBI
receiver drops it on the floor. It also cannot express per-stream context on multiplexed HTTP/2
connections, so OBI disables it there — leaving **encrypted gRPC from non-Go apps with no
propagation whatsoever** (`SUPPORT_MATRIX.md:64-65`).

**Bottom line:** in a realistic polyglot mesh with TLS everywhere, OBI's distributed traces stay
stitched only along Go→anything edges (header injection pre-encryption) and OBI→OBI same-L4-path
edges (TCP option). Every other TLS edge fractures into disconnected trace fragments.

### 2.2 Context propagation is a stack of bounded heuristics

Each layer works inside an explicit, hardcoded window; step outside it and correlation silently breaks:

- **Traceparent scan windows.** Ingress/egress header discovery scans at most **4 KB** of an HTTP/1
  header block (`k_max_iter=4 × k_max_chunk_size=1024`, `tpinjector.c:1012-1013`) and at most
  **192 bytes** of an HPACK block across at most **4–6 HTTP/2 frames per packet**
  (`bpf/common/h2_defs.h:21-26` — the 6-frame cap is explicitly "Capped by the 33 tail-call
  budget"). A traceparent pushed past 4 KB by fat cookies/JWTs, or in a later frame, is missed —
  OBI then mints a *new* trace, and the graph silently splits.
- **Black-box parent search** links a client call to the server request that caused it by walking
  thread/goroutine hierarchies — capped at **3 levels** for Java thread nesting
  (`bpf/common/trace_parent.h:200-228`), ~3 goroutine levels for Go (`SUPPORT_MATRIX.md:144`),
  5 levels generic. Thread pools, work-stealing runtimes, and queue handoffs beyond the caps lose
  the parent.
- **15-second correlation epochs.** Cross-process correlation on the same host matches requests
  that fall in the same `NANOSECONDS_PER_EPOCH = 15s` bucket (`bpf/common/tracing.h:13,93-128`),
  deliberately skipping same-PID matches to dodge port-reuse false positives — a documented
  correctness-vs-false-positive trade. Unrelated concurrent transactions can be mis-linked.
- **The async admission.** OBI's own docs: *"OBI normally assumes that work running on the same
  thread belongs to the same logical request. That assumption breaks down for Python async
  workloads"* (`devdocs/python-asyncio-context-propagation.md:28-39`). The fixes are per-runtime:
  uvloop-only Python, Puma-only Ruby, a Node.js agent, Java virtual-thread mount tracking.
- **io_uring is not handled at all.** The only `io_uring` references in the tree are kernel type
  dumps and a test fixture. Servers doing socket I/O through io_uring bypass the
  `tcp_sendmsg/recvmsg` kprobes entirely → effectively uninstrumented. As io_uring adoption grows
  (high-performance proxies, runtimes), this is a widening blind spot.
- **Propagation is off by default** (`OTEL_EBPF_BPF_CONTEXT_PROPAGATION=disabled`), because turning
  it on means letting a kernel program rewrite live application traffic — which is itself telling.

### 2.3 Memory-layout coupling: the offsets treadmill

OBI's Go instrumentation depends on knowing the byte offset of fields inside other people's structs:

- A hand-maintained registry of ~60 struct-field paths (`net/http.Request.URL`,
  `runtime.hchan.sendx`, gRPC transport internals, gin/gorilla/pgx/mysql/mongo/sarama internals) in
  `pkg/internal/goexec/structmembers.go:159-535`, resolved from DWARF when present, else from a
  **1,498-line embedded `offsets.json`** generated by a per-library tracker toolchain
  (`configs/offsets/*`). Unknown version → the field is *silently skipped* at Debug log level
  (`structmembers.go:665`) → partial instrumentation with no operator-visible failure.
- Hardcoded library-version behavior gates (`grpcOneSixZero`, `http2ZeroFortyFive`,
  `mongoOneThirteenOne`, …) at `structmembers.go:27-33` — every upstream release can require a new gate.
- Stripped binaries force **per-architecture instruction disassembly** to find return sites
  (Go can't use uretprobes; `pkg/internal/goexec/instructions_{amd64,arm64}.go`); Go < 1.17 is
  rejected outright (`gofile.go:19-33`).
- Beyond Go: **nginx support is literal magic numbers** — `ngx_http_request_s.connection=0x8`,
  `.upstream=0x48`, … (`bpf/generictracer/nginx.c:21-26`), validated on exactly two nginx versions
  (`SUPPORT_MATRIX.md:102`).

This is the same class of maintenance treadmill otelc has with its rule version matrix (§3.4) —
but OBI's breaks at *runtime against binaries it has never seen*, while otelc's breaks at *build
time against dependencies you declared*.

### 2.4 The verifier tax

The eBPF verifier forces the code into shapes chosen for provability, not correctness of coverage:

- Tail-call budget arithmetic as a design input ("Capped by the 33 tail-call budget (≤5 hops per
  frame)", `h2_defs.h:23-24`); capture buffers capped at 256 B/1 KB (`bpf/common/http_buf_size.h`);
  protocol classification sees as little as 24 bytes.
- Comments narrate the fight: *"inlining under the 192-iter scan blows older verifiers"*
  (`tpinjector.c:1353`); *"Server finalize tail-called to stay under verifier insn limit on 5.15"*
  (`protocol_http2.h:236`); a hand-written `asm goto` register pin whose comment calls itself
  "this 'beauty'" (`tpinjector.c:627-647`); Huffman HPACK encoding avoided because `bpf_loop`
  would raise the kernel floor to 5.17 (`go_nethttp.c:1308`); a giant unrolled memcpy switch in
  `bpf_builtins.h`.
- The support surface (kernels 5.8→6.x, two ISAs, endian variants) is CI-validated on **two kernel
  versions** (5.15.152, 6.10.6 x86_64 + one arm64 runner, `SUPPORT_MATRIX.md:47-49`); verifier
  acceptance on untested kernels is a live regression risk the comments themselves acknowledge.

### 2.5 Protocol detection and capture-fidelity heuristics

- HTTP/1 detection is a 7-verb prefix match (`http_types.h:119-141`) — CONNECT, TRACE, WebDAV,
  and custom methods are invisible. Postgres detection requires a message to fit exactly in one
  captured segment (`protocol_postgres.h:110-168`): queries split across TCP segments are missed;
  coincidental binary payloads can false-positive.
- Anything established **before OBI attached** degrades: HTTP/2 preface never seen → connection
  never classified; gRPC methods report `*`; prepared-statement text missing; Redis DB unknown
  (`SUPPORT_MATRIX.md:65-75`).
- Payloads truncate at 64 KiB/direction; ringbuffer overflow drops events with no backpressure;
  the in-kernel PID filter caps ~3001 concurrently instrumented processes.
- Spans exist only at syscall/socket boundaries: no internal application spans (except captured Go
  manual spans), no exceptions/stack traces, no business attributes; sub-span timing is heuristic.

### 2.6 Sampling gaps

- Head sampling only, applied per-span in userspace at export (`tracesgen.go:99-107`). **Verified
  defect: `ShouldSample` receives a bare `context.Context`, never the remote parent SpanContext —
  so `parentbased_*` samplers (including the default) always take the root branch.** Upstream
  sampling decisions do not influence OBI. Only `traceidratio` behaves consistently (it hashes the
  propagated trace ID). No tail sampling, no `tracestate`, no baggage.
- eBPF always mints traces with sampled=1; incoming W3C flags are used only for exemplar gating
  (`pkg/export/prom/prom.go:985`).

### 2.7 Security and operational footprint

- Requires root or a bundle of high-trust capabilities — `CAP_BPF`, `CAP_PERFMON`,
  `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_SYS_PTRACE` (`pkg/internal/helpers/capabilities.go:16-58`,
  `SUPPORT_MATRIX.md:33`) — plus BTF-enabled kernels ≥ 5.8.
- **`bpf_probe_write_user` writes into the live memory of monitored processes.** The code's own
  comment: *"writing with bad offsets can crash the application, be defensive here"*
  (`go_nethttp.c:860`). Bounds are a `len & 0xffff` mask, not a proof; too-small buffers silently
  skip injection (inconsistent propagation); the helper taints the kernel and is unavailable under
  some lockdown configs. A stale `offsets.json` entry is a write to a wrong address in a foreign
  process. A compromised OBI agent is a write primitive into every instrumented process.
- The Java path accepts a user pointer + length over an `ioctl` side channel with narrow start/end
  checks (`java_tls.c:216-235`) — the repo's own security doc warns "Do not reuse this pattern
  blindly" (`devdocs/java-tls-ioctl-security.md`).

---

## 3. The compile-time approach — strengths and its own costs

### 3.1 What it gets structurally right

- **It is the real SDK.** W3C traceparent/tracestate/baggage via standard propagators; native
  `context.Context` flow; resource detection; exporters — all standard `OTEL_*` env config
  (docs/configuration.md). Nothing is reconstructed.
- **Parent-based sampling actually works** (in-process parent context), custom samplers can be
  compiled in, tail sampling composes normally at the collector — the exact gaps OBI has (§2.6).
- **Manual + auto spans interoperate**: developers call `otel.Tracer()` and their spans nest
  correctly with injected ones — categorically impossible for OBI, where SDK spans and eBPF spans
  are separate universes stitched heuristically.
- **Cross-goroutine correctness via GLS**: the runtime hook copies goroutine-local storage
  parent→child on spawn, so context survives `go func()` without ctx threading — solving in-process
  what OBI approximates with 3-level thread walks and 15-second epochs.
- **Contained failure modes**: trampolines catch hook panics; the worst rule mismatch yields a
  *non-instrumented* build, not a crashed process.
- **TLS is a non-issue**: instrumentation runs above the TLS layer by construction.

### 3.2 Maturity (the honest picture, July 2026)

- otelc: **v0.5.0 (2026-05-29), README: "not ready for production use"**, ~12 instrumented targets
  (net/http, database/sql, grpc, gin, go-redis v9, mongo, client-go, kafka-go, openai-go, logrus,
  stdlib log, SDK bootstrap + runtime/GLS), `go get` install broken (issue #665). Active SIG
  (Alibaba+Datadog+Quesma/Cabify, weekly meetings), v1.0 roadmap (#261) with 10/11 GA blockers done
  (vendoring support still open).
- Production-grade compile-time today = **loongsuite-go-agent v1.12.0, ~60 plugins** (gin/echo/
  fiber/hertz/kratos, gorm/sqlx/clickhouse/es, redis×3, kafka×3/rocketmq/rabbitmq, zap/logrus/
  zerolog/slog, large AI/LLM set) or Datadog Orchestrion.

### 3.3 Costs and shortcomings

1. **Go only.** Nothing for your Java/Python/Rust neighbors, databases, or third-party binaries.
2. **Adoption is per-service and invasive to CI**: every team switches to `otelc go build`
   (or GOFLAGS), commits a pin file, rebuilds, redeploys. Coverage grows team-by-team; you cannot
   instrument what you cannot rebuild. Changing *what* is instrumented requires a rebuild.
3. **Version-matrix treadmill, mirror-image of OBI's offsets**: rules carry explicit version
   ranges; an unmatched version is a **silent no-op** (you must inspect `.otelc-build/matched.json`
   to notice). Loongsuite's support table visibly caps versions below current releases (grpc
   ≤ v1.63.0 etc.); issues #644/#556 show the drift in the OTel repo. Hooks can even bump your
   dependency versions — a reproducibility hazard v0.5.0 now at least warns about.
4. **Build-time overhead**: Alibaba measured **~92.8% compile-time increase** (stdlib injection
   forces full rebuilds upstream); the OTel repo enforces a ≤150%-overhead CI ceiling and added
   incremental builds in v0.3.0. Real, budgeted, nonzero.
5. **Runtime overhead is small but not zero** ("zero overhead" marketing means "no separate
   agent"): trampolines + GLS bookkeeping on every goroutine spawn + the SDK itself. Alibaba's
   published figures: ~5% CPU, <1 ms latency. The OTel repo hasn't formalized its own SLO yet (#570).
6. **Build-system compatibility edges**: vendoring is an open GA blocker; `go.work` had bugs on
   the blocker list; Bazel/goma-style drivers that bypass `cmd/go` are effectively unsupported
   (toolexec is a `cmd/go` feature).
7. **Supply-chain surface**: the otelc binary, every hook package, and every rule file are
   code-execution-equivalent inside your build; `OTELC_RULES` env replaces (not merges) all other
   rule sources — a stray env var in shared CI silently disables or redirects instrumentation.
   Mitigation is auditability (pins in source control, `matched.json`), not sandboxing.
8. **Debugging oddities**: trampolines and `//go:linkname` in stack traces; what actually compiled
   lives in `.otelc-build/`; generics have restricted hook APIs.

---

## 4. Head-to-head

| Dimension | OBI (eBPF) | otelc / loongsuite (compile-time) |
|---|---|---|
| **Languages** | Any (Go best; Java/Python/Node/Ruby/.NET via per-runtime hacks; Rust/rustls dark) | Go only |
| **Adoption unit** | One DaemonSet per node; zero app changes | Every service's build pipeline; rebuild + redeploy |
| **Works on binaries you can't rebuild** | Yes (its raison d'être) | No |
| **Span origin** | Reconstructed at syscall/socket boundary | Real SDK spans inside the app |
| **Internal spans, errors, business attrs** | No (except captured Go manual spans) | Yes — full SDK, manual interop |
| **Context propagation** | 4-layer heuristic; **off by default**; bounded scan windows (4 KB / 192 B / 6 frames); 15 s epochs; ≤3-level thread walks | Native ctx + GLS across goroutines; standard propagators; baggage |
| **TLS (in-process termination)** | Capture: OpenSSL/Go/.NET/Java-agent only. **Injection: Go only**; others → proprietary TCP opt 25 (OBI-to-OBI, proxy-stripped); non-Go gRPC/TLS: none | Non-issue (above TLS layer) |
| **Sampling** | Head-only at export; **parent-based effectively broken** (bare ctx to `ShouldSample`); no tracestate/baggage | Full SDK sampling incl. correct parent-based, custom samplers |
| **Async / io_uring** | Per-runtime special cases; **io_uring unsupported** | Whatever the app does — hooks run in-process |
| **Runtime overhead** | Low per-request; kprobes on every TCP send/recv node-wide; ringbuffer drops under load | ~5% CPU, <1 ms (Alibaba figures); no separate agent |
| **Build overhead** | None | ~92.8% (Alibaba) / ≤150% CI ceiling (otelc) |
| **Privileges** | Root or CAP_SYS_ADMIN/BPF/NET_ADMIN/PERFMON/SYS_PTRACE; BTF kernels ≥5.8; writes into target process memory | None at runtime; build-time supply-chain trust instead |
| **Maintenance treadmill** | offsets.json + version gates + protocol parsers + verifier/kernel matrix; breaks at runtime vs unseen binaries | Rule/version matrix per library; breaks at build time vs declared deps |
| **Worst failure mode** | Silently wrong/missing/mis-linked telemetry; process crash via bad `bpf_probe_write_user` offset | Silent non-instrumentation; build breakage |
| **Failure visibility** | Debug-level logs, degraded traces | `matched.json`, build output (still too quiet) |
| **Maturity (07/2026)** | Production (Beyla lineage, vendor-adopted) | otelc v0.5.0 pre-prod; loongsuite v1.12.0 production |

## 5. Interpretation and recommendation

**These are complements, not competitors** — the founding OTel/CNCF blog says as much, and the
architectures confirm it:

- **OBI's irreducible value** is the first 80%: instant, fleet-wide, language-agnostic RED metrics
  and coarse traces over services nobody will ever rebuild — legacy binaries, third-party
  containers, polyglot sprawl. Nothing else does this.
- **OBI's irreducible ceiling** is that it reconstructs semantics it cannot see. Every finding in
  §2 is a consequence of one root cause: *the process does not cooperate*. Header scan windows,
  offset registries, epoch heuristics, TCP option 25, the `valid=0` SSL dance, io_uring blindness —
  each is a workaround for missing cooperation, each with a boundary that fails silently. Adding
  more per-runtime hacks moves the boundary; it never removes it.
- **Compile-time instrumentation is what "cooperation" looks like** with near-zero developer
  effort. For Go services you own, it delivers the things OBI structurally cannot: correct
  propagation through TLS/proxies/goroutines, working parent-based and tail sampling, baggage,
  manual-span nesting, internal spans, exceptions. Its costs (rebuilds, rule drift, compile time,
  build-trust) are organizational, not epistemic — you pay in process, not in correctness.

**Practical guidance:**

1. Run OBI fleet-wide for coverage: network/RED metrics, service graph, traces for
   non-rebuildable and non-Go workloads. Treat its cross-service traces over TLS as best-effort
   unless every hop is Go or every host runs OBI with TCP options surviving the path.
2. For Go services you actively develop, adopt compile-time instrumentation for trace quality —
   today that pragmatically means loongsuite-go-agent (or Orchestrion) with an eye on otelc as the
   convergence point; migrate when it reaches v1.0/GA and its library matrix covers your stack.
3. Where both run, dedupe: suppress OBI's app-level spans for compile-time-instrumented processes
   (OBI already has SDK-detection machinery for this — `devdocs/exclude-otel-instrumented-services.md`)
   and keep OBI's network-level signals.
4. If you must rely on OBI's distributed tracing, budget for its sharp edges explicitly: enable
   `context_propagation`, keep header blocks under the 4 KB scan window on hot paths, don't expect
   parent-based sampling semantics, and monitor for trace fragmentation at every TLS/non-Go/proxy edge.

---

## Appendix: key evidence index

OBI (this repo): `bpf/tpinjector/tpinjector.c` (valid=0 SSL path :856-886; TCP opt 25 :99-101,428-504;
4 KB scan :1012; asm-goto :627), `bpf/gotracer/go_nethttp.c` (pre-TLS injection :809-915; crash
comment :860), `bpf/generictracer/libssl.c` (capture-only), `bpf/generictracer/java_tls.c` (ioctl
channel), `bpf/generictracer/nginx.c:21-26` (magic offsets), `bpf/common/tracing.h:13` (15 s epochs),
`bpf/common/trace_parent.h:200-228` (3-level walk), `bpf/common/h2_defs.h:21-26` (scan caps),
`pkg/internal/goexec/structmembers.go` + `offsets.json` (offset registry),
`pkg/export/otel/tracesgen/tracesgen.go:99-107` (sampler defect), `SUPPORT_MATRIX.md`,
`devdocs/context-propagation.md`, `devdocs/grpc-context-propagation.md`,
`devdocs/python-asyncio-context-propagation.md`, `devdocs/java-tls-ioctl-security.md`.

otelc: github.com/open-telemetry/opentelemetry-go-compile-instrumentation — docs/implementation.md,
docs/rules.md, docs/configuration.md, docs/benchmarking.md, ADR-0004/0005, issues #261 (GA
roadmap), #665 (go get broken), #570 (overhead SLO), #644/#556 (version drift); OTel blog
"go-compile-time-instrumentation" (2025); alibaba/loongsuite-go-agent (supported-libraries.md,
compilation-time.md, context-propagation.md); OTel community issue #2344 (donation, overhead figures).

---

## 6. Addendum: adversarial review — corrections and blind spots (2026-07-10)

After the report above was written, a 5-lens adversarial review (OBI code re-sweep, otelc
red-team, ecosystem sweep, hostile re-read of this report, first-principles dimension analysis)
produced 44 raw findings; 12 were selected and independently verified by refutation-oriented
skeptics. **11 confirmed, 1 plausible, 0 refuted.** They correct this report in several places.
Context updates: otelc is about to cut v1.0, and Datadog's Orchestrion has proven the toolexec
model in production — the maturity framing below supersedes §0/§4.

### 6.1 Corrections to this report

1. **"OBI is production" is wrong for this repo.** OBI's own `README.md:12` says *"OBI is
   currently in Development… expect breaking changes between minor releases while the project
   remains in v0"*; `VERSIONING.md`: "All current OBI user-facing surfaces are unstable by
   default"; latest release v0.10.0 (2026-06-30), GA targeted late 2026. The honest framing is
   **symmetric**: both OTel repos are pre-GA v0.x donations from production-proven lineages
   (Grafana Beyla ↔ loongsuite-go-agent/Orchestrion).
2. **The headline "TLS injection works for exactly one runtime: Go" has an unstated
   precondition**: `SupportsContextPropagationWithProbe()` requires **CAP_SYS_ADMIN and kernel
   `lockdown=none`** (`pkg/ebpf/common/common.go:516-540`; unreadable lockdown file → treated as
   integrity). Secure-Boot distros default to `lockdown=integrity`, so on such fleets
   `bpf_probe_write_user` paths early-return and **no runtime gets TLS header injection** — Go
   degrades to TCP option 25 like everyone else.
3. **"Manual + auto span interop categorically impossible for OBI" is overstated.** OBI uprobes
   the OTel *API* (`global.(*tracer).Start`, `nonRecordingSpan.End/SetStatus/SetAttributes/
   RecordError`, and `go.opentelemetry.io/auto/sdk`) for Go apps with no SDK installed
   (`bpf/gotracer/go_sdk.c`, `gotracer.go:660-697`): manual spans nest bidirectionally with eBPF
   spans, with attributes, status, and errors. Caveats: only within an eBPF-tracked request
   (standalone root manual spans are dropped), bounded fidelity, and a delegate check skips apps
   that installed a real SDK.
4. **The §4 row "Internal spans, errors, business attrs: No" is materially misleading.** OBI
   synthesizes "in queue"/"processing" sub-spans and extracts application-semantic attributes
   from payloads — including a full **GenAI layer** (OpenAI/Anthropic/Gemini/Qwen/Bedrock spans
   with token usage incl. cache/reasoning tokens, tool calls, opt-in prompt/response capture —
   `tracesgen.go:603-1005`), MCP/JSON-RPC, and opt-in header/body attributes. Developer-defined
   in-code attributes remain impossible for non-Go.
5. **This report judged a multi-signal system on the traces axis only.** Missing entirely:
   GPU/CUDA kernel-launch telemetry (`bpf/gpuevent/`), netolly flow metrics and statsolly
   kernel-truth TCP stats (SRTT/retransmits — signals that survive even when L7 parsing fails, so
   "entirely dark" for unsupported TLS stacks is true only at L7), **trace-log correlation**
   (logenricher writes trace IDs into app log buffers via `bpf_probe_write_user` — also widening
   §2.7's write-primitive surface beyond Go), and **trace-profile correlation** (pinned
   `traces_ctx_v1` map). For LLM-heavy shops, zero-code GenAI spans from Python services
   materially shift the complement-vs-competitor calculus.

### 6.2 Missed comparison dimensions

6. **Messaging context propagation — arguably a bigger practical gap than TLS.** OBI cannot
   propagate through Kafka/MQTT/AMQP at all (`SUPPORT_MATRIX.md:73-75`: Context propagation = No;
   `go_kafka_go.c` tracks traceparents in maps only, never writes message headers; TCP option 25
   is per-connection and dies at the broker). Producer→consumer traces **always** fragment in
   event-driven architectures. Compile-time injects W3C context into message headers via SDK
   propagators (otelc kafka-go hooks; loongsuite: 4× Kafka, RocketMQ, RabbitMQ, MQTT).
7. **Platform classes where eBPF is impossible and compile-time is trivial** (plausible,
   evidence-backed): Fargate/Lambda/Cloud Run (eBPF-disabled environments), Windows containers,
   macOS dev. GKE Autopilot is nuanced: privileged DaemonSets are allowlist-gated and Beyla is
   allowlisted, but the vendor-neutral OBI image is not (yet). §5's "run OBI fleet-wide" is not
   executable on these platforms.

### 6.3 Unknown unknowns on the compile-time side (pre-v1.0 relevance)

8. **GLS mis-parents across requests via pooled goroutine workers — same failure class as eBPF
   thread reuse, undocumented.** GLS copies parent→child only in `runtime.newproc1`
   (`instrumentation/runtime/otelc.yaml`). A pool worker lazily spawned under request A's span
   keeps A's span in its GLS clone forever (span End only cleans the ending goroutine's GLS;
   `ClearTraceContext` has zero callers). Every later task on that worker that starts a span from
   `context.Background()` gets A as parent via `afterSpanFromContext` (`trace/hook.go:15-22`) —
   **cross-request contamination (wrong link), worse than OBI's missing link**, plus the
   recordingSpan pinned in memory for the worker's lifetime. Loongsuite's dedicated `goants-v2`
   plugin is the admission that spawn-time copy doesn't cover pools; otelc has no pool rule and
   no doc. The §3.1 claim that GLS "solves" what OBI approximates is too strong: **any approach
   that infers causality from execution-unit identity inherits the reuse failure class** —
   threads for eBPF, pooled goroutines for GLS.
9. **The GLS fallback rewrites `trace.SpanFromContext` semantics program-wide.** Intentional
   root spans (`tracer.Start(context.Background(), …)`) inside any goroutine with non-empty GLS
   silently become children of the ambient span; no runtime opt-out is documented
   (`OTEL_GO_DISABLED_INSTRUMENTATIONS` doesn't gate the GLS hooks; `//otelc:ignore` is only
   planned, #469; `trace.WithNewRoot()` works but isn't documented as the escape). Above
   `OTEL_GLS_MAX_SPANS` (default 1000), `add()` fails **silently** (no log/metric), `tail()`
   returns a wrong-but-valid parent, and `End()` still pays an O(n) linked-list walk — a hidden
   CPU cliff precisely under overload. Neither overflow nor re-parenting semantics are in
   `docs/configuration.md`.
10. **otelc doesn't fingerprint itself into Go's build cache.** Go derives compile-action cache
    keys from the toolexec wrapper's `-V=full` output; Orchestrion intercepts it
    (`internal/toolexec/version.go`) to invalidate caches when tooling/config changes. otelc has
    no `-V` handling; its substitute (private GOCACHE at `.otelc-build/gocache`) is bypassed
    whenever the user sets GOCACHE (`setup.go:415-433` "respect it") — common in Docker cache
    mounts and CI. Then `go build` and `otelc go build` share identical action IDs: plain builds
    can link instrumented runtime objects and instrumented builds can silently reuse
    uninstrumented packages; rule edits and otelc upgrades never invalidate anything. **The
    classic production toolexec bug, already solved upstream in Orchestrion.**
11. **"Vendoring support" (PR #616, merged 2026-07-09) silently builds with `-mod=mod`**,
    rewriting explicit `-mod=vendor`, resolving from the network module cache while `vendor/` is
    left untouched — announced by one info-level log line. Hermetic/air-gapped vendored builds
    stop being hermetic, and compiled dependency code can diverge from the audited `vendor/`
    tree (local patches). This ships at GA as-is.
12. **No machine-checkable "expected instrumentation present" gate exists or is on the v1.0
    roadmap** — `match.go` warns only when *zero* rules match; a Renovate bump past one rule's
    version ceiling shrinks `matched.json` silently and spans vanish with nothing to bisect. The
    v1.0 CLI/env freeze (#261) makes fail-by-default a breaking change later; an additive
    `verify`/`doctor` command remains possible but shipping 1.0 without one cements silent
    degradation as the frozen default.

### 6.4 Interop: what actually happens when both run

13. **OBI suppresses ALL its telemetry for SDK-exporting services BY DEFAULT** —
    `exclude_otel_instrumented_services` defaults to **true** (`pkg/obi/config.go:304`), so §5's
    recommendation 3 ("suppress… " as if opt-in) had it backwards. Detection is *behavioral*:
    first observed successful OTLP export flips the service (`span.go:1873`), which means
    (a) duplicate telemetry until first successful export — forever for short-lived jobs or
    failing exporters; (b) suppression is all-or-nothing per signal: one traces export silences
    OBI's SQL/Redis/Kafka/DNS spans that otelc's ~12-library rule set does not cover — **adopting
    otelc on a service can net-reduce its observability** unless the flag is tuned;
    (c) false-positive path: any successful gRPC call to port 4317 can flag a service;
    (d) false-negative path: exporters on pre-OBI connections to code-configured ports duplicate
    permanently. Span-metrics suppression is a separate default-false flag; detection events are
    visible in the `obi_avoided_services` internal metric.

### 6.5 The structural insight

The strongest pattern across all findings: **every zero-effort context-propagation mechanism is a
heuristic keyed on execution-unit identity, and every one of them fails when execution units are
reused.** eBPF fails at thread/epoch granularity (missing links); GLS fails at pooled-goroutine
granularity (wrong links — contamination). The only non-heuristic propagation is explicit
`context.Context` threading — the very thing auto-instrumentation exists to avoid. The two
approaches don't differ in *whether* they approximate causality, only in how often the
approximation breaks, and whether it breaks by fragmenting a trace or by corrupting one.
Fragmentation is visible; contamination is not — which is an argument for otelc to invest in
pool-aware rules and GLS diagnostics before broad adoption, and for OBI to keep its
wrong-link-avoidance bias (skip same-PID matches) even at the cost of more missing links.
