**PRODUCTION IMPLEMENTATION EXECUTION SPECIFICATION**

**CIGAR**

**Composable Intelligence Graph Agent Runtime**

*Production implementation and release execution specification for Codex*

**Document status:** Execution-ready

**Version:** 1.0

**Date:** July 10, 2026

**Product stage:** Production v1 implementation and open-source release

**Release license:** Apache License 2.0

**NORTH STAR**  Build, verify, demonstrate, package, and release a production-quality portable context and effect kernel whose canonical behavior is identical across models, agents, tools, SDKs, and workflow runtimes.

**Primary audience**  
Codex coding agents, systems engineers, compiler engineers, storage engineers, SDK maintainers, integration engineers, test engineers, and release engineers

# **Document control**

| Field | Value |
| :---- | :---- |
| Deliverable | Production-ready CIGAR v1.0.0 open-source protocol and reference implementation |
| Source product definition | CIGAR Context Kernel Product Requirements Document v0.2 |
| Execution authority | This document fixes implementation choices and release gates for v1 |
| Implementation language | Rust 2024 edition for the semantic core and binaries |
| SDK languages | Rust, TypeScript, Python, and Go |
| Reference integration | Claude Code user-scoped plugin using documented MCP and hook surfaces |
| Persistence profiles | SQLite local profile; PostgreSQL-compatible shared profile; encrypted content-addressed blobs |
| Transport profiles | Embedded Rust API, HTTP/JSON, gRPC, SSE, stdio MCP |
| Packaging | Native binaries and installers, container images, Rust crates, npm, PyPI, Go module, Claude plugin bundle |
| License artifact | Apache License 2.0 with required NOTICE and third-party attribution files |
| Explicit exclusion | Project governance, community governance, committee design, and organizational process |

## **Requirement language**

MUST, MUST NOT, SHALL, SHALL NOT, SHOULD, SHOULD NOT, MAY, and OPTIONAL are normative. A work packet is complete only when its code, tests, demo, documentation, and exit gate all pass. A release gate cannot be waived by marking a test ignored, adding a retry, reducing an assertion, or documenting a known failure.

## **Source-of-truth precedence**

When implementation documents conflict, use this order:

1. Security, authorization, lane-separation, immutability, and intent-before-dispatch invariants in this specification.  
2. Canonical schemas and published v1 test vectors in the repository.  
3. This execution specification.  
4. The CIGAR Context Kernel PRD v0.2.  
5. Adapter documentation and examples.

Any unresolved contradiction SHALL block the dependent work packet and be recorded in IMPLEMENTATION\_STATUS.md with a minimal reproduction, affected contract, and proposed resolution. Codex SHALL not invent a silent compatibility behavior.

## **Definition of production-ready**

Production-ready means all of the following are true:

* The complete local workflow runs offline from installation through catalog, compile, handoff, effect reconciliation, and replay.  
* The shared-service profile provides authenticated multi-user access, transactional durability, tenant isolation, migrations, backup and restore procedures, metrics, health checks, and bounded resource behavior.  
* The semantic protocol has frozen v1 schemas, deterministic canonicalization, cross-language test vectors, compatibility tests, and stable public errors.  
* The compiler never bypasses scope, purpose, temporal, trust, instruction-authority, processor, or integrity gates.  
* Every selected catalog-derived block has provenance; every mediated mutation has durable intent, authorization, attempt, and receipt or explicit unknown state.  
* Rust, TypeScript, Python, and Go clients pass the same contract tests.  
* The Claude Code reference adapter installs, operates, degrades safely, and uninstalls without requiring private provider files.  
* All required demos run deterministically without paid model access; optional live demos run when credentials are supplied.  
* Unit, property, integration, end-to-end, fuzz, security, migration, fault-injection, performance, compatibility, and packaging gates pass.  
* Release artifacts are signed, checksummed, include SBOMs and provenance, and install successfully on the supported operating-system matrix.  
* There are no placeholder implementations, panic-on-user-input paths, untracked TODO items, skipped release tests, or known critical or high-severity security defects.

# **Table of contents**

*Interactive section index*

[**1\. Execution mandate**](#bookmark=id.zgjwrjqw6cz4)

[1.1 How Codex SHALL execute this specification](#bookmark=id.vmkkgslpjl14)

[1.2 Coding rules](#bookmark=id.onwrixc64we5)

[1.3 Product outcome to preserve](#bookmark=id.n73eku214jwf)

[1.4 Fixed v1 scope](#bookmark=id.85nnzwq556tv)

[1.5 Non-goals for implementation](#bookmark=id.1nkg0nnqeohn)

[**2\. Fixed architecture and technical decisions**](#bookmark=id.f70c8l2od45a)

[2.1 System architecture](#bookmark=id.r0vh03vw43ti)

[2.2 Fixed technology choices](#bookmark=id.iqnm5go8qsd9)

[2.3 Dependency direction](#bookmark=id.1ysm0bmu87n1)

[2.4 Feature policy](#bookmark=id.vxblfdbtok1v)

[2.5 Compatibility policy implemented in code](#bookmark=id.fn7ji9m3xztx)

[2.6 Supported release profiles](#bookmark=id.9r9ljn37yqyn)

[**3\. Repository and build layout**](#bookmark=id.aqm9lxl41azz)

[3.1 Monorepo tree](#bookmark=id.2towdlnrofka)

[3.2 Workspace package rules](#bookmark=id.to6lee79i6bk)

[3.3 Authoritative commands](#bookmark=id.ywwu4wnex75x)

[3.4 Bootstrap behavior](#bookmark=id.rpy1d22a3zw)

[3.5 Configuration layout](#bookmark=id.rbspe1dbu2th)

[**4\. Protocol types, schemas, and canonicalization**](#bookmark=id.hrwatoo31r20)

[4.1 Protocol crate responsibilities](#bookmark=id.ylluuaokwhf9)

[4.2 Schema rules](#bookmark=id.uuvimx7cetpw)

[4.3 Core atom schema](#bookmark=id.i7sksrudmncd)

[4.4 Context contract schema](#bookmark=id.agqtgulkw3hf)

[4.5 Stable error model](#bookmark=id.owxd3qva7gop)

[4.6 Deterministic CBOR profile](#bookmark=id.y6dp2j86iy0b)

[4.7 Digest domains](#bookmark=id.n5pon06k1ag)

[4.8 Identity generation](#bookmark=id.x8cglangm1e)

[4.9 Cross-language golden vectors](#bookmark=id.khvynthpsk1)

[**5\. Cryptography and secret-safe handling**](#bookmark=id.2by7tm37oftq)

[5.1 Key provider abstraction](#bookmark=id.fqto85k0wk2n)

[5.2 Blob encryption](#bookmark=id.ksifr6gvalm7)

[5.3 Signatures](#bookmark=id.wxfxi738kmc3)

[5.4 Secret types](#bookmark=id.pdsun8n2m69k)

[**6\. Persistence and transactional model**](#bookmark=id.en1gkzd6ymwu)

[6.1 Store interfaces](#bookmark=id.jujdraf2u9pe)

[6.2 Logical tables](#bookmark=id.ndqk9m3wwx1x)

[6.3 SQLite profile](#bookmark=id.ts2rwc8zndfg)

[6.4 PostgreSQL profile](#bookmark=id.d8fdxfyldcvr)

[6.5 Migration system](#bookmark=id.jppm1pmdvu4b)

[6.6 Backup and restore](#bookmark=id.1qai21xc6d2e)

[6.7 Retention and garbage collection](#bookmark=id.f3thuoicyhv5)

[**7\. Catalog ingestion and code intelligence**](#bookmark=id.rx9uc8e0fsrx)

[7.1 Source connector contract](#bookmark=id.q7zd8k6l1yfn)

[7.2 Filesystem and Git connector](#bookmark=id.ldbbgh4ord1p)

[7.3 Atomic ingestion pipeline](#bookmark=id.3rqxdm6gc71y)

[7.4 Atomizers](#bookmark=id.dry0kptiv2n1)

[7.5 Tree-sitter code intelligence](#bookmark=id.arsg7kky5ayl)

[7.6 Secret and sensitive-content scanning](#bookmark=id.pyqegndpkwu5)

[7.7 Invalidation graph](#bookmark=id.nrxnukwmd7m)

[**8\. Policy, capability, and instruction enforcement**](#bookmark=id.8ytx9w3tyef)

[8.1 Non-bypassable hard gates](#bookmark=id.vayqllpp89sd)

[8.2 Policy interface](#bookmark=id.6yan4oxvwsi)

[8.3 Declarative v1 profile](#bookmark=id.k1xj1hcyzhar)

[8.4 Capability grants](#bookmark=id.pwz6w4tqyipr)

[8.5 Instruction authority](#bookmark=id.44gp3xyg0jma)

[8.6 Redaction and denied existence](#bookmark=id.forgrnmbhyrd)

[8.7 Required policy properties](#bookmark=id.wvno7vi0ey4j)

[**9\. Indexes and retrieval**](#bookmark=id.wqfptqdr5b80)

[9.1 Index families](#bookmark=id.vt56kcmexswh)

[9.2 Index update protocol](#bookmark=id.5a6pn4gtidua)

[9.3 Retrieval interface](#bookmark=id.fx3z7jl90lf4)

[9.4 Query planning](#bookmark=id.mdg2kqmg57tb)

[9.5 Consistency](#bookmark=id.yvh6ytb77xay)

[9.6 Candidate features](#bookmark=id.uy579zfxex1j)

[9.7 Vector adapter constraints](#bookmark=id.9b9bh6f7zbap)

[**10\. Context planner and compiler**](#bookmark=id.xmyegcmpytyw)

[10.1 Public interface](#bookmark=id.tt6yog55sjf)

[10.2 Deterministic compilation path](#bookmark=id.8e3nu4azx4cz)

[10.3 Standard lanes](#bookmark=id.qk4ccsldagl7)

[10.4 Budget arithmetic](#bookmark=id.wn7lsfg4lg20)

[10.5 Packing algorithm](#bookmark=id.6qgxy5hpjkr8)

[10.6 Conflict handling](#bookmark=id.qmez3ltc6qfq)

[10.7 Representation transforms](#bookmark=id.p9o625fj7z8w)

[10.8 Manifest](#bookmark=id.xvzy3fngtuqf)

[**11\. Materialization, caching, deltas, and token accounting**](#bookmark=id.wm0hosq0dsl1)

[11.1 Materializer contract](#bookmark=id.u4hlaoi9hbpn)

[11.2 Provider-present set](#bookmark=id.dpdet3covgnd)

[11.3 Cache layers](#bookmark=id.w2ymwh6hskfk)

[11.4 Delta compilation](#bookmark=id.i289sdskvwrz)

[11.5 Token accounting](#bookmark=id.joq04ylunsqv)

[**12\. Context spaces and handoff protocol**](#bookmark=id.lwcgsqwr0b5r)

[12.1 Context hierarchy](#bookmark=id.z57g8lhae0tu)

[12.2 Overlays and merge](#bookmark=id.joosplxo6u0x)

[12.3 Multi-project federation](#bookmark=id.izw29llkd21g)

[12.4 Handoff creation](#bookmark=id.u5f7k54z2mrj)

[12.5 Acceptance](#bookmark=id.d8451suvhh9)

[12.6 Child result](#bookmark=id.g0980by6hx6j)

[12.7 Coordination events](#bookmark=id.lw6nuztynrv2)

[**13\. Effect journal, connectors, and replay**](#bookmark=id.rn1d4ojghh0l)

[13.1 Effect states](#bookmark=id.he6jx3ayejrr)

[13.2 Effect intent and approval](#bookmark=id.gjvw0jm5zuy9)

[13.3 Connector interface](#bookmark=id.1zm7rgq42weg)

[13.4 Dispatch algorithm](#bookmark=id.rl1iaioroizf)

[13.5 Reference connectors](#bookmark=id.p2jbyyd6rv0f)

[13.6 Decision records](#bookmark=id.42u3d756545i)

[13.7 Replay modes](#bookmark=id.47zag2jdx3zz)

[**14\. Daemon, APIs, authentication, and operations**](#bookmark=id.gcbti2d7n2qk)

[14.1 Runtime composition](#bookmark=id.rbrw87oa9vl7)

[14.2 Local authentication](#bookmark=id.t6bxtt2mi2mx)

[14.3 Shared authentication](#bookmark=id.r57jv7ludfjq)

[14.4 HTTP and gRPC conventions](#bookmark=id.amshkv6jjqp)

[14.5 Required routes](#bookmark=id.6cttsul9m16w)

[14.6 Health and readiness](#bookmark=id.403j60zer515)

[14.7 Graceful shutdown and recovery](#bookmark=id.he2lqk6mqo10)

[14.8 Resource controls](#bookmark=id.3lgwoxj89j0s)

[14.9 Extension host and stable extension boundary](#bookmark=id.isgdsogv4kvb)

[**15\. CLI and SDK implementation**](#bookmark=id.tcurjr8li7q3)

[15.1 CLI surface](#bookmark=id.mib4zmz0o2e2)

[15.2 CLI UX requirements](#bookmark=id.kt1em9pa5mvc)

[15.3 Rust SDK](#bookmark=id.ajfsbepnfnju)

[15.4 TypeScript SDK](#bookmark=id.2qociirfy95g)

[15.5 Python SDK](#bookmark=id.oindhdn53yxv)

[15.6 Go SDK](#bookmark=id.8cpa0dt4canx)

[15.7 SDK parity](#bookmark=id.vbxojep408mt)

[**16\. Claude Code reference adapter**](#bookmark=id.y65uux7yu9zx)

[16.1 Packaging](#bookmark=id.fcvkvq28mi3u)

[16.2 Installation](#bookmark=id.7m8pwd3moc89)

[16.3 MCP surface](#bookmark=id.bozy1bkvjfjk)

[16.4 Hook executable](#bookmark=id.8yx54d2enn7q)

[16.5 Token behavior](#bookmark=id.vwftl5365sm9)

[16.6 Adapter limitations presented to users](#bookmark=id.44zt5f75x83h)

[16.7 Claude adapter acceptance](#bookmark=id.ea7fkfo42ubh)

[**17\. Product demos and executable examples**](#bookmark=id.jmd0tkv3d6w3)

[17.1 Demo 1: offline context compiler](#bookmark=id.j5x7dm49hwi3)

[17.2 Demo 2: multi-project isolation and focus switching](#bookmark=id.o5gx9hpsoone)

[17.3 Demo 3: multi-agent handoff](#bookmark=id.xi1si1vvs3w)

[17.4 Demo 4: effect crash recovery](#bookmark=id.nolm4ohn9kgf)

[17.5 Demo 5: cross-runtime replay](#bookmark=id.2yubdti30uzs)

[17.6 Demo 6: prompt-injection defense](#bookmark=id.jopnblyecs1k)

[17.7 Demo 7: Claude Code experience](#bookmark=id.ogdqm1wi90fz)

[17.8 SDK quickstarts](#bookmark=id.5whw4i6l36ku)

[**18\. Verification architecture and testability**](#bookmark=id.w8ou5kib0pvw)

[18.1 Release claims require executable evidence](#bookmark=id.poqns5n2he1h)

[18.2 Required testability interfaces](#bookmark=id.yb3jwa5d88kh)

[18.3 Verification repository](#bookmark=id.dphlezfb31an)

[18.4 Fixture manifest](#bookmark=id.yuds0nsbxaot)

[18.5 Synthetic corpus requirements](#bookmark=id.g2da2wdbicbx)

[18.6 Test command inventory](#bookmark=id.xuebzahetl9i)

[**19\. Component and invariant verification**](#bookmark=id.cee220r69nsp)

[19.1 ABI and canonicalization](#bookmark=id.nrd1akq6jubk)

[19.2 Catalog, provenance, temporal truth, and invalidation](#bookmark=id.uy56tqmjeuvm)

[19.3 Policy and isolation](#bookmark=id.eumc0u48rl3e)

[19.4 Planner, retrieval, compiler, and explanation](#bookmark=id.cfrww5h1zncs)

[19.5 Materializers and tokenizers](#bookmark=id.xyj62j8b8787)

[19.6 Context spaces and handoffs](#bookmark=id.jrz1zaprjzil)

[19.7 Effect crash matrix](#bookmark=id.4euxp4azylao)

[19.8 Replay](#bookmark=id.6ppxs12zcfni)

[19.9 Storage and APIs](#bookmark=id.vg7witudeh2w)

[19.10 CLI, SDK, and Claude adapter](#bookmark=id.pt0logg8jsjf)

[**20\. Conformance kit**](#bookmark=id.b8q5trubopp9)

[20.1 Profiles](#bookmark=id.ae0ufxgq1odi)

[20.2 Runner](#bookmark=id.9fexyrtn9bmp)

[20.3 Compatibility matrix](#bookmark=id.wcgrarqghsv5)

[**21\. Fuzzing, security, concurrency, and chaos**](#bookmark=id.ykynnqcxoswg)

[21.1 Fuzz targets](#bookmark=id.7juihkrd3nph)

[21.2 Property testing and model checking](#bookmark=id.xkz7gtey6mol)

[21.3 Static and supply-chain checks](#bookmark=id.7ied5qwdynrl)

[21.4 Dynamic adversarial families](#bookmark=id.qibyeefd0u8t)

[21.5 Chaos program](#bookmark=id.8hieoj7abkcb)

[**22\. Performance, scale, and outcome qualification**](#bookmark=id.7j3pufcfvzgj)

[22.1 Measurement discipline](#bookmark=id.iayhhtt7kmf)

[22.2 v1 performance gates](#bookmark=id.qyw0bdg7gjph)

[22.3 Load matrix](#bookmark=id.423mm3181xf8)

[22.4 CIGARBench harness](#bookmark=id.3np4ltqzlneb)

[22.5 Outcome gates](#bookmark=id.9na3bua17wb9)

[**23\. Observability and production operations**](#bookmark=id.oyrjetosi1pb)

[23.1 Trace tree](#bookmark=id.38ccl6iyb0c)

[23.2 Metrics](#bookmark=id.oosdyugyuxyc)

[23.3 Logging](#bookmark=id.otmunvea1tn9)

[23.4 Operational commands](#bookmark=id.vlqf7z119j1r)

[23.5 Service operations documentation](#bookmark=id.t0t5yujdtmod)

[**24\. CI, packaging, and release engineering**](#bookmark=id.nibj37eaaogd)

[24.1 Pull-request pipeline](#bookmark=id.j08gjz3egwg7)

[24.2 Merge pipeline](#bookmark=id.773oy7b66sdz)

[24.3 Nightly and weekly](#bookmark=id.s29wm9otcyka)

[24.4 Artifact matrix](#bookmark=id.n8rtvpb4t09)

[24.5 Package contract tests](#bookmark=id.okw7uimzhoqy)

[24.6 Reproducible builds](#bookmark=id.3u8b2jswbpgj)

[24.7 SBOM, signing, and provenance](#bookmark=id.d08s982yo0f0)

[24.8 Release evidence](#bookmark=id.auvfjjxd6yzs)

[24.9 Stop-ship conditions](#bookmark=id.f92gicsj27h0)

[**25\. Documentation and user-facing deliverables**](#bookmark=id.5tq4qyiqhmal)

[25.1 Documentation site](#bookmark=id.k1n61l6yvl25)

[25.2 Documentation correctness](#bookmark=id.wa055cwn997i)

[25.3 Root README](#bookmark=id.wcdda2mle6oe)

[25.4 Open-source release files](#bookmark=id.onofpqc3t96e)

[**26\. Dependency-ordered implementation work packets**](#bookmark=id.5fmnyuqavuc4)

[26.1 Execution waves](#bookmark=id.2i3dgmktcg04)

[26.2 Packet evidence contract](#bookmark=id.91ivg31rh88p)

[26.3 WP00 \- repository, toolchain, and quality skeleton](#bookmark=id.jtdf83tpae8p)

[26.4 WP01 \- Context ABI domain types and schemas](#bookmark=id.qvgfe5r9wwmk)

[26.5 WP02 \- canonicalization, hashing, crypto, and errors](#bookmark=id.vlf7bx4tbo2p)

[26.6 WP03 \- store traits and transaction contracts](#bookmark=id.ftb9e81xahww)

[26.7 WP04 \- SQLite, blob storage, backup, and recovery](#bookmark=id.6orxlu6nwkfn)

[26.8 WP05 \- catalog, ingestion, code intelligence, and invalidation](#bookmark=id.yjupwu2zwuz9)

[26.9 WP06 \- index manager and authorized retrieval](#bookmark=id.gg5yhsrfk4wu)

[26.10 WP07 \- policy, redaction, and capabilities](#bookmark=id.pd7ydlzbil6w)

[26.11 WP08 \- planner and deterministic compiler](#bookmark=id.bmmxhwglhmlh)

[26.12 WP09 \- materializers, tokenizers, caches, and deltas](#bookmark=id.q48zh0dcnbn4)

[26.13 WP10 \- context spaces, overlays, commits, and events](#bookmark=id.raiuzwmb02ic)

[26.14 WP11 \- handoff and agent result protocol](#bookmark=id.95q604c9jegm)

[26.15 WP12 \- effect journal and reference connectors](#bookmark=id.4ovpbensecj2)

[26.16 WP13 \- decision records and replay](#bookmark=id.ep8khcbp8fs9)

[26.17 WP14 \- daemon, APIs, authentication, and operations](#bookmark=id.7ymxtr88ueyc)

[26.18 WP15 \- complete CLI](#bookmark=id.ebj9z0rea7hh)

[26.19 WP16 \- Rust, TypeScript, Python, and Go SDKs](#bookmark=id.khqu7k3nsqgm)

[26.20 WP17 \- Claude Code plugin, MCP, hooks, and skills](#bookmark=id.dqzvg08ja1p2)

[26.21 WP18 \- PostgreSQL, object storage, and shared deployment](#bookmark=id.h1ej3b9ahr39)

[26.22 WP19 \- conformance, security, fuzz, and quality hardening](#bookmark=id.ksvvziox5p03)

[26.23 WP20 \- demos and CIGARBench](#bookmark=id.br6g3tyu7h0f)

[26.24 WP21 \- packaging, documentation, and operational readiness](#bookmark=id.2s4iw3vfrey2)

[26.25 WP22 \- release candidate and v1.0.0](#bookmark=id.8bwxw1u618r8)

[**27\. Codex execution control protocol**](#bookmark=id.qpq0pqrtp7wk)

[27.1 Kickoff procedure](#bookmark=id.ivrymektj5uo)

[27.2 Work packet selection](#bookmark=id.ojsa39ejomqp)

[27.3 Parallel agent use](#bookmark=id.4vsaxiitr0v)

[27.4 Change discipline](#bookmark=id.1ud984i9dcq5)

[27.5 Test order for every slice](#bookmark=id.4spv6sqwqd53)

[27.6 Blocker protocol](#bookmark=id.4sqylsffvwqx)

[27.7 Resume and context compaction](#bookmark=id.2edgfrdfjpk2)

[27.8 Completion report for each packet](#bookmark=id.x0j85p1tew5z)

[27.9 No-waiver rule](#bookmark=id.r6dqde1rispb)

[**28\. Release-candidate execution sequence**](#bookmark=id.v4flri5dtt17)

[28.1 Clean-source qualification](#bookmark=id.cb7jkz8r8loj)

[28.2 Installed-artifact qualification](#bookmark=id.yx516fciwr2k)

[28.3 Soak requirements](#bookmark=id.8ioumenub9sk)

[28.4 Final release evidence](#bookmark=id.p28lnwvd0ms)

[**29\. Production definition of done**](#bookmark=id.obli2um8c4fg)

[**Appendix A. Implementation status template**](#bookmark=id.742hlgg9y7jv)

[**Appendix B. Machine-readable requirement template**](#bookmark=id.71i0coeab6re)

[**Appendix C. Minimal end-to-end acceptance script**](#bookmark=id.nerdynafyvwu)

[**Appendix D. Release artifact manifest**](#bookmark=id.waixcl3ewgu2)

[**Appendix E. Codex master execution prompt**](#bookmark=id.fg9nmwttnfqf)

[**Appendix F. Final stop-ship checklist**](#bookmark=id.hzgjsobwp28v)

[**Appendix G. Final execution directive**](#bookmark=id.kmhh0rrpp9gd)

# **1\. Execution mandate**

## **1.1 How Codex SHALL execute this specification**

Codex SHALL treat the repository as a durable engineering program rather than a one-shot code-generation task. At the beginning of execution it creates IMPLEMENTATION\_STATUS.md from the template in Appendix A. It records every work packet as not\_started, in\_progress, blocked, or complete, along with commit or patch identity, commands run, tests passed, performance results, and remaining risks.

Only one critical-path work packet may be in\_progress per working branch. Independent packages may run in parallel branches or agents after their shared contract is frozen. Parallel work MUST NOT edit the same schema, migration, generated artifact, lockfile, or compatibility vector without an explicit integration owner.

For every work packet Codex SHALL:

1. Verify prerequisites and read the named public contracts.  
2. Enumerate files to create or modify and record the scope.  
3. Add a failing unit, integration, contract, or end-to-end test for each behavior before or with the implementation.  
4. Implement production behavior, including negative paths, cancellation, resource limits, and typed errors.  
5. Run package-local format, lint, unit, and property tests.  
6. Run dependent contract and integration suites.  
7. Run the packet's scripted demo or observable acceptance scenario.  
8. Update generated schemas, fixtures, API references, and user documentation in the same packet.  
9. Record results in IMPLEMENTATION\_STATUS.md and produce a clean packet boundary.

Codex SHALL stop and surface a blocker when it encounters an authorization ambiguity, schema incompatibility, data-loss path, nondeterministic canonical result, unsafe effect retry, failed migration, or a release-gate regression. It SHALL not make a permissive assumption to continue.

## **1.2 Coding rules**

* Use Rust stable pinned in rust-toolchain.toml; all Rust packages use edition 2024\.  
* Deny warnings in CI. Public Rust items require documentation. Unsafe Rust is forbidden except in an explicitly audited platform adapter with a safety proof and dedicated tests.  
* unwrap, expect, indexing that may panic, process abort, and unchecked numeric conversion are forbidden in production paths.  
* Use thiserror for library errors and anyhow only at binary or test orchestration boundaries.  
* All asynchronous operations accept cancellation and deadlines through request context.  
* All loops over user-controlled data have explicit limits. All recursive graph behavior has depth and result bounds.  
* All public mutations are idempotent or require an idempotency key and expected revision.  
* Logs and traces use structured fields. Secrets and raw protected content are never formatted through Debug or Display.  
* No test depends on public internet access. Live-provider and live-connector tests are opt-in and excluded from default CI.  
* Generated files are reproducible and checked by cargo xtask generate \--check.  
* Every code example in public documentation is compiled or executed in CI.  
* TODO, FIXME, unimplemented\!, todo\!, placeholder success responses, and empty catch blocks fail the release lint unless linked to an excluded non-v1 path and compiled out of release features.

## **1.3 Product outcome to preserve**

CIGAR compiles the smallest sufficient governed context for a job, records why every item was included or excluded, hands task state to another agent without transferring the parent transcript by default, and journals any resulting external effect. The implementation MUST optimize cost per verified successful job, not token count alone.

The reference benchmark target for repeated long-horizon coding work is at least 40% median physical input-token reduction, at least 95% critical-context recall, no more than two percentage points of task-success regression, zero unauthorized cross-project items, and 100% provenance on selected catalog-derived blocks.

## **1.4 Fixed v1 scope**

The v1 release includes:

* Canonical Context ABI records and deterministic wire semantics.  
* Local and shared catalogs with source snapshots, immutable atoms, typed edges, content blobs, tombstones, and invalidation.  
* Exact, lexical, temporal, graph, and optional vector retrieval.  
* Hard policy gates, deterministic planning, conflict handling, dependency closure, token-aware packing, evidence-carrying transforms, manifests, materialization, caching, and deltas.  
* Context spaces, branches, overlays, optimistic publication, handoff capsules, recipient acceptance, capability attenuation, and typed child-result merge.  
* Effect intents, approvals, attempts, receipts, unknown state, reconciliation, compensation links, and replay-safe behavior.  
* Decision records, evidence reproduction, invocation reproduction, observational replay, and live comparison.  
* Embedded API, daemon, HTTP/JSON, gRPC, SSE, CLI, stdio MCP, and four SDKs.  
* Claude Code plugin with MCP, hooks, skills, diagnostics, and provider-present context accounting.  
* Production diagnostics, metrics, tracing, backup, restore, migrations, health checks, and resource controls.  
* Deterministic demos, conformance kit, performance harness, documentation, installers, packages, images, SBOMs, signatures, and release provenance.

## **1.5 Non-goals for implementation**

Do not build an agent planner, workflow scheduler, model gateway, vector database, graph-database product, agent studio, prompt marketplace, hosted billing system, or visual workflow editor. Do not parse private Claude session formats. Do not promise bit-identical model output or universal exactly-once remote execution. Do not add project-governance or community-governance systems to the codebase.

# **2\. Fixed architecture and technical decisions**

## **2.1 System architecture**

![Layered CIGAR v1 production architecture showing product surfaces, composable application services, the trusted semantic kernel, and replaceable sources, indexes, persistence, consumers, and connectors.][image1]

*Figure 1\. CIGAR v1 production architecture*

One semantic core supports embedded, local-daemon, and shared-service modes. Public record identity, canonical bytes, hashes, policy order, compilation results, state-machine transitions, and error codes MUST remain identical across modes.

The reference architecture consists of:

* cigar-protocol: portable domain types, schema versions, validation, compatibility, and error codes.  
* cigar-canon: deterministic CBOR, semantic envelope selection, digests, and test vectors.  
* cigar-crypto: key abstraction, envelope encryption, signatures, blinded identifiers, and secret-safe types.  
* cigar-store: transactional repository traits and SQLite/PostgreSQL/blob implementations.  
* cigar-catalog: source snapshots, atom publication, lifecycle, provenance graph, and invalidation.  
* cigar-retrieval: exact, lexical, temporal, graph, and optional vector candidate generation.  
* cigar-policy: non-bypassable hard gates and a deterministic declarative rule profile.  
* cigar-compiler: contract normalization, planning, reconciliation, optimization, transform, pack, manifest, cache, and delta.  
* cigar-space: context commits, overlays, handoff, capability attenuation, merge, leases, and subscriptions.  
* cigar-effects: intent-first journal, connectors, receipts, reconciliation, and compensation.  
* cigar-replay: decision capture, reproduction modes, comparison, and completeness reporting.  
* cigar-extension-host: signed extension manifests, WASI or subprocess isolation, capabilities, limits, and host calls.  
* cigar-api: service orchestration, authentication context, HTTP/gRPC/SSE contracts, and client core.  
* cigar-daemon, cigar-cli, cigar-mcp: deployable surfaces.  
* cigar-testkit and cigar-sim: hermetic fixtures, failpoints, deterministic consumers, and fake external services.

## **2.2 Fixed technology choices**

| Concern | v1 choice | Required property |
| :---- | :---- | :---- |
| Core language | Rust stable, edition 2024 | Memory safety, native performance, shared semantic implementation |
| Async runtime | Tokio | Cancellation, bounded concurrency, mature network and signal support |
| HTTP | Axum with Tower middleware | Typed routing, limits, timeouts, tracing, auth layers |
| gRPC | Tonic and Prost | Streaming and generated cross-language contracts |
| API description | Protobuf authoritative for RPC; OpenAPI generated for HTTP; JSON Schema for protocol artifacts | Checked-in, reproducible, compatibility-tested |
| Canonical wire | RFC 8949 deterministic CBOR profile | Identical cross-language bytes and hashes |
| Human interchange | JSON with generated JSON Schema | Inspectable and validation-friendly |
| Integrity | SHA-256 multihash over domain-separated canonical envelope | Stable and independently implementable |
| Signatures | Ed25519 | Portable handoff, bundle, receipt, and release integrity |
| Blob encryption | XChaCha20-Poly1305 with per-blob nonce and envelope key reference | Authenticated encryption and key rotation |
| Local metadata | SQLite in WAL mode | Embedded, crash-safe, offline profile |
| Shared metadata | PostgreSQL-compatible database | Transactions, locking, tenant scale, operational tooling |
| Local lexical index | SQLite FTS5 | No external service required |
| Shared lexical index | PostgreSQL full text behind the same retriever trait | Operational simplicity and consistent filters |
| Graph projection | Transactional edge tables plus adjacency indexes | No mandatory graph-database dependency |
| Vector retrieval | Optional adapter; local HNSW and shared pgvector-compatible profile | Replaceable and never required for correctness |
| Code parsing | Tree-sitter adapters with language-specific symbol extractors | Deterministic structural atoms and incremental updates |
| Observability | tracing plus OpenTelemetry export | Structured, content-free default telemetry |
| Configuration | Layered TOML plus environment overrides and secret handles | Typed validation and deterministic effective config |
| Build orchestration | Cargo workspace, cargo xtask, and just convenience recipes | One authoritative implementation in xtask |
| Test runner | Cargo Nextest for Rust plus native SDK test runners | Parallel, retry-free, machine-readable results |
| Release build | Pinned cargo-dist or equivalent declared in xtask | Multi-platform packages, checksums, signatures, provenance |

Dependency versions SHALL be pinned by lockfiles for binaries and exact package-manager locks for SDKs and docs. Renovation occurs through tested update changes, not floating CI installs.

## **2.3 Dependency direction**

![Layered dependency diagram from binaries and adapters down through APIs, application services, kernel services, and protocol, canonicalization, crypto, and generation foundations.][image2]

*Figure 2\. Rust workspace and package dependency direction*

Foundation crates cannot import persistence, networking, CLI, provider, or daemon crates. Application services depend on repository traits, not concrete SQLite or PostgreSQL implementations. Binaries compose concrete backends. The CI job cargo xtask architecture-check reads Cargo metadata and fails forbidden dependency edges or cycles.

## **2.4 Feature policy**

The default binary includes SQLite, FTS5, filesystem blobs, deterministic transforms, HTTP/gRPC APIs, CLI, MCP, and local observability. Optional features include PostgreSQL, vector retrieval, remote OpenTelemetry export, and live connectors. Security-critical behavior is never removed by a feature flag.

Every feature combination compiled for release has a named profile. CI tests default, minimal-local, shared-service, and all-features. Unnamed arbitrary combinations are unsupported and the code MUST fail configuration validation rather than partially initialize.

## **2.5 Compatibility policy implemented in code**

* All public records include schema\_version and reject unsupported major versions.  
* Readers accept the current v1 minor form and declared additive older forms.  
* Writers emit one configured current form.  
* Unknown fields are preserved only in explicitly extensible envelopes; security decisions never depend on ignored fields.  
* Protobuf breaking checks, OpenAPI diff, JSON Schema compatibility, Rust semantic version checks, and cross-SDK fixtures run in CI.  
* Database migrations support upgrade from the previous two release lines and documented backup restore.  
* Canonical bytes never change for an existing schema version.

## **2.6 Supported release profiles**

| Profile | Required targets | Claim |
| :---- | :---- | :---- |
| Tier 1 local | Linux x86\_64 and arm64; macOS arm64 | Merge matrix plus full release-artifact qualification |
| Tier 2 local | Windows x86\_64; macOS x86\_64 while supported by dependencies | Nightly plus full release-artifact qualification |
| Shared service | Linux x86\_64 and arm64 OCI images | PostgreSQL/object profile, rolling upgrade, load, and chaos |
| Embedded | Rust on Tier 1 targets | Same semantic conformance through direct library calls |
| SDK | Supported Node LTS, maintained CPython versions, and supported Go toolchain | Clean package install and client conformance |

Exact minimum versions are pinned during WP00 in machine-readable support metadata. A release cannot broaden the claim without qualifying the added target.

# **3\. Repository and build layout**

## **3.1 Monorepo tree**

cigar/  
  Cargo.toml  
  Cargo.lock  
  rust-toolchain.toml  
  rustfmt.toml  
  clippy.toml  
  deny.toml  
  justfile  
  LICENSE  
  NOTICE  
  SECURITY.md  
  README.md  
  IMPLEMENTATION\_STATUS.md  
  .config/nextest.toml  
  .cargo/config.toml  
  .github/workflows/  
  crates/  
    cigar-protocol/  
    cigar-canon/  
    cigar-crypto/  
    cigar-policy/  
    cigar-store/  
    cigar-catalog/  
    cigar-code-intel/  
    cigar-retrieval/  
    cigar-compiler/  
    cigar-space/  
    cigar-effects/  
    cigar-replay/  
    cigar-observe/  
    cigar-extension-host/  
    cigar-api/  
    cigar-daemon/  
    cigar-cli/  
    cigar-mcp/  
    cigar-testkit/  
    cigar-sim/  
    xtask/  
  sdk/  
    typescript/  
    python/  
    go/  
  adapters/  
    claude-code/  
  connectors/  
    filesystem/  
    http-idempotent/  
    github-issues/  
    demo-issue-service/  
  spec/  
    context-abi/  
    canonicalization/  
    policy/  
    effects/  
    errors/  
    compatibility/  
  schemas/  
    json/  
    proto/  
    openapi/  
    vectors/  
  migrations/  
    sqlite/  
    postgres/  
  tests/  
    contract/  
    integration/  
    e2e/  
    security/  
    migration/  
    chaos/  
    compatibility/  
    installation/  
  fuzz/  
  benches/  
  demos/  
    quickstart/  
    multiproject-payments/  
    agent-handoff/  
    effect-recovery/  
    replay-comparison/  
    prompt-injection-defense/  
    sdk-clients/  
  docs/  
    site/  
    guides/  
    reference/  
    operations/  
    troubleshooting/  
  deploy/  
    docker/  
    compose/  
    kubernetes/  
    systemd/  
  tools/  
    release/  
    fixtures/

## **3.2 Workspace package rules**

Each Rust crate SHALL have one clear responsibility, a README.md with stability level, crate-level documentation, unit tests, and no undeclared feature behavior. Shared dependency versions, license, repository, rust-version, and lint configuration live in workspace metadata.

cigar-protocol, cigar-canon, and cigar-crypto are small and stable. cigar-api owns orchestration facades but not domain semantics. cigar-daemon and cigar-cli contain composition and UX only; moving a rule from a binary into a library is mandatory before another surface duplicates it.

## **3.3 Authoritative commands**

cargo xtask bootstrap  
cargo xtask generate  
cargo xtask generate \--check  
cargo xtask fmt \--check  
cargo xtask lint  
cargo xtask test unit  
cargo xtask test integration  
cargo xtask test e2e  
cargo xtask test security  
cargo xtask test compatibility  
cargo xtask test chaos  
cargo xtask test all  
cargo xtask bench smoke  
cargo xtask docs \--check  
cargo xtask package \--profile local  
cargo xtask package \--profile shared  
cargo xtask release-verify \<artifact-directory\>

just recipes may call these commands but SHALL contain no independent build logic. CI calls cargo xtask directly.

## **3.4 Bootstrap behavior**

cargo xtask bootstrap verifies the pinned Rust toolchain, required native tools, Node, Python, Go, Protobuf compiler, SQLite capabilities, container runtime for shared-profile tests, and platform signing prerequisites. It installs nothing silently. Missing tools produce exact supported versions and installation links.

It then validates locks, generates schemas into a temporary directory, compares checked-in artifacts, creates test certificates and keys under an ignored temporary directory, initializes deterministic fixture databases, and prints the next executable command.

## **3.5 Configuration layout**

\[daemon\]  
mode \= "local"                 \# local | shared  
listen \= "unix:///run/user/.../cigard.sock"  
shutdown\_grace \= "15s"  
   
\[storage\]  
metadata \= "sqlite:///.../cigar.db"  
blobs \= "file:///.../blobs"  
encryption\_key \= "keychain://cigar/local-master"  
   
\[compiler\]  
profile \= "balanced-v1"  
max\_candidates \= 10000  
default\_input\_tokens \= 6000  
deterministic \= true  
   
\[policy\]  
profile\_path \= "\~/.config/cigar/policy.toml"  
fail\_closed \= true  
   
\[telemetry\]  
content\_capture \= false  
otlp\_endpoint \= null

Configuration precedence is compiled defaults, system config, user config, project config, explicit \--config, environment overrides, and CLI flags. Security restrictions can only narrow at later layers. The effective configuration can be printed with secret values redacted and a source for every field.

# **4\. Protocol types, schemas, and canonicalization**

## **4.1 Protocol crate responsibilities**

cigar-protocol contains data-only domain types, enum discriminants, schema-version parsing, validation, redaction views, stable error codes, and conversion between Rust, JSON, Protobuf, and canonical CBOR representations. It does not perform I/O, database access, networking, tokenization, ranking, policy evaluation, or cryptography.

Required top-level v1 records are:

* Identity and source: RecordId, LineageId, VersionId, ContentDigest, SourceDescriptor, SourceSnapshot.  
* Catalog: ContextAtom, ContextEdge, BlobRef, Lifecycle, TemporalEnvelope, GovernanceEnvelope, QualityEnvelope.  
* Compilation: ContextContract, ContextRequirement, Budget, TargetProfile, ContextPlan, PlanLane, CandidateDisposition, ContextBlock, ContextBundle, SelectionManifest, MaterializedContext, ContextDelta.  
* Coordination: ContextSpaceId, ContextCommit, Overlay, CapabilityGrant, HandoffCapsule, HandoffAcceptance, HandoffDelta, Lease.  
* Effects: EffectIntent, EffectApproval, EffectAttempt, EffectReceipt, EffectJournalEvent, ReconciliationReport, CompensationLink.  
* Replay: DecisionRecord, ReplayRequest, ReplayExecution, ReplayCompleteness, ReplayDiff, VerificationReceipt.  
* Service: PageCursor, IdempotencyKey, ExpectedRevision, Problem, HealthReport, CompatibilityReport.

Every record SHALL derive or implement schema validation, secret-safe debug formatting, canonical serialization where applicable, and a deterministic fixture constructor in cigar-testkit.

## **4.2 Schema rules**

* Record schemas use closed enums for security-sensitive states. Unknown security enum values fail validation.  
* Extensible metadata uses namespaced keys matching ^\[a-z0-9\]\[a-z0-9.\_/-\]{0,127}$ and bounded values.  
* Strings declare byte and character limits. Paths and URIs use typed wrappers rather than unvalidated strings.  
* Timestamps are UTC instants with nanosecond precision in memory and RFC 3339 form in JSON. Canonical form uses signed integer nanoseconds from Unix epoch.  
* Durations use non-negative integer nanoseconds with explicit maximums.  
* Floating-point values are prohibited in canonical semantic records. Confidence and score components use bounded fixed-point integers.  
* Optional fields are absent when unset; canonical semantic objects never encode a null alternative.  
* Byte payloads use base64url without padding in JSON and byte strings in CBOR.  
* Map keys are strings or fixed numeric discriminants. Order-sensitive collections use arrays; sets are sorted and uniqueness-validated before canonicalization.  
* Default values are explicit in schema documentation and normalized before hashing.  
* Every maximum has a named constant in cigar-protocol::limits and corresponding boundary tests.

## **4.3 Core atom schema**

ContextAtomV1 {  
  schema\_version: "cigar.atom.v1"  
  atom\_id: UUIDv7  
  lineage\_id: UUIDv7  
  version\_id: Multihash  
  content\_digest: Multihash  
  kind: AtomKind  
  payload: InlineText | StructuredJson | BlobRef  
  source: SourceDescriptor  
  scope: ScopeEnvelope  
  temporal: TemporalEnvelope  
  governance: GovernanceEnvelope  
  quality: QualityEnvelope  
  retrieval: RetrievalEnvelope  
  lifecycle: Active | Superseded | Tombstoned | Quarantined  
  extensions: BoundedMap\<ExtensionKey, CanonicalValue\>  
}

Validation order is structural limits, version support, identity syntax, payload integrity, source requirements, scope requirements, temporal consistency, governance completeness, quality bounds, retrieval metadata consistency, lifecycle invariants, and extension bounds. Validation returns all safe independent errors up to a configured cap rather than failing after the first field.

## **4.4 Context contract schema**

ContextContractV1 SHALL require a non-empty job goal, operation class, principal, purpose, context-space or project scope, target profile, total input budget, output reserve, and consistency mode. Required context selectors identify semantic type, exact or query selector, minimum authority, maximum age, minimum coverage, and whether missing data blocks compilation.

The canonical normalized form:

* Trims and Unicode-normalizes human text without changing code, identifiers, or exact constraints.  
* Resolves project aliases to immutable IDs before hashing.  
* Sorts set-like project, capability, and exclusion collections.  
* Converts lane budgets into exact integers and verifies their sum against the total.  
* Resolves tokenizer and materializer fingerprints.  
* Expands defaults into explicit fields.  
* Excludes transport request IDs and trace IDs from the semantic fingerprint.

## **4.5 Stable error model**

Errors are defined in spec/errors/catalog.yaml and generated into Rust, Protobuf, OpenAPI, TypeScript, Python, and Go. Each error has a numeric code, stable symbolic name, HTTP status, gRPC status, retry class, safe message template, remediation template, and whether details may disclose record identity.

Required families include:

| Family | Examples |
| :---- | :---- |
| Input | INVALID\_ARGUMENT, LIMIT\_EXCEEDED, UNSUPPORTED\_SCHEMA |
| Identity | UNKNOWN\_PRINCIPAL, INVALID\_CAPABILITY, CAPABILITY\_EXPIRED |
| Catalog | SOURCE\_UNAVAILABLE, SNAPSHOT\_INCOMPLETE, INTEGRITY\_FAILURE |
| Index | INDEX\_STALE, INDEX\_UNAVAILABLE, CONSISTENCY\_UNSATISFIED |
| Policy | POLICY\_DENIED, PROCESSOR\_DENIED, INSTRUCTION\_AUTHORITY\_DENIED |
| Compiler | BUDGET\_UNSATISFIABLE, MISSING\_REQUIRED\_CONTEXT, UNRESOLVED\_CRITICAL\_CONFLICT |
| Delta | DELTA\_BASE\_MISMATCH, BUNDLE\_INVALIDATED |
| Coordination | REVISION\_CONFLICT, HANDOFF\_EXPIRED, HANDOFF\_RECIPIENT\_MISMATCH |
| Effect | APPROVAL\_REQUIRED, APPROVAL\_STALE, EFFECT\_UNKNOWN, UNSAFE\_RETRY |
| Replay | REPLAY\_INCOMPLETE, DEPENDENCY\_UNAVAILABLE, LIVE\_AUTHORIZATION\_REQUIRED |
| Service | RATE\_LIMITED, DEADLINE\_EXCEEDED, DEPENDENCY\_DEGRADED, INTERNAL |

Problem.details is a typed, bounded map with per-error schema. Internal causes are logged by correlation ID but not leaked to unauthorized clients.

## **4.6 Deterministic CBOR profile**

cigar-canon implements a documented RFC 8949 deterministic profile:

* Definite-length items only.  
* Shortest integer and length encodings.  
* Map keys sorted by bytewise order of their encoded deterministic key representation.  
* No floating point, tags outside the approved registry, indefinite strings, duplicate keys, or non-shortest forms.  
* Text is valid UTF-8. Human text uses NFC where the field schema declares normalization; code and opaque text retain exact bytes.  
* Sets are pre-sorted by each member's canonical bytes and reject duplicates.  
* Schema discriminants use fixed unsigned integers published in spec/canonicalization/discriminants.md.  
* Semantic envelope selection excludes non-semantic observation fields only where the record specification names them.

The canonicalizer uses a streaming encoder with explicit maximum depth, map entries, array entries, and total output bytes. Decoding a canonical record re-encodes and byte-compares in strict mode. Non-canonical but semantically parseable input is rejected at signed and hash-addressed boundaries.

## **4.7 Digest domains**

Every digest prepends an ASCII domain separator, zero byte, schema major, and canonical payload:

CIGAR-ATOM\\0v1\\0\<canonical-atom-envelope\>  
CIGAR-BUNDLE\\0v1\\0\<canonical-ordered-bundle\>  
CIGAR-MANIFEST\\0v1\\0\<canonical-manifest\>  
CIGAR-HANDOFF\\0v1\\0\<canonical-handoff\>  
CIGAR-EFFECT\\0v1\\0\<canonical-effect-intent\>  
CIGAR-RECEIPT\\0v1\\0\<canonical-receipt\>

The v1 digest algorithm is SHA-256 represented as a multihash. The algorithm identifier is part of every digest. An algorithm registry permits future additions without changing v1 bytes.

## **4.8 Identity generation**

Record and lineage IDs use UUIDv7 from a monotonic generator. The generator handles clock rollback by retaining the last timestamp and incrementing its random sequence; it never emits duplicates under concurrent load. Semantic version\_id values are content-derived and therefore independent of record creation time.

Source URIs are normalized by scheme-specific code. Filesystem identity records platform, volume or device identity where available, canonical root, relative path bytes, case-sensitivity mode, and source revision. Generic URI normalization MUST NOT lowercase or percent-decode path content beyond the relevant URI standard.

## **4.9 Cross-language golden vectors**

schemas/vectors/ contains at least 200 vectors:

* Minimum and maximum valid records for every top-level schema.  
* Unicode normalization, exact code text, path, URI, timestamp, fixed-point, and map-order cases.  
* Equivalent JSON inputs that normalize to one canonical byte sequence.  
* Invalid duplicate, overflow, null, float, non-canonical CBOR, unknown discriminant, and malformed signature cases.  
* Stable expected CBOR bytes, content digest, version ID, signature input, and validation errors.

Rust generates vectors only through an explicit update command. TypeScript, Python, and Go independently parse JSON, canonicalize supported records, verify bytes and digests, and reject invalid cases. CI fails if any SDK delegates the assertion back to a server instead of reproducing it locally.

# **5\. Cryptography and secret-safe handling**

## **5.1 Key provider abstraction**

KeyProvider exposes create, resolve, rotate, sign, verify, wrap, unwrap, and destroy operations using opaque KeyRef values. Production implementations are operating-system keychain, file-backed encrypted development keystore, and external KMS adapter. Raw private key bytes never cross the trait boundary except inside the software-keystore implementation.

Keys have purpose, algorithm, tenant, creation time, activation time, retirement time, status, and public identity. Policy prevents a signing key from being used for blob encryption or a tenant key from crossing tenant scope.

## **5.2 Blob encryption**

Each blob is compressed before encryption only when its MIME and policy permit. The store generates a random data-encryption key and 192-bit nonce, encrypts with XChaCha20-Poly1305, and binds tenant, blob digest, MIME, size, compression, and schema version as associated data. The data key is wrapped by the configured master key.

Blob filenames and object keys use a tenant-blinded digest by default. Plaintext digest remains in protected metadata for integrity and deduplication within the disclosure domain. Verification decrypts, decompresses under a maximum expansion ratio, hashes plaintext, and constant-time compares the digest.

## **5.3 Signatures**

Handoff capsules, exported bundles, effect receipts, and release conformance statements may be signed. A signature envelope contains algorithm, key ID, signer principal, purpose, signed-at, expires-at if relevant, payload digest, and signature bytes. Verification checks purpose, key scope, key status at signing time, expiry, schema support, and payload digest.

Local single-user mode still uses an Ed25519 installation key so exported artifacts retain portable integrity. Import never treats a valid signature as authorization; recipient policy evaluates the signer and payload independently.

## **5.4 Secret types**

Secret values use SecretString, SecretBytes, or SecretHandle. Their debug output is \[REDACTED\], cloning is minimized, and memory is zeroized where feasible. Configuration accepts secrets only through handles, environment variables explicitly marked secret, or interactive secure input. cigar doctor \--security scans effective configuration, logs, test artifacts, and catalog fixtures for accidental secret serialization.

# **6\. Persistence and transactional model**

## **6.1 Store interfaces**

cigar-store defines repository traits around domain transactions rather than one generic key-value API:

Store.begin\_read(snapshot\_or\_latest) \-\> ReadTxn  
Store.begin\_write(expected\_revision) \-\> WriteTxn  
ReadTxn.get\_atom(version\_id)  
ReadTxn.query\_atoms(selector, limit, cursor)  
ReadTxn.edges\_from(version\_id, relation, limit)  
ReadTxn.get\_bundle(bundle\_id)  
ReadTxn.get\_effect(effect\_id)  
WriteTxn.stage\_snapshot(source\_snapshot)  
WriteTxn.publish\_atoms(atoms, edges)  
WriteTxn.append\_context\_commit(events)  
WriteTxn.append\_effect\_event(event)  
WriteTxn.enqueue\_outbox(message)  
WriteTxn.commit() \-\> CommitReceipt

Transactions carry tenant and purpose context. Repository methods cannot be called without it. SQLite and PostgreSQL implementations pass the same behavior suite.

## **6.2 Logical tables**

Required tables and invariants:

| Table | Key | Critical invariant |
| :---- | :---- | :---- |
| tenants | tenant ID | Immutable identity; deletion is staged |
| principals | principal ID | Status and authentication mapping versioned |
| source\_snapshots | snapshot ID | State is staged, published, failed, or tombstoned |
| atoms | atom version ID | Immutable semantic envelope and digest |
| atom\_lineages | lineage ID | Current version is explicit, never inferred by timestamp |
| edges | edge ID | Immutable; derivation acyclicity validated before commit |
| blobs | blinded storage key | Size, digest, encryption, retention, and reference count |
| context\_commits | space and sequence | Monotonic sequence and parent revision |
| context\_events | commit and ordinal | Ordered, immutable events |
| policies | policy version | Immutable compiled profile and source digest |
| index\_watermarks | index and partition | Never advances beyond committed source sequence |
| plans | plan ID | Immutable normalized plan and fingerprints |
| bundles | bundle ID | Ordered blocks and dependency root |
| manifests | manifest ID | Candidate-log reference and exact compiler inputs |
| materializations | materialization ID | Target adapter, exact bytes or protected reference, token count |
| handoffs | handoff ID | Snapshot, recipient, capability root, expiry, nonce |
| handoff\_acceptances | handoff and recipient | One immutable acceptance version per attempt |
| decision\_records | decision ID | Bundle and output integrity links |
| effect\_intents | effect ID | Prepared before any attempt exists |
| effect\_attempts | attempt ID | Monotonic number per effect |
| effect\_receipts | receipt ID | Immutable evidence; outcome does not overwrite attempts |
| effect\_events | effect and sequence | Valid state transition and hash chain |
| outbox | message ID | Written in the same transaction as causal state |
| invalidation\_queue | invalidation ID | Idempotent dependency propagation cursor |
| leases | lease ID | Resource, holder, fencing token, expiry |

## **6.3 SQLite profile**

SQLite opens in WAL mode with foreign keys, defensive mode, busy timeout, bounded page cache, secure delete according to policy, and synchronous mode FULL for journal and context commits. One writer task serializes commits; read transactions use snapshots. Long-running readers have duration limits to prevent WAL growth.

Migrations enable required FTS5 tables and triggers. A startup capability check verifies SQLite version and compile options. The binary may use a bundled SQLite build for predictable supported platforms.

Local blob publication writes encrypted content to a temporary file, flushes and fsyncs file data, atomically renames within the same filesystem, fsyncs the parent directory, then commits the metadata reference. Orphan temporary and blob files are reconciled on startup.

## **6.4 PostgreSQL profile**

The shared profile uses explicit transactions, tenant predicates, prepared statements, statement and lock timeouts, pool bounds, advisory locks only for coordination that cannot be expressed through row versions, and FOR UPDATE SKIP LOCKED for workers. Every query is tenant-scoped at the repository layer and reinforced by row-level security where supported.

Context-space publication increments a stored revision under row lock. Effect dispatch workers claim authorized records with a fencing token and heartbeat. Outbox and invalidation workers update their cursor in the same transaction as processed state.

## **6.5 Migration system**

Migrations are append-only, checksum-verified, and present for SQLite and PostgreSQL. Each migration declares compatible application range, online or offline classification, expected lock behavior, data backfill, verification query, and rollback or restore plan.

Release CI tests:

* Fresh database creation.  
* Upgrade from every supported previous release fixture.  
* Interrupted migration recovery at each failpoint.  
* Downgrade refusal with a safe diagnostic.  
* Backup before irreversible migration.  
* Post-migration semantic hash equivalence.  
* Cross-profile import and export through protocol records, not raw SQL copying.

## **6.6 Backup and restore**

cigar backup create produces a signed manifest, consistent metadata snapshot, encrypted blob inventory, schema versions, key references, and checksums. cigar backup verify performs offline integrity validation. cigar restore targets an empty location by default, validates keys and capacity, restores metadata and blobs, rebuilds disposable indexes, and runs semantic consistency checks before activation.

Shared-service backup integrates with database-native physical backups but still emits a CIGAR inventory and verification receipt. Restore drills are automated in nightly CI with generated catalogs.

## **6.7 Retention and garbage collection**

Deletion writes a tombstone, emits invalidation, and removes future materialization eligibility. Physical blob deletion requires zero live references, expired replay and retention windows, no legal hold flag, and a completed backup policy check. GC is mark-and-sweep with a dry-run report and bounded batch size. A crash between mark and delete is safe and idempotent.

# **7\. Catalog ingestion and code intelligence**

## **7.1 Source connector contract**

SourceConnector.discover(root, policy) \-\> DiscoveryPlan  
SourceConnector.snapshot(previous\_revision, deadline) \-\> SourceSnapshotStream  
SourceConnector.read(record\_ref, byte\_range, deadline) \-\> BoundedBytes  
SourceConnector.subscribe(watermark) \-\> ChangeStream  
SourceConnector.health() \-\> SourceHealth

Connectors authenticate to the source, preserve stable revisions and record locations, enforce byte and item limits, and never assign semantic authority. Discovery returns an explicit preview before first ingestion.

## **7.2 Filesystem and Git connector**

The P0 connector supports Git repositories, uncommitted working trees, worktrees, local non-Git projects, ignore rules, symlink policy, sparse checkouts, submodules as explicit separate sources, and case-sensitive or insensitive filesystems.

Discovery applies this order: hard secret and platform exclusions, policy exclusions, .cigarignore, Git ignore rules, size and MIME limits, then user preview overrides that may only broaden when policy permits. Symlinks are recorded but targets outside authorized roots are not followed.

Stable project identity uses tenant namespace, normalized Git remote identity when available, repository root lineage UUID, and an explicit disambiguator. Moving a directory or creating a worktree preserves the project ID. Forks remain distinct projects unless linked.

## **7.3 Atomic ingestion pipeline**

1. Create a staged SourceSnapshot with base revision.  
2. Discover changed, added, deleted, renamed, and permission-changed source records.  
3. Stream bounded bytes through MIME detection, secret scanning, parser selection, and atomization.  
4. Write blobs and staged atoms with exact source ranges.  
5. Validate source-level invariants, edge references, derivation acyclicity, and limits.  
6. Build or update index entries in staging partitions.  
7. Commit atoms, tombstones, edges, source snapshot, and canonical sequence atomically.  
8. Advance index watermarks only after committed projection work.  
9. Emit invalidations and source-change events through the transactional outbox.

A failure before publication leaves the prior snapshot current. Retrying the same source revision reuses content digests and produces the same semantic result.

## **7.4 Atomizers**

Required atomizers:

* Plain text and Markdown: heading hierarchy, paragraphs, lists, table rows, code blocks, links, and explicit decision sections.  
* JSON, YAML, TOML, XML, and Protocol Buffers: documents, paths, schema entities, and exact scalar constraints.  
* Source code: package, module, namespace, type, function, method, field, signature, implementation span, imports, call or dependency references, documentation, and tests.  
* Git: commit metadata, diff hunks, changed-symbol mapping, branch and worktree state.  
* Interaction events: user intent, accepted decision, rejected alternative, correction, open question, artifact, tool result, and verification receipt.  
* CIGAR native records: manifests, decisions, handoffs, effects, and replay outputs.

Each atomizer declares supported MIME and language, deterministic version, maximum input, produced kinds, authority ceiling, and invalidation behavior.

## **7.5 Tree-sitter code intelligence**

cigar-code-intel defines a language adapter interface and ships at least Rust, TypeScript/JavaScript, Python, Go, Java, and C/C++ adapters for v1. Each adapter maps parse nodes into a language-neutral symbol model and exact source ranges. Parse-error regions are represented explicitly and never silently omitted.

Incremental parsing reuses prior trees for changed files. Symbol identity combines project, language, qualified name, kind, and source lineage, while symbol versions include signature and implementation digests. Rename detection is heuristic evidence and cannot overwrite identity without a verified source relation.

Symbol capsules contain signature, contract or documentation, direct dependencies, selected implementation spans, tests, and current diff. Capsule generation is deterministic and token-budget aware.

## **7.6 Secret and sensitive-content scanning**

Scanning combines hard path rules, entropy and pattern detectors, private-key parsers, known credential formats, and configurable organization rules. Findings are exclude, quarantine, or allow\_with\_label. Raw matched secret text is never stored in diagnostics; reports use detector, source ref, range, and blinded fingerprint.

The test corpus includes synthetic API keys, PEM keys, tokens embedded in code, encoded secrets, false-positive high-entropy fixtures, and boundary-split values. Release thresholds are documented and measured.

## **7.7 Invalidation graph**

The catalog stores exact dependency edges from source record to atom, derived atom, index entry, plan cache, bundle, materialization, handoff, and decision. Invalidation events contain root change, affected relationship, prior version, new version or tombstone, policy impact, and canonical commit.

Workers traverse in bounded batches with an idempotent visited key. High-priority revocation and authorization invalidations preempt ordinary freshness updates. A bundle with a revoked dependency becomes unservable immediately at the policy boundary even if background traversal has not completed.

# **8\. Policy, capability, and instruction enforcement**

## **8.1 Non-bypassable hard gates**

Technical policy enforcement is part of the semantic kernel. It cannot be delegated to prompts, rank weights, adapter convention, or an optional external policy service. The following gates are implemented directly in cigar-policy and always run:

* Tenant and workspace identity match.  
* Explicit project, branch, task, session, and agent scope.  
* Principal status and delegated capability validity.  
* Purpose and processor authorization.  
* Classification, residency, and egress restrictions.  
* Lifecycle, quarantine, tombstone, and integrity state.  
* World-valid time, transaction time, freshness, and expiry.  
* Instruction authority and lane promotion.  
* Explicit contract exclusions and target modality.  
* Effect operation, target, risk, approval, and retry capability.

A configurable rule profile may further deny, redact, require refresh, require approval, or narrow results. It can never override a hard denial.

## **8.2 Policy interface**

pub trait PolicyEngine: Send \+ Sync {  
    fn snapshot(\&self) \-\> PolicySnapshot;  
    fn authorize\_partition(\&self, request: PartitionRequest) \-\> PartitionDecision;  
    fn authorize\_metadata(\&self, request: MetadataRequest) \-\> MetadataDecision;  
    fn authorize\_content(\&self, request: ContentRequest) \-\> ContentDecision;  
    fn authorize\_processor(\&self, request: ProcessorRequest) \-\> ProcessorDecision;  
    fn authorize\_bundle(\&self, request: BundleRequest) \-\> BundleDecision;  
    fn authorize\_handoff(\&self, request: HandoffRequest) \-\> HandoffDecision;  
    fn authorize\_effect(\&self, request: EffectRequest) \-\> EffectDecision;  
}

Decisions are DENY, QUARANTINE, REQUIRE\_REFRESH, REDACT, REQUIRE\_APPROVAL, or ALLOW. Each contains stable reason code, input digest, policy digest, redaction paths, expiry, and conditions. Precedence is deny or quarantine, refresh, redaction, approval, allow.

## **8.3 Declarative v1 profile**

The built-in profile is versioned canonical JSON and a human-authored TOML mapping compiled to the same form. Rules contain stable ID, priority, action, resource selector, principal selector, purpose set, processor set, classification bounds, scope constraints, temporal conditions, effect constraints, and redaction paths.

Evaluation is deterministic:

1. Normalize selectors and reject unsupported operators.  
2. Select rules through indexed resource and principal classes.  
3. Sort by priority then rule ID.  
4. Apply every matching hard denial.  
5. Intersect allowed scopes and processors.  
6. Union required redactions.  
7. Apply refresh and approval requirements.  
8. Emit one decision and explanation digest.

No arbitrary code, network call, clock read, regex with unbounded complexity, or model invocation occurs during built-in evaluation. External providers implement the same decision interface, but the kernel hard gates remain authoritative.

## **8.4 Capability grants**

CapabilityGrant contains issuer, subject or recipient selector, tenant, resources, operations, purpose, limits, effect risk ceiling, delegable flag, not-before, expiry, nonce, parent grant, and signature. Attenuation computes a structural subset; it cannot add resource patterns, operations, purposes, duration, limits, or risk.

Every privileged API receives a resolved EffectiveCapabilities object bound to the authenticated principal and request. It is not reconstructed from prompt content or adapter-supplied labels. High-risk effect dispatch also checks a current fencing token where required.

## **8.5 Instruction authority**

Authority is a property of source and path under policy, not of text content. Valid authorities are system, managed\_policy, organization\_instruction, project\_instruction, user\_instruction, procedure, and none. Only approved paths and source connectors can produce non-none authority.

Atomizers may flag instruction-like text in untrusted evidence but cannot promote it. Model-generated content starts at none. Promotion creates a new validated atom with explicit promoter principal, source evidence, scope, and policy decision. Materializers preserve instruction and evidence structures and delimit untrusted data.

## **8.6 Redaction and denied existence**

Redaction transforms typed fields before content reaches retrieval scoring, embeddings, transforms, materializers, logs, or explanations. Redacted content has a derived digest and policy lineage. A required field that cannot be safely redacted makes the candidate ineligible.

Caller-facing explanations cannot reveal denied source paths, IDs, hashes, scores, counts, or timing. The policy engine returns a disclosure class with each reason. Aggregate metrics use fixed buckets or protected audit views when counts could leak existence.

## **8.7 Required policy properties**

* **Monotonicity:** narrowing scope or capabilities cannot increase authorized content or effects.  
* **Non-interference:** changing only unauthorized atoms cannot change caller-visible bundle bytes, explanation, or response class beyond defined constant-time tolerance.  
* **Project isolation:** adding Project B to the catalog does not make it visible to a Project-A-only contract.  
* **Processor confinement:** disallowed plaintext never reaches an embedding, ranker, summary, telemetry, or retry queue.  
* **Instruction separation:** payload text cannot increase its authority.  
* **Revocation:** current ACL or policy denial blocks materialization, handoff acceptance, and effect use even for an older otherwise-valid bundle.  
* **Fail closed:** protected operations fail when a required policy dependency is unavailable.

# **9\. Indexes and retrieval**

## **9.1 Index families**

The required v1 projections are:

* Exact ID, lineage, digest, canonical URI, source revision, schema, and artifact handle.  
* Tenant, workspace, project, branch, task, session, agent, classification, and purpose partitions.  
* Path, filename, repository, language, fully qualified symbol, entity, tag, and declared term.  
* Lexical full text with a committed analyzer and configuration fingerprint.  
* Bitemporal validity, freshness expiry, lifecycle, verification, authority, and classification.  
* Forward and reverse graph adjacency by relation and version.  
* Active context-space, task, session, handoff, bundle, decision, and effect cursors.  
* Optional vector projections partitioned by authorization domain and identified by model, dimensions, normalization, preprocessing, and source commit.

Indexes contain references and search features, not an independent source of truth. Each partition exposes built\_through\_commit, configuration\_digest, state, and last\_verified\_at.

## **9.2 Index update protocol**

Canonical publication writes an outbox event. An indexer claims events in sequence, applies idempotent updates, verifies affected entries, and advances the watermark in one transaction. Rebuild creates a new generation, catches up through the outbox, verifies counts and samples, then atomically switches the active generation.

Revocation and hard authorization changes have a direct policy check in addition to index removal, so a stale projection cannot leak content.

## **9.3 Retrieval interface**

\#\[async\_trait\]  
pub trait Retriever: Send \+ Sync {  
    fn descriptor(\&self) \-\> RetrieverDescriptor;  
    async fn retrieve(  
        \&self,  
        stage: RetrievalStage,  
        partition: AuthorizedPartition,  
        snapshot: CatalogCommit,  
        deadline: Deadline,  
    ) \-\> Result\<CandidateBatch\>;  
}

Retrievers return CandidateRef, fixed-point feature values, match evidence, index fingerprint, and watermark. They do not return unrestricted content. An authorized batch reader loads eligible content after complete metadata policy evaluation.

## **9.4 Query planning**

Requirements expand into independent bounded stages:

1. Governing policy and mandatory exact selectors.  
2. Current task, checkpoint, diff, branch state, criteria, and unresolved decisions.  
3. Exact symbol, path, entity, URI, claim, and artifact lookup.  
4. Declared dependency and definition traversal.  
5. Lexical BM25 search over authorized partitions.  
6. Optional vector neighbors over authorized partitions.  
7. Bounded graph expansion over defines, depends\_on, supports, contradicts, supersedes, references, and derived\_from.  
8. Freshness, verification, current-state, and project-proximity augmentation.

Stages run concurrently only after partition authorization. Caps are per requirement and stage so one broad query cannot starve mandatory categories. The plan records every stage, query fingerprint, cap, timeout, fallback, and required watermark.

## **9.5 Consistency**

strong waits until every required index reaches the pinned commit or returns INDEX\_STALE at deadline. bounded\_stale permits an explicit maximum commit or duration lag and records actual lag in the manifest and semantic bundle digest. eventual is allowed only for exploratory catalog query, not a governed compile, handoff acceptance, effect authorization, or replay claim.

Optional vector failure may fall back to exact, lexical, symbol, graph, and temporal retrieval when the contract permits degradation. Required exact selectors never degrade.

## **9.6 Candidate features**

Every candidate feature is an integer from 0 through 10,000:

requirement\_match, exact\_match, lexical\_match, semantic\_match,  
graph\_proximity, project\_proximity, task\_proximity, authority,  
verification, freshness, novelty, conflict\_risk, staleness,  
estimated\_tokens, requirement\_coverage\_bits, entity\_coverage\_bits

The balanced v1 score is a checked signed 64-bit sum:

score \= 280\*requirement\_match  
      \+ 150\*exact\_match  
      \+ 110\*lexical\_match  
      \+  80\*semantic\_match  
      \+  90\*graph\_proximity  
      \+  70\*project\_proximity  
      \+  60\*task\_proximity  
      \+  90\*authority  
      \+  45\*verification  
      \+  35\*freshness  
      \+  30\*novelty  
      \- 130\*conflict\_risk  
      \- 100\*staleness

Weights are versioned in CompilerProfile. Vector scores are quantized before compilation. Ties resolve by required status, lane priority, total score, lower token cost, canonical URI, source range, then version ID. Runtime randomness and hash-map order cannot affect results.

## **9.7 Vector adapter constraints**

Vector retrieval is optional. Embeddings are derived projection data with model and preprocessing fingerprints. The adapter receives only authorized, processor-approved plaintext or a configured local representation. Index partitions prevent cross-tenant and cross-project neighbor discovery. Re-embedding creates a new generation and never changes atom identity.

No v1 correctness claim depends on vectors. Every demo and conformance profile has a vector-disabled path.

# **10\. Context planner and compiler**

## **10.1 Public interface**

\#\[async\_trait\]  
pub trait ContextEngine: Send \+ Sync {  
    async fn plan(\&self, contract: ContextContract) \-\> Result\<ContextPlan\>;  
    async fn compile(\&self, plan: ContextPlan) \-\> Result\<ContextBundle\>;  
    async fn compile\_delta(\&self, plan: ContextPlan, base: BundleId)  
        \-\> Result\<ContextDelta\>;  
    async fn materialize(\&self, bundle: BundleId, target: TargetProfile)  
        \-\> Result\<MaterializedContext\>;  
    async fn explain(\&self, bundle: BundleId, view: ManifestViewPolicy)  
        \-\> Result\<SelectionManifestView\>;  
    async fn revalidate(\&self, bundle: BundleId) \-\> Result\<ValidationResult\>;  
}

Planning and compilation are persisted separately. A plan pins catalog commit, graph revision, policy digest, index watermarks, compiler profile, tokenizer, materializer profile, target capability, and normalized contract fingerprint. Compilation refuses a plan whose required immutable dependency differs.

## **10.2 Deterministic compilation path**

![Request and outcome flow from context contract through snapshot, plan, deterministic compile, sealed bundle, target materialization, consumption, decision record, verification, effect intent and receipt, and replay.][image3]

*Figure 3\. Compile, consume, observe, and journal execution path*

1. **Validate contract.** Normalize task, scope, purpose, target, consistency, risk, processors, lane budgets, exclusions, and requirements. Free text never grants authority.  
2. **Freeze inputs.** Open a store snapshot; resolve context-space head, policy, graph, indexes, tokenizer, and materializer. Compute request fingerprint.  
3. **Construct lanes.** Expand the standard authority lanes and resolve mandatory selectors, quotas, and permitted transform loss.  
4. **Retrieve references.** Execute authorized staged retrieval and persist candidate evidence.  
5. **Hard gate.** Enforce lifecycle, integrity, scope, purpose, processor, classification, instruction authority, temporal validity, freshness, modality, and exclusions before loading or transforming protected content.  
6. **Canonicalize candidates.** Resolve aliases, current lineage versions, exact duplicates, supersession, and source identity.  
7. **Reconcile claims.** Group claims by subject and predicate, apply explicit supersession and temporal rules, and create typed conflicts when unresolved.  
8. **Close dependencies.** Add definitions, source evidence, policies, schemas, decisions, and transform inputs required by selected candidates.  
9. **Build representation variants.** Produce exact, span, symbol, diff, fact, decision, checkpoint, and previously verified summary variants with exact dependencies and loss class.  
10. **Prove feasibility.** Insert mandatory closure using allowed lossless transforms. Return BUDGET\_UNSATISFIABLE with minimum required tokens if it cannot fit.  
11. **Satisfy lane minima.** Select deterministic marginal coverage within each lane.  
12. **Pack optional content.** Run the v1 multiple-choice submodular knapsack heuristic with category quotas and bounded local swaps.  
13. **Order blocks.** Apply authority order, causal dependency order, explicit priority, current-before-history, source URI and range, and version-ID tie break.  
14. **Tokenize and repair.** Use the exact target tokenizer and framing cost; remove lowest-value optional closure until within budget.  
15. **Validate and seal.** Re-run authorization, dependency, conflict, lane, token, integrity, and output-reserve checks; atomically persist bundle and manifest.  
16. **Subscribe.** Record dependency roots and invalidation watchers; emit BundleCompiled.

## **10.3 Standard lanes**

| Order | Lane | Compression policy |
| :---- | :---- | :---- |
| 1 | Governing policy and immutable constraints | No lossy transform |
| 2 | Project and repository instructions | Lossless structure only unless source explicitly permits |
| 3 | Job goal, non-goals, criteria, and output contract | Exact and pinned |
| 4 | Current state, diff, commitments, and dependencies | Exact or structural capsule |
| 5 | Verified evidence and claims | Extractive or verified evidence-carrying summary |
| 6 | Decisions, alternatives, assumptions, conflicts, open questions | Structured capsule; uncertainty preserved |
| 7 | Procedures, skills, examples, tools, and schemas | On-demand and target-specific |
| 8 | Coordination, handoff, verification, and completion state | Structured capsule |
| 9 | Untrusted content | Delimited data; never promoted |

Lane minimums, maximums, mandatory selectors, and loss classes are part of the plan and manifest.

## **10.4 Budget arithmetic**

usable\_input \= total\_input\_tokens  
             \- reserved\_runtime\_tokens  
             \- reserved\_output\_tokens  
             \- safety\_margin  
             \- materializer\_fixed\_overhead

Retrieval may use conservative token estimates. Final packing uses exact tokenizer counts. An estimator-only target must declare an error bound and cannot claim hard compliance unless the safety margin covers the measured worst case.

Mandatory closure is computed before optional packing. Dependency tokens are charged to the candidate that introduces them and become shared when later candidates reuse the same dependency.

## **10.5 Packing algorithm**

Candidate representation i has integer marginal gain:

gain(i | S) \= relevance(i)  
            \+ Wreq \* new\_requirement\_coverage(i, S)  
            \+ Went \* new\_entity\_coverage(i, S)  
            \+ Wdiv \* source\_diversity(i, S)  
            \- Wred \* maximum\_similarity(i, S)  
            \- Wdep \* new\_dependency\_tokens(i, S)  
            \- Wloss \* information\_loss(i)  
   
priority(i | S) \= gain(i | S) / max(1, incremental\_tokens(i | S))

Fractions compare through checked cross multiplication. At most one representation variant of a logical item is selected. The algorithm:

1. Inserts mandatory closure.  
2. Satisfies lane and category minima.  
3. Maintains a deterministic priority queue keyed by current marginal value.  
4. Recomputes stale marginal entries when popped.  
5. Selects feasible positive-gain variants.  
6. Runs a fixed-iteration local swap considering one selected item versus at most two alternatives.  
7. Stops at profile iteration cap or no positive improvement.

The test oracle brute-forces small candidate sets and verifies the heuristic never violates constraints and meets the published approximation floor for those fixtures.

## **10.6 Conflict handling**

Candidates describing the same operational state are grouped through typed subject/predicate keys. Resolution order is explicit supersession, world-valid time, transaction time, source authority, verification, scope specificity, and current source revision.

If conflict remains:

* Governing policy or exact task-state conflict returns UNRESOLVED\_CRITICAL\_CONFLICT unless the contract defines a human resolution step.  
* Evidence conflict produces a ConflictBlock containing alternatives, support, authority, timestamps, and operational warning.  
* A transform cannot merge contradictory claims into one statement.

## **10.7 Representation transforms**

* SpanExtract: exact bytes or lines plus bounded context.  
* SymbolCapsule: signature, documentation, relevant constants, direct dependencies, selected implementation, tests, and source ranges.  
* DiffCapsule: base and head, hunks, enclosing symbols, rename evidence, and affected tests.  
* FactTable: canonical fields with provenance per row.  
* DecisionCapsule: decision status, supporting and rejecting evidence, alternatives, assumptions, questions, and supersession.  
* CheckpointCapsule: goal, criteria, completed work, current state, validation, blockers, next actions, and effect cursor.

The default compile path makes no model call. A generative summary is eligible only as a pre-existing derived atom with complete source lineage, transform and model fingerprint, validation receipt, policy permission, and validity bounded by every dependency.

## **10.8 Manifest**

The full manifest stores all plan inputs, component fingerprints, stage queries, candidate references, feature vectors, policy dispositions, conflicts, representation alternatives, dependencies, transformations, selection and exclusion reason, exact token costs, baseline estimates, degraded status, and revalidation condition.

Stable reason codes include MANDATORY, REQUIREMENT\_COVERAGE, DEPENDENCY, HIGH\_UTILITY, DIVERSITY, UNAUTHORIZED, OUT\_OF\_SCOPE, STALE, SUPERSEDED, QUARANTINED, DUPLICATE, CONFLICT\_LOSER, UNSUPPORTED\_PROCESSOR, BUDGET\_PRUNED, LOW\_MARGINAL\_UTILITY, and MODALITY\_MISMATCH.

An explanation view reruns disclosure policy. /cigar:why can answer why an item was selected, why an authorized alternative was omitted, what was compressed, which constraints consumed budget, which conflicts remain, which indexes were stale, and what invalidates the result.

# **11\. Materialization, caching, deltas, and token accounting**

## **11.1 Materializer contract**

pub trait Materializer: Send \+ Sync {  
    fn profile(\&self) \-\> MaterializerProfile;  
    fn fixed\_overhead(\&self, target: \&TargetProfile) \-\> TokenCost;  
    fn tokenize(\&self, blocks: &\[SemanticBlock\], target: \&TargetProfile)  
        \-\> Result\<ExactTokenReport\>;  
    fn materialize(\&self, bundle: \&ContextBundle, target: \&TargetProfile)  
        \-\> Result\<MaterializedContext\>;  
    fn validate(\&self, output: \&MaterializedContext) \-\> Result\<()\>;  
}

Required materializers are canonical JSON, Markdown human brief, Claude structured prompt and MCP resource, and a generic structured fact set. A materializer cannot drop a semantic block, merge authority lanes, or truncate. It requests recompile with a different target profile when framing cannot fit.

## **11.2 Provider-present set**

Adapters maintain a content-addressed set of blocks already known to be present in the consumer context, with acquisition source, provider session, first and last observation, validity, and confidence. Successful CIGAR expansion, file reads observed through documented hooks, and injected blocks update the set.

The compiler may omit a present optional block and emit a handle, but it cannot assume provider retention beyond the adapter's documented model. Compaction, session clear, target change, or uncertain retention invalidates the applicable set.

## **11.3 Cache layers**

* Atom parse and symbol cache keyed by source digest and parser fingerprint.  
* Transform cache keyed by exact source versions, transform configuration, processor, policy, and verifier.  
* Retrieval cache keyed by authorized partition, snapshot, index fingerprint, and query.  
* Plan cache keyed by normalized contract, policy, compiler profile, target, and watermarks.  
* Bundle cache keyed by complete plan fingerprint and snapshot.  
* Materialization cache keyed by bundle, target, tokenizer, materializer, and framing configuration.

Every cache hit rechecks current revocation and policy eligibility. Sensitive cache entries remain tenant and disclosure-domain isolated. Cache corruption is detected by digest and falls back to recomputation.

## **11.4 Delta compilation**

Delta compilation verifies the base bundle and reuses only blocks whose atoms, policy decisions, dependencies, transforms, target profile, and tokenizer remain valid. It produces ordered additions, removals, and replacements plus the new full bundle ID and manifest.

Applying the delta to the canonical base blocks MUST reproduce the new digest. Base mismatch returns DELTA\_BASE\_MISMATCH; no fuzzy application occurs. Adapters acknowledge applied deltas so present-state accounting is auditable.

## **11.5 Token accounting**

Every materialization records:

* Named and versioned baseline.  
* Exact physical input tokens.  
* Stable-prefix tokens.  
* Delta tokens.  
* Deduplicated, extractively reduced, structurally reduced, summarized, and omitted-present tokens.  
* Provider cache-write and cache-read counts when reported.  
* Output and runtime reserve.  
* Estimated and actual provider cost when pricing is configured.

Physical reduction is calculated separately from cache discount. Provider usage is authoritative for cost but not for semantic bundle token counts unless the provider tokenizer is the selected exact tokenizer.

# **12\. Context spaces and handoff protocol**

## **12.1 Context hierarchy**

The hierarchy is tenant, workspace, project, branch or worktree, task, session, and agent overlay. A view is an immutable base commit plus at most one private overlay. Attaching context visibility never grants filesystem, network, tool, or effect authority.

ContextCommit contains space, sequence, parent, author, purpose, ordered events, resulting root digest, policy snapshot, and timestamp. Publication uses expected\_head. Current head and all history are immutable.

## **12.2 Overlays and merge**

Agents write proposed atoms, decisions, state, and artifacts to a private overlay. Publishing performs a three-way merge against base and current head:

* Independent additions merge.  
* Identical semantic versions deduplicate.  
* Task progress merges only when steps and artifacts do not conflict.  
* Instructions, decisions, capabilities, leases, and effect state require exact-base or typed resolution.  
* Conflicts retain base, left, right, evidence, and required resolver.

No semantic last-writer-wins exists. An overlay can be discarded without mutating canonical history.

## **12.3 Multi-project federation**

Contracts list exact project IDs and relation intent. Default compile includes only the active project. Cross-project relations are explicit and directional. Per-project contribution caps prevent a large dependency repository from crowding out active-project context, except for mandatory dependencies.

cigar project link shows a disclosure preview and relation. cigar project attach changes context eligibility only. The host product separately grants file or tool access.

## **12.4 Handoff creation**

1. Resolve issuer, task branch, snapshot, checkpoint, current bundle, and effect cursor.  
2. Validate recipient selector, role, task, criteria, projects, requested capabilities, budget, topics, expiry, and audience.  
3. Compute issuer\_effective ∩ requested ∩ handoff\_policy; list rejected capability requests.  
4. Create source, state, decision, artifact, uncertainty, and effect references; exclude unrestricted transcript and raw secrets.  
5. Generate disclosure preview and policy decision.  
6. Canonically encode and sign capsule with nonce, issuer key, audience, expiry, and protocol version.  
7. Persist capsule and HandoffCreated event.

## **12.5 Acceptance**

1. Verify schema, digest, signature, key status, nonce, audience, recipient, expiry, and revocation.  
2. Intersect delegated grants with actual recipient and current policy.  
3. Reauthorize every source, project, processor, and effect capability.  
4. Mark inaccessible references without disclosing content.  
5. Compile recipient-specific bundle under its target and budget.  
6. Persist acceptance receipt with accepted and rejected scope, unavailable sources, policy, bundle, and acknowledgement.  
7. Subscribe only to declared topics and invalidations.

Replay protection stores nonce and reusable or one-time semantics. Acceptance never treats signature validity as authorization.

## **12.6 Child result**

HandoffDelta contains base snapshot, producer, claims with evidence, decisions and alternatives, artifacts, source changes, verifier receipts, unresolved questions, blockers, effect references, and requested follow-up capabilities. Parent merge reauthorizes content and validates base revisions. Child prose cannot directly mutate canonical decisions or instructions.

## **12.7 Coordination events**

Required events are ContextCommitted, AtomInvalidated, BundleInvalidated, TaskCheckpointed, HandoffCreated, HandoffAccepted, HandoffRevoked, AgentResultProposed, MergeConflictCreated, EffectStateChanged, and PolicySnapshotChanged. Delivery is at least once; consumers deduplicate by event ID and resume from a persisted cursor.

# **13\. Effect journal, connectors, and replay**

## **13.1 Effect states**

PREPARED  
  \-\> PENDING\_APPROVAL \-\> AUTHORIZED  
  \-\> AUTHORIZED  
  \-\> REJECTED | EXPIRED | CANCELLED  
AUTHORIZED \-\> DISPATCHING  
DISPATCHING \-\> SUCCEEDED | FAILED | UNKNOWN  
UNKNOWN \-\> SUCCEEDED | FAILED | AUTHORIZED\_FOR\_RETRY | MANUAL\_RESOLUTION  
SUCCEEDED \-\> COMPENSATION\_PENDING \-\> COMPENSATING  
COMPENSATING \-\> COMPENSATED | COMPENSATION\_FAILED | UNKNOWN

Only the transition table in cigar-effects changes state. Every transition checks expected state, effect version, actor, capability, policy, freshness, approval, lease, and connector constraints. It appends a hash-chained event in the same transaction as the current projection.

## **13.2 Effect intent and approval**

Intent includes connector, operation, normalized arguments digest, encrypted arguments reference, target, preconditions, result schema, risk, source decision and bundle, capability, idempotency scope and key, retry policy, expiry, and optional compensation. Preparation performs no external action.

Approval binds effect ID, intent digest, target, risk, bundle, conditions, limits, approver, and expiry. Any semantic change requires a new intent digest. Agent-to-agent messages cannot satisfy a human-required approval.

## **13.3 Connector interface**

\#\[async\_trait\]  
pub trait EffectConnector: Send \+ Sync {  
    fn descriptor(\&self) \-\> ConnectorDescriptor;  
    fn normalize(\&self, operation: \&str, arguments: CanonicalValue)  
        \-\> Result\<NormalizedEffect\>;  
    async fn check\_preconditions(\&self, ctx: \&EffectContext)  
        \-\> Result\<PreconditionReport\>;  
    async fn dispatch(\&self, ctx: \&DispatchContext)  
        \-\> Result\<DispatchObservation\>;  
    async fn reconcile(\&self, ctx: \&ReconcileContext)  
        \-\> Result\<ReconcileObservation\>;  
    async fn compensate(\&self, ctx: \&CompensationContext)  
        \-\> Result\<DispatchObservation\>;  
}

The descriptor declares operations, schemas, idempotency, lookup, verification, compensation, timeouts, classifications, and requested capabilities. Connector code never decides CIGAR authorization.

## **13.4 Dispatch algorithm**

1. Compare-and-swap AUTHORIZED to DISPATCHING and allocate attempt and fencing token.  
2. Append journal event and persist request digest; commit before remote call.  
3. Check connector preconditions if not already bound.  
4. Call connector with deadline, cancellation, idempotency key, and trace context.  
5. Store protected response and transition to succeeded, failed, or unknown in a new transaction.  
6. Treat timeout, connection reset after possible send, process crash, invalid response, or receipt failure as unknown unless non-execution is proven.  
7. Reconcile through remote operation ID, idempotency record, target postcondition, or audit API.  
8. Permit automatic redispatch only when same-key remote idempotency guarantees safety or reconciliation proves non-execution.

The outbox wakes workers but is not semantic authority. Worker at-least-once execution cannot create another logical effect because normalized idempotency scope and key are unique.

## **13.5 Reference connectors**

* demo-issue-service: local HTTP service with idempotency, status lookup, controlled delay, disconnect, lost response, crash, and compensation.  
* filesystem: restricted-root atomic write connector with expected digest, temp-file flush, atomic rename, and receipt.  
* http-idempotent: schema-configured HTTP operations requiring idempotency header and reconciliation endpoint.  
* github-issues: issue create or update with normalized repository, operation, correlation marker, GitHub receipt, and lookup. Live tests are opt-in.

Arbitrary shell commands remain observed or unverified and never receive a universal exactly-once claim.

## **13.6 Decision records**

Decision capture stores observable task, plan, bundle, materialization, runtime and consumer fingerprints, output artifacts, asserted claims, evidence, uncertainty, verification, effects, usage, timing, and outcome. Hidden chain-of-thought is neither requested nor stored.

## **13.7 Replay modes**

* Evidence reproduction verifies all source, blob, policy, index, manifest, and bundle digests.  
* Invocation reproduction reconstructs exact consumer input, tools, parameters, and declared environment without invoking.  
* Observational replay substitutes recorded model, tool, connector, and effect observations and forbids egress.  
* Live rerun invokes configured dependencies under an explicit flag. Effects remain simulated unless new effect intents are separately authorized.

ReplayDiff compares semantic context, materialization, components, output claims, verification, effect plan, and observations in separate fields. Provider variance is not reported as compiler nondeterminism.

# **14\. Daemon, APIs, authentication, and operations**

## **14.1 Runtime composition**

cigard composes store, blobs, indexes, catalog, policy, compiler, spaces, effects, replay, API, auth, and telemetry. It owns bounded worker pools for ingestion, indexing, invalidation, compilation, outbox, reconciliation, lease cleanup, backup, and GC.

No channel is unbounded. Every queue publishes capacity, depth, oldest age, rejection count, and overflow policy. CPU parsing and tokenization run in a bounded blocking pool. Request cancellation stops nondurable work but cannot undo committed journal state.

## **14.2 Local authentication**

Local mode uses a permission-restricted Unix socket where available. Windows uses a named pipe with user ACL. Loopback TCP fallback requires a random file-protected bearer token and never binds all interfaces by default. Project roots and local user identity are resolved server-side.

## **14.3 Shared authentication**

Shared mode requires TLS, OIDC JWT validation, audience and issuer pinning, bounded JWKS refresh, clock-skew limit, and optional service mTLS. Auth maps to a CIGAR principal; semantic authorization still occurs in services. Algorithm confusion, missing audience, unsigned tokens, excessive token size, expired keys, and tenant-claim mismatch are negative tests.

## **14.4 HTTP and gRPC conventions**

* HTTP base /v1; Protobuf package cigar.v1.  
* Mutations require Idempotency-Key; revisioned mutations require If-Match or expected revision.  
* Immutable records return semantic ETags.  
* Lists use bounded page size and opaque signed cursor pinned to snapshot and query.  
* Streams use gRPC server streaming and SSE with Last-Event-ID.  
* Requests accept deadline and trace context; server limits override client values.  
* HTTP uses application/problem+json with stable generated errors.  
* Protobuf and OpenAPI behavior is verified by differential contract tests.  
* Request decompression has compressed-size, expanded-size, and ratio limits.

## **14.5 Required routes**

| Route family | Operations |
| :---- | :---- |
| Catalog | discover, ingest, source status, atom batch, query, tombstone |
| Context | plan, compile bundle, compile delta, fetch, explain, revalidate, materialize |
| Spaces | create, fork, publish, log, events, checkpoint, merge conflict |
| Handoffs | create, preview, accept, revoke, result, merge |
| Effects | prepare, authorize, dispatch, status, reconcile, compensate |
| Replay | reconstruct, observational run, live compare, completeness |
| Operations | live, ready, version, capabilities, config summary, diagnostics, metrics |

All service operations also have internal typed facades used by embedded mode.

The v1 HTTP contract SHALL expose exactly the following operation paths. Generated OpenAPI operation IDs SHALL equal the corresponding Protobuf RPC names in lower camel case. Adding aliases or alternate spellings is a compatibility change and is not permitted during v1 implementation.

POST /v1/sources:discover  
POST /v1/catalog:ingest  
GET  /v1/catalog/sources/{source\_id}  
POST /v1/catalog:query  
POST /v1/catalog/atoms:batch  
POST /v1/catalog/atoms/{atom\_id}:tombstone  
   
POST /v1/context/plans  
POST /v1/context/bundles:compile  
POST /v1/context/deltas:compile  
GET  /v1/context/bundles/{bundle\_id}  
GET  /v1/context/bundles/{bundle\_id}/manifest  
POST /v1/context/bundles/{bundle\_id}:explain  
POST /v1/context/bundles/{bundle\_id}:materialize  
POST /v1/context/bundles/{bundle\_id}:revalidate  
   
POST /v1/spaces  
POST /v1/spaces/{space\_id}:fork  
POST /v1/spaces/{space\_id}:publish  
GET  /v1/spaces/{space\_id}/log  
GET  /v1/spaces/{space\_id}/events  
POST /v1/spaces/{space\_id}/checkpoints  
GET  /v1/spaces/{space\_id}/conflicts  
POST /v1/spaces/{space\_id}/conflicts/{conflict\_id}:resolve  
   
POST /v1/handoffs  
POST /v1/handoffs/{handoff\_id}:preview  
POST /v1/handoffs/{handoff\_id}:accept  
POST /v1/handoffs/{handoff\_id}:revoke  
POST /v1/handoffs/{handoff\_id}/results  
POST /v1/handoffs/{handoff\_id}:merge  
   
POST /v1/effects  
POST /v1/effects/{effect\_id}:authorize  
POST /v1/effects/{effect\_id}:dispatch  
GET  /v1/effects/{effect\_id}  
POST /v1/effects/{effect\_id}:reconcile  
POST /v1/effects/{effect\_id}:compensate  
   
POST /v1/replays  
POST /v1/replays/{replay\_id}:run  
POST /v1/replays/{replay\_id}:compare  
GET  /v1/replays/{replay\_id}/completeness  
   
GET  /livez  
GET  /readyz  
GET  /v1/version  
GET  /v1/capabilities  
GET  /v1/configuration  
GET  /v1/diagnostics  
GET  /metrics

For every mutation, the HTTP binding, Protobuf request, SDK method, CLI JSON envelope, audit event, and error catalog SHALL share one generated operation identifier. The contract tests SHALL enumerate the list above and fail on a missing route, undocumented route, divergent request field, incompatible status mapping, or operation lacking an embedded service equivalent.

## **14.6 Health and readiness**

/livez checks process progress only. /readyz checks metadata store, expected migration level, blob read/write probe, policy snapshot, critical journal integrity, mandatory index health and lag, key provider, and worker heartbeat. It returns structured component status and never protected content.

## **14.7 Graceful shutdown and recovery**

Shutdown stops new requests, drains bounded reads and compiles, prevents new dispatch claims, checkpoints workers, releases renewable leases, flushes telemetry within deadline, and exits. Dispatching effects without receipt remain recoverable as unknown. Startup performs migrations, journal transition validation, orphan blob reconciliation, expired lease cleanup, and worker cursor verification before readiness.

## **14.8 Resource controls**

Per-tenant and global limits cover request concurrency, source bytes, atom count, query stages, candidate count, graph expansions, compile CPU, tokenization CPU, transform output, event subscriptions, outstanding effects, and blob bandwidth. Tower middleware enforces timeouts and body limits; semantic services enforce domain limits again.

## **14.9 Extension host and stable extension boundary**

The extension host makes replaceable behavior modular without allowing extension code to redefine CIGAR identities, authorization, state transitions, or journal semantics. Supported extension kinds are SourceConnector, Atomizer, Retriever, RankingFeature, Transform, SummaryVerifier, Tokenizer, Materializer, PolicyProvider, StorageBackend, EffectConnector, and Reconciler. Built-in extensions MAY link in-process. Third-party extensions MUST execute as a WASI Preview 2 component or as an isolated subprocess using length-delimited canonical CBOR over restricted standard I/O. A remote gRPC extension is permitted only in shared deployments and uses the same logical ABI.

An ExtensionManifestV1 contains extension ID and version, protocol ABI range, implementation digest, package digest, publisher key and signature, entry point, extension kinds, input and output schema digests, declared source classifications, declared processors, deterministic or nondeterministic flag, required host capabilities, network allowlist, filesystem preopens, maximum memory, fuel or CPU time, wall deadline, input and output bytes, concurrency, and compatible CIGAR versions. The manifest itself is canonicalized and signed. The host verifies signature, package digest, ABI range, schemas, capability compatibility, and resource limits before activation.

Third-party extensions start with no ambient filesystem, environment, clock, randomness, credential, process, or network authority. Host calls expose only opaque source and blob handles, bounded iterators, a deterministic clock and random source when requested, structured tracing, cancellation, and the minimum data authorized for that invocation. Plaintext is copied into an extension only when its manifest, source policy, processor constraints, and current compile authorization all permit it. Secrets are never materialized into an extension unless the extension kind and operation explicitly require a secret handle; the host resolves that handle at the final outbound boundary.

The host terminates an extension that exceeds fuel, memory, deadline, output, recursion, or concurrency limits and returns a typed error containing no protected payload. Read-only calls MAY retry according to declared idempotency. A transform, source write, storage mutation, or effect dispatch is never automatically retried unless its operation contract proves same-key safety. A crash cannot advance a CIGAR state machine because only the trusted host commits catalog, space, compiler, or effect transitions.

Deterministic extensions MUST pass the published vector suite under repeated process launches, locale and timezone changes, randomized host scheduling, and every Tier 1 architecture. Their declared semantic output participates in the enclosing CIGAR digest. Nondeterministic extensions emit an observation record whose digest, inputs, implementation, execution limits, and output become explicit replay dependencies. Package tests include invalid signature, digest substitution, ABI confusion, schema bomb, oversized frame, path traversal, forbidden preopen, environment leak, network escape, fork or subprocess attempt, infinite loop, memory growth, output flood, cancellation race, and crash-after-response cases.

# **15\. CLI and SDK implementation**

## **15.1 CLI surface**

cigar init  
cigar source add | list | refresh | inspect | remove  
cigar ingest  
cigar status  
cigar context plan | compile | explain | diff | revalidate | materialize  
cigar project list | attach | detach | switch | link | unlink  
cigar focus new | switch | checkpoint | close  
cigar space fork | publish | log | conflicts  
cigar handoff create | preview | inspect | accept | revoke | merge  
cigar effect prepare | approve | dispatch | list | inspect | reconcile | compensate  
cigar replay reconstruct | run | compare | completeness  
cigar policy check | explain  
cigar backup create | verify | restore  
cigar gc plan | run  
cigar doctor \[--security\]  
cigar serve  
cigar mcp serve

Every command supports \--output text|json, \--deadline, \--config, and explicit local, embedded, or remote target. JSON output is versioned. Mutating and destructive commands support dry run. Non-interactive mode never prompts and requires explicit confirmation flags or authorization material.

## **15.2 CLI UX requirements**

* Errors lead with stable code and actionable remediation.  
* Progress is disabled when output is not a terminal or \--quiet is used.  
* Color is optional and never the only status signal.  
* Tables have a machine-readable equivalent.  
* Secret values never echo.  
* doctor provides component status, compatibility, index lag, stuck or unknown effects, and exact next commands.  
* Shell completion and man pages are generated and tested.

## **15.3 Rust SDK**

The Rust SDK exposes embedded builders and daemon clients behind parallel async interfaces. Builders require explicit storage and policy profiles and return validation errors before starting workers. Public traits are object-safe where extension use requires it. Semantic types reuse cigar-protocol directly.

## **15.4 TypeScript SDK**

The package ships ESM, declarations, source maps, generated wire types, high-level client, AsyncIterable streams, abort signals, typed error classes, idempotency helpers, bundle and delta validation, and local digest verification. It targets maintained Node LTS releases and uses no postinstall binary download.

## **15.5 Python SDK**

The package ships wheels and source distribution, py.typed, generated models, async client, synchronous facade, context managers, iterators for streams, typed errors, idempotency helpers, and local digest verification. Network clients use bounded timeouts and never retry unsafe mutations automatically.

## **15.6 Go SDK**

The Go module includes generated Protobuf and HTTP clients, idiomatic context cancellation, typed errors, streaming channels or iterators with explicit close, digest verification, and examples. Public records do not expose mutable maps without copy or canonical ordering helpers.

## **15.7 SDK parity**

One machine-readable capability manifest lists every operation and type per SDK. Cross-language tests create and hash contracts, call local and shared profiles, compile and fetch bundles, apply deltas, accept handoffs, follow an effect through reconciliation, and reconstruct replay. Documentation generation fails if parity is incomplete.

# **16\. Claude Code reference adapter**

## **16.1 Packaging**

The adapter ships as a user-scoped plugin:

adapters/claude-code/  
  .claude-plugin/plugin.json  
  .mcp.json  
  hooks/hooks.json  
  compatibility.json  
  skills/  
  agents/  
  README.md  
  tests/

The compiled cigar-claude-hook binary and cigar mcp serve command come from signed CIGAR packages. The plugin does not download executable code after installation.

## **16.2 Installation**

cigar plugin install claude-code previews files and capabilities, checks the Claude Code version against compatibility.json, installs at user scope, verifies daemon and MCP handshake, validates hook schemas, and runs a no-op compile. \--dry-run makes no change. Uninstall removes adapter files but not portable catalog data.

## **16.3 MCP surface**

Tools are context\_compile, context\_expand, context\_explain, catalog\_query, checkpoint\_create, handoff\_create, handoff\_accept, effect\_prepare, effect\_commit, and effect\_status. Resources use stable cigar://project, workspace, task, decision, bundle, handoff, effect, and artifact URIs.

Descriptions and server instructions remain under 2 KiB. Default outputs are 500–4,000 tokens and paginate. Large data returns a handle. Every result identifies snapshot, bundle or source, expiry, degraded status, and authority lane.

## **16.4 Hook executable**

The hook reads one documented JSON event from stdin under a strict byte limit, validates schema, calls cigard with a short deadline, and writes one documented response to stdout. Structured redacted diagnostics go to stderr. Duplicate hook events return the original result using session, event, and payload digest idempotency.

Supported events include session start and end, user prompt, instructions loaded, tool before and after, tool failure and batch, subagent start and stop, task creation and completion, compaction before and after, directory change, worktree lifecycle, stop, and stop failure.

UserPromptSubmit uses deterministic task-boundary rules, compiles a delta, and injects no identical block twice. It makes no model call by default. Context augmentation failure fails open with a visible bounded marker. Governed effect precheck follows configured fail-closed policy.

## **16.5 Token behavior**

* Default startup bootstrap is at most 500 tokens.  
* Project reference content stays in the catalog, not plugin skills or startup instructions.  
* Stable policy and project blocks form a cache-aligned prefix.  
* Tool results and logs are stored by handle with bounded summaries.  
* Compaction stores a structured checkpoint and recompiles current state afterward.  
* Subagents receive recipient-specific handoffs rather than the parent transcript.  
* Cost reporting separates physical tokens, cache writes, cache reads, and outcome metrics.

## **16.6 Adapter limitations presented to users**

The adapter cannot guarantee effects hidden inside arbitrary shell commands, remove large built-in tool output already in the provider context, or make provider output deterministic. Host filesystem and tool permissions remain separate. Compatibility uses documented public hooks and MCP; private session files are not a dependency.

## **16.7 Claude adapter acceptance**

* Installation and uninstall pass on every supported platform.  
* Session, prompt, tool, subagent, task, compaction, directory, worktree, stop, and end fixtures pass.  
* Prompt hook p95 is at most 150 ms warm and p99 at most one second.  
* No default prompt-hook model call occurs.  
* Bootstrap remains at most 500 tokens.  
* Duplicate event and duplicate injection tests pass.  
* Adapter failure leaves Claude usable and visibly degraded.  
* Recognized mediated effects authorize before execution.  
* Every injection is inspectable through /cigar:why.

# **17\. Product demos and executable examples**

Every demo is a release test, not a slide or unverified transcript. It includes fixture data, deterministic seed, recorded consumer mode, optional live mode, setup, expected output, assertions, teardown, and CI smoke command.

## **17.1 Demo 1: offline context compiler**

Fixture: a realistic repository with 100 or more files, architecture decisions, stale alternatives, tests, issue excerpts, and distractors.

Flow:

1. Initialize and preview eligible sources.  
2. Ingest without network or embeddings.  
3. Compile a bug-fix contract.  
4. Show lanes, selected spans, conflicts, exact tokens, and provenance.  
5. Modify one source and compile a delta.  
6. Explain additions, removal, replacement, and token reduction.

Assertions: deterministic bundle digest, strong index watermark, no stale superseded decision, 100% selected provenance, correct delta application, and at least 40% physical reduction against the fixture full-project baseline.

## **17.2 Demo 2: multi-project isolation and focus switching**

Workspace contains checkout-web, payments-api, ledger-service, and a forbidden hr-private project with overlapping names. The user links permitted dependencies, switches among three task branches, and resumes the first.

Assertions: unattached and forbidden projects never enter candidates or caller-visible counts; task-specific old detail disappears on focus switch; resumed task recompiles against current state; filesystem authority remains unchanged.

## **17.3 Demo 3: multi-agent handoff**

A parent delegates read-only test research and security review to two deterministic child consumers. Each receives distinct scopes and capabilities, returns evidence-backed typed results, and merges through optimistic revision. One child attempts to access a forbidden project and request write capability.

Assertions: denied access reveals no source details; grant attenuation rejects write; recipient packages are at most 20% of parent transcript baseline; first action is useful; results merge as claims, artifacts, uncertainty, and verification rather than transcript.

## **17.4 Demo 4: effect crash recovery**

The local issue service injects failures before dispatch, after durable dispatch state before send, after remote acceptance before receipt persistence, during response parse, and during reconciliation.

Assertions: prepared intent precedes every send; possible remote commit becomes unknown; restart recovers journal; same idempotency key produces one logical mutation; non-idempotent unknown blocks automatic retry; compensation is a new linked effect.

## **17.5 Demo 5: cross-runtime replay**

Compile one semantic bundle, materialize for two adapters, run a deterministic fake consumer, capture decision, and reproduce through another SDK.

Assertions: semantic bundle digest is identical; target materialization differences are expected and recorded; evidence reproduction is exact; observational replay performs no network or connector call; live comparison creates a separate execution.

## **17.6 Demo 6: prompt-injection defense**

Fixture documents contain hostile instructions, fake policy blocks, hidden prompt text, and exfiltration requests. One approved project instruction exists at the correct authoritative path.

Assertions: hostile content remains untrusted evidence, cannot grant tools or become instructions, never exposes secret fixtures, and appears in explanation only under permitted disclosure. The approved instruction remains exact and mandatory.

## **17.7 Demo 7: Claude Code experience**

Recorded hook and MCP fixtures simulate install, session start, task prompt, context delta, file reads, subagent handoff, compaction, resume, effect prepare, and session end. An optional live script runs when Claude Code and credentials are present.

Assertions: bootstrap and delta budgets, no duplicate injection, bounded MCP output, correct checkpoints, explicit degraded marker, user-inspectable manifest, and safe uninstall.

## **17.8 SDK quickstarts**

Rust embedded, TypeScript daemon, Python async, and Go gRPC examples all ingest the same fixture, compile the same contract, verify bundle digest, and inspect a manifest. CI compares output identities and runs each quickstart from a clean package install.

# **18\. Verification architecture and testability**

## **18.1 Release claims require executable evidence**

Unit coverage is necessary but insufficient. Every critical invariant requires a golden or contract test, a negative or adversarial test, a property or model test, and—when persistence, IPC, concurrency, or effects are involved—a real process-boundary fault test.

Tests are organized by semantic invariant rather than source directory. tests/invariants.yaml maps each invariant and normative requirement to test IDs, fixtures, profiles, release thresholds, and resulting evidence files. CI fails an unmapped requirement or nonexistent, skipped, or quarantined referenced test.

## **18.2 Required testability interfaces**

Before a component is feature-complete, it supports:

* Injected Clock, IdSource, RandomSource, Tokenizer, PolicyEngine, BlobStore, IndexBackend, Transport, and connector I/O.  
* Deterministic mode fixing clock, IDs, seed, locale, timezone, Unicode behavior, tokenizer, map order, watermarks, and tie breaking.  
* CompilationInputs containing every semantic dependency; no environment singleton may affect a digest.  
* A failpoints feature compiled out of release binaries and enumerated by cigar-testkit.  
* Structured in-memory test events at transactions, state transitions, cache lookups, queries, policies, transforms, materialization, dispatch, and reconciliation.  
* Temporary homes, repositories, key stores, sockets, databases, and blob roots. Tests cannot access the developer's real CIGAR or Claude state.  
* Subprocess crash harness using process kill, not only panic.  
* Deterministic fake remote service that commits, delays, drops, duplicates, reorders, lies, and reconciles under controlled modes.  
* Injected deny transport and OS-level no-egress test isolation.  
* Stable versioned JSON output for every user-visible operation.

## **18.3 Verification repository**

tests/  
  invariants.yaml  
  vectors/  
  fixtures/  
    catalogs/ repositories/ policies/ tokenizers/  
    handoffs/ effects/ replay/ attacks/ migrations/  
  contract/  
  integration/  
  e2e/  
  security/  
  migration/  
  chaos/  
  compatibility/  
  installation/  
conformance/  
  runner/ profiles/ vectors/ expected/  
fuzz/  
  fuzz\_targets/ corpus/ dictionaries/  
benches/  
  micro/ macro/ cigarbench/ baselines/ thresholds/  
reports/                         \# ignored locally; CI artifact output

cigar-testkit provides deterministic builders, fake time and IDs, in-memory policy and indexes, connectors, event recorder, canary scanner, subprocess crash controller, fixture loader, semantic assertions, and conformance client. Production crates include it only as a development dependency.

## **18.4 Fixture manifest**

Every fixture directory includes fixture.toml with:

* Fixture ID and semantic version.  
* Source revision and expected snapshot digest.  
* Fixed time, ID seed, random seed, locale, timezone, and Unicode form.  
* Schema, tokenizer, policy, parser, index, compiler, transform, and materializer fingerprints.  
* Permitted, prohibited, mandatory, stale, contradicted, and secret-canary atoms.  
* Expected reason codes and tokens by materializer.  
* Expected bundle, manifest, delta, handoff, decision, and journal digests.  
* Expected external calls, with none explicit.  
* Minimum implementation and compatibility behavior.

Published golden vectors are immutable. An intentional semantic change creates a new version and difference.json; it never modifies a released digest in place. The update command requires CIGAR\_ALLOW\_VECTOR\_UPDATE=1, emits a semantic diff, and fails unnamed changes.

## **18.5 Synthetic corpus requirements**

Fixtures cover overlapping symbols across projects, Unicode normalization and confusables, newline and case differences, symlinks, executable bits, nested ignore rules, generated and vendored content, large binaries, sparse files, exact constraints, stale and superseded decisions, temporal corrections, prompt injection in every source field, synthetic secrets, corrupt serialization, parser bombs, deep nesting, duplicate keys, invalid UTF-8, decompression bombs, cyclic graphs, and every connector capability combination.

Secret canaries are registered with the scanner. They must never appear in materialization, embedding requests, traces, logs, errors, crash reports, journal plaintext, temporary files, package contents, or network capture.

## **18.6 Test command inventory**

cargo xtask is authoritative; just exposes equivalent short aliases.

| Suite | Command | Trigger | Target duration | Release blocking |
| :---- | :---- | :---- | :---- | :---- |
| Format and generation drift | cargo xtask fmt \--check && cargo xtask generate \--check | Every change | 2 min | Yes |
| Rust lint and docs | cargo xtask lint rust && cargo xtask docs \--check | Every change | 5 min | Yes |
| SDK lint and type | cargo xtask lint sdks | Every change | 5 min | Yes |
| Unit | cargo xtask test unit | Every change | 8 min | Yes |
| Canonical vectors | cargo xtask test vectors | Every change | 4 min | Yes |
| Schema compatibility | cargo xtask test compatibility \--schema | Every change | 4 min | Yes |
| Changed integration | cargo xtask test integration \--changed | Every change | 10 min | Yes |
| Full integration | cargo xtask test integration | Merge/nightly | 30 min | Yes |
| Conformance | cargo xtask test conformance | Merge/nightly | 20 min | Yes |
| End-to-end demos | cargo xtask test e2e | Merge/nightly | 30 min | Yes |
| Security negatives | cargo xtask test security | Merge/nightly | 30 min | Yes |
| Fuzz smoke | cargo xtask fuzz smoke | Affected change | 10 min/shard | Yes |
| Extended fuzz | cargo xtask fuzz nightly | Nightly | 2 CPU-hours/target | Any crash blocks |
| Sanitizers and Miri | cargo xtask test sanitizers | Nightly | 90 min | Yes |
| Concurrency models | cargo xtask test models | Nightly | 60 min | Yes |
| Mutation | cargo xtask test mutations | Weekly/RC | 4 h | Threshold |
| Chaos and crash | cargo xtask test chaos | Nightly/RC | 2 h | Yes |
| Microbench | cargo xtask bench micro \--verify | Merge | 20 min | Regression |
| Macro and scale | cargo xtask bench macro \--verify | Nightly/RC | 2 h | Yes |
| CIGARBench | cargo xtask bench efficacy | Scheduled/RC | Workload-specific | Yes |
| Package smoke | cargo xtask package \--smoke | RC | 60 min/target | Yes |
| Reproducibility | cargo xtask release reproduce | RC | Two builds/target | Yes |
| Offline and no-egress | cargo xtask test offline | Nightly/RC | 20 min | Yes |
| Upgrade matrix | cargo xtask test migrations | Nightly/RC | 45 min | Yes |

# **19\. Component and invariant verification**

## **19.1 ABI and canonicalization**

Test every record in minimal, maximal, extension, and invalid forms. Cover Unicode NFC, exact code text, map ordering, integer ranges, float rejection, URI and path normalization, timestamp precision, absent versus null, byte strings, tagged unions, ordered versus set arrays, duplicate JSON keys, invalid UTF-8, unpaired surrogates, invalid tags, trailing bytes, nesting, and allocation limits.

Required properties:

* canonicalize(decode(canonicalize(x))) \== canonicalize(x).  
* Any semantic field change changes the domain digest.  
* Non-semantic JSON whitespace or map order does not.  
* Different record domains never share preimage framing.  
* Unsupported hash, schema, or discriminant fails closed.  
* At least 100,000 generated records produce identical Rust, TypeScript, Python, and Go bytes or digests.

Gate: zero cross-language differences, zero unbounded allocation, and full public schema-vector coverage.

## **19.2 Catalog, provenance, temporal truth, and invalidation**

Test atomic snapshot visibility under parser failure, process kill, disk full, duplicate import, retry, and concurrent readers. Verify immutable correction, source ranges across newline and rename changes, all bitemporal quadrants, late correction, future-effective fact, deletion, and as-of replay.

Generated dependency DAGs test invalidation from source edit, tombstone, revocation, ACL, parser, transform, policy, and expiry. Unrelated atoms remain valid. Derivation cycles return typed error. Delete and rebuild every projection from canonical data. Cross-domain dedupe cannot reveal timing, count, ID, or cache-hit signals.

Gate: no partial snapshot, 100% expected invalidation, zero unexpected invalidation in controlled fixtures, and zero canary leak.

## **19.3 Policy and isolation**

Run a generated matrix over principals, tenants, workspaces, projects, tasks, purposes, processors, runtimes, classifications, trust, time, grants, and operations through catalog query, compiler, explanation, cache, subscription, handoff, materialization, replay, and effects.

Required properties are monotonicity, capability attenuation, denied-atom non-interference, pre-ranking enforcement, lane integrity, fail-closed protected operation, and no coupling from context visibility to execution authority.

The scale matrix includes at least 100 principals, 20 projects, eight purposes, all index types, warm and cold caches, and concurrent revocation.

Gate: zero unauthorized bytes, identities, counts, paths, scores, timing class, or existence signal.

## **19.4 Planner, retrieval, compiler, and explanation**

* Independently enable, disable, delay, and degrade every retrieval channel.  
* Use an adversarial ranker returning denied IDs to prove policy remains before ranking.  
* Generate budgets at every boundary and require mandatory inclusion or typed unsatisfiable result.  
* Run identical compilation across input permutations, parallelism, map seeds, restarts, architectures, and supported OSes.  
* Verify duplicate, superseded, contradicted, stale, and mutually dependent dispositions.  
* Resolve every included block to source, transform, score, dependency, policy, and reason.  
* Verify exact-field pinning through transforms, escaping, ordering, materialization, and deltas.  
* Attempt cache poisoning across principal, purpose, project, target, policy, and runtime.  
* Verify delta round trip and tamper rejection.  
* Verify explanation redaction and counterfactual budget views.

Metamorphic tests prove that irrelevant distractors do not remove mandatory items, increasing budget cannot remove mandatory items, denied content changes do not alter authorized output, ingestion order does not alter deterministic output, exact authorized duplicates do not increase physical context, and supersession selects new valid state or exposes conflict.

Gate: 100% mandatory inclusion, 100% selected provenance, at least 99.99% budget compliance over one million generated materializations, and byte-identical deterministic digests.

## **19.5 Materializers and tokenizers**

Golden outputs cover JSON, Markdown human brief, Claude/MCP, and fact sets. Differential token counts cover at least 10,000 generated ASCII, Unicode, code, JSON, handle, and boundary inputs. Escape tests include delimiter collision, Markdown/HTML/XML, JSON termination, tool-call-looking content, and bidirectional controls.

Materializers may not add, omit, merge, reorder semantically constrained blocks, or truncate. Target overflow returns typed recompile-required error. Handle expansion reauthorizes and preserves provenance.

Gate: 100% semantic block preservation, at least 99.99% token compliance, zero lane escape, zero secret canary.

## **19.6 Context spaces and handoffs**

Test branch, checkpoint, publish, merge, abandon, resume, and restart. Run two through 64 concurrent writers and verify stale base conflicts. Verify private overlays are invisible by content and existence signal.

Handoff vectors cover full and partial acceptance, unsupported policy, unavailable source, expired capsule, revoked issuer or recipient, source change, target restriction, clock boundary, and generated grant lattices. Parent inspection and merge preserve typed claims, evidence, artifacts, decisions, uncertainty, verification, effects, and conflicts.

Gate: zero authority amplification, zero overlay leakage, deterministic receipts, handoff and first bundle at most 20% of parent transcript reference, and at least 90% productive first action on the adjudicated set.

## **19.7 Effect crash matrix**

The effect model generates valid and invalid event sequences and compares state after every event. For release-candidate qualification, run at least 1,000 randomized repetitions per row and at least 100,000 total operations involving possible remote commit.

| ID | Injected boundary | Required recovery and assertion |
| :---- | :---- | :---- |
| EFX-C01 | Before intent transaction | No journal row; zero connector calls |
| EFX-C02 | Intent write before commit | Atomic rollback or absence; zero calls |
| EFX-C03 | Durable intent before policy | PREPARED; authorization can resume |
| EFX-C04 | During approval persistence | No partial approval; zero calls |
| EFX-C05 | Authorized before attempt | AUTHORIZED; safe to claim attempt |
| EFX-C06 | Attempt before outbox commit | Attempt and outbox atomically absent or present; zero premature call |
| EFX-C07 | Durable dispatch claim before send | Recoverable attempt; one logical key |
| EFX-C08 | Connect fails before request bytes | Retryable only if connector proves no commit |
| EFX-C09 | Request partially written | UNKNOWN unless non-execution proven |
| EFX-C10 | Remote definitive rejection | FAILED with rejection receipt |
| EFX-C11 | Remote commit, response lost | UNKNOWN, reconcile to confirmed, no duplicate |
| EFX-C12 | Response received, crash before receipt | Reopen unknown and reconcile by remote identity |
| EFX-C13 | Receipt appended, state projection crash | Rebuild projection to confirmed from journal |
| EFX-C14 | Duplicate or reordered response | One accepted receipt; no second transition |
| EFX-C15 | Reconciler unavailable | Visible unknown, bounded backoff, no dispatch |
| EFX-C16 | Weakly consistent lookup says absent | Remain unknown through certainty window |
| EFX-C17 | Verification contradicts receipt | Conflict or escalation; never silent success |
| EFX-C18 | Approval expires before send | Dispatch denied; new approval required |
| EFX-C19 | Policy or capability revoked before send | Dispatch denied under current-check policy |
| EFX-C20 | Same key for different normalized intent | Hard collision failure; no connector call |
| EFX-C21 | Compensation commits, response lost | New compensation effect becomes unknown and reconciles |
| EFX-C22 | Disk full during receipt | Unknown and alert; journal remains valid |
| EFX-C23 | Hash-chain corruption at restart | Quarantine or read-only failure; no dispatch or replay claim |
| EFX-C24 | Two workers claim one outbox item | Fencing permits at most one active dispatch |

Gate: no unjournaled dispatch, no unsafe blind retry, zero duplicate logical effects in the idempotent campaign, and every ambiguity visible.

## **19.8 Replay**

Evidence replay reconstructs exact bundle and manifest. Invocation replay reconstructs bytes or reports unsupported dependencies. Observational replay runs under OS network denial with connectors that panic if called. Live rerun creates a new execution and cannot reuse approval or receipt to mutate.

Missing source, tokenizer, adapter, policy, consumer, tool schema, or blob produces an explicit completeness report. Tampering fails before replay.

Gate: zero network or effect call in non-live modes and exact retained evidence digests.

## **19.9 Storage and APIs**

SQLite tests cover WAL configuration, process kill, WAL truncation, corrupt page, disk full, missing blob, permission change, and projection rebuild. PostgreSQL tests cover serialization, outbox atomicity, disconnect, failover, lag, locks, and concurrent migration. Object tests cover failed upload, stale list, checksum mismatch, missing key, and credential expiry.

API tests cover deadlines, cancellation, backpressure, pagination stability, body limits, compression, unknown fields, errors, idempotency, revision, content type, event duplicate, reconnect, authorization change during subscription, and slow consumer eviction.

Gate: journal RPO zero in the supported durability profile, no semantic loss after rebuild, and all adjacent migrations on supported platforms.

## **19.10 CLI, SDK, and Claude adapter**

Every CLI command has golden JSON success and error output. Human output covers TTY, non-TTY, no color, narrow width, Unicode-disabled fallback, piping, cancellation, confirmation, and non-admin paths.

SDKs share success, errors, deadline, cancellation, pagination, stream resume, redaction, idempotency, and retry vectors. Retry helpers never redispatch unsafe effects.

The Claude adapter installs into a temporary fake home, executes versioned events, performs MCP and hook tests, degrades on daemon and socket faults, and uninstalls leaving all non-CIGAR host files byte-identical. Static checks reject references to private session paths.

# **20\. Conformance kit**

## **20.1 Profiles**

| Profile | Required behavior |
| :---- | :---- |
| cigar-core-v1 | Protocol, canonicalization, digests, errors, deterministic bundle identity |
| cigar-catalog-v1 | Snapshots, atoms, provenance, bitemporal query, invalidation, rebuild |
| cigar-compiler-v1 | Hard gates, lanes, budgets, selection, manifests, deltas, explanation |
| cigar-handoff-v1 | Scope, attenuation, recipient auth, partial acceptance, merge/conflicts |
| cigar-effect-v1 | Durable intent, idempotency, unknown, reconciliation, compensation |
| cigar-replay-v1 | Evidence, invocation, observational replay, completeness, live isolation |
| cigar-service-v1 | HTTP/gRPC, errors, pagination, cancellation, streams |
| cigar-runtime-claude-code-v1 | Plugin, MCP, hooks, materialization, degradation |

## **20.2 Runner**

The standalone cigar-conformance runner accepts an executable, HTTP endpoint, gRPC endpoint, or SDK adapter. It emits conformance-result.v1.json containing implementation and build digest, claimed profiles, runner and vector digests, platform, each case, status, duration, expected and actual public digest, redacted diagnostic, and overall result.

cargo xtask conformance build  
cigar-conformance run \\  
  \--profile cigar-core-v1 \\  
  \--profile cigar-compiler-v1 \\  
  \--endpoint unix:///tmp/cigard.sock \\  
  \--vectors conformance/vectors/v1 \\  
  \--output reports/conformance-result.v1.json  
cigar-conformance verify reports/conformance-result.v1.json

Required cases cannot be skipped. The runner isolates CPU, memory, time, output, filesystem, and network; detects crash, timeout, malformed output, external call, and vector mutation; and starts a fresh namespace unless persistence is the behavior under test.

## **20.3 Compatibility matrix**

Test current client and server, previous two stable clients against current server, current client against previous two servers for documented operations, old persisted catalog and journal upgrade, optional unknown fields, and explicit failure for unsupported mandatory features. Release archives include every vector and expected digest for offline independent execution.

# **21\. Fuzzing, security, concurrency, and chaos**

## **21.1 Fuzz targets**

At minimum:

1. Canonical JSON-to-CBOR and strict CBOR decode.  
2. Every public record decoder and schema validator.  
3. URI, path, source range, and project identity normalization.  
4. Policy profile parse and evaluation.  
5. Context contract planning and compiler candidate sets.  
6. Delta generation and application.  
7. Manifest and explanation decode and redaction.  
8. Handoff decode, verification, acceptance, and merge.  
9. Materializer escaping and token-budget boundary.  
10. Effect event sequences, receipts, reconciliation, and damaged journal recovery.  
11. Replay envelopes and completeness.  
12. Extension manifests and sandbox messages.  
13. MCP request and response decode.  
14. Every built-in source parser and atomizer.

Assertions include no crash, panic, OOM, recursion escape, undefined behavior, secret reflection, invalid state transition, forbidden noncanonical acceptance, or unstable round trip. Inputs have strict size, depth, allocation, and execution limits.

PR smoke runs affected targets for at least 60 seconds. Nightly runs two CPU-hours per target. RC requires a clean continuous seven-day-equivalent campaign and ordinary regression tests for every prior crash.

## **21.2 Property testing and model checking**

Use Proptest, fast-check, Hypothesis, and Go fuzzing for canonical idempotence, hash sensitivity, authorization monotonicity, grant attenuation, delta round trip, budget safety, permutation invariance, invalidation closure, effect safety, key stability, and journal append-only behavior.

Use Loom or Shuttle-style schedules for cache publication, snapshot visibility, context revisions, outbox claim and fencing, subscription cursor, invalidation queue, and shutdown. Run ThreadSanitizer, AddressSanitizer, UndefinedBehaviorSanitizer, and Miri on appropriate targets. Every shrunk failure becomes a checked-in regression fixture.

## **21.3 Static and supply-chain checks**

cargo clippy \--workspace \--all-targets \--all-features \-- \-D warnings  
cargo deny check  
cargo audit \--deny warnings  
pnpm audit \--prod \--audit-level high  
python \-m pip\_audit \--strict  
gitleaks detect \--no-banner \--redact  
semgrep scan \--config auto \--error

An exception must be exact-package and exact-advisory scoped, have a verified mitigation or non-reachability test, and expire before the next release. Critical or high unmitigated issues block.

## **21.4 Dynamic adversarial families**

* Cross-tenant, project, purpose, and processor leaks through retrieval, vectors, graph, dedupe, cache, pagination, counts, explanation, events, handoff, replay, and timing.  
* Prompt injection and instruction smuggling through content, comments, filenames, metadata, summaries, and tool-looking syntax.  
* Secret exfiltration through all outputs, logs, metrics, traces, panic, core dump, storage, IPC, temp, packages, and network.  
* Path traversal, symlink or hard-link race, case collision, device file, pipe, socket, worktree or submodule escape, archive traversal, and preview-to-ingest TOCTOU.  
* SSRF through redirects, DNS rebinding, address literals, Unix sockets, proxy variables, connectors, plugins, and providers.  
* Parser, graph, compression, tokenization, vector, regex, and streaming denial of service.  
* Extension sandbox breakout and capability forgery.  
* API smuggling, oversized and compressed request, slow stream, auth confusion, IDOR, cursor forgery, replayed approval, and cancellation storm.  
* Storage and journal edit, swap, rollback, truncate, and key mismatch.  
* Effect normalization ambiguity, target alias, approval substitution, key collision, connector lie, duplicate race, receipt forgery, and reconciliation spoof.  
* Mixed-version downgrade across schema, policy, connector, materializer, SDK, plugin, and daemon.

Canary scanning covers exported buffers, logs, temporary directories, storage where plaintext is forbidden, network capture, and CI artifacts.

## **21.5 Chaos program**

Chaos scenarios run real processes and stores from deterministic plans. Faults include process kill at every failpoint, restart loops, rolling mixed versions, disk full, quota, read-only, short write, fsync error, corruption, slow disk, PostgreSQL abort and failover, object-store errors, index lag and corruption, ranker and transform crash, policy unavailable or malformed, duplicate or delayed events, clock jumps, network partition at every remote boundary, one through 64 concurrent agents, memory and CPU pressure, file-descriptor exhaustion, and cancellation storms.

After each scenario run deep doctor, database integrity, hash-chain verification, projection rebuild, unknown-effect reconciliation, and canonical state comparison. Required invariants are no partial snapshot or bundle, no unauthorized output, no lost committed journal event, no falsely confirmed effect, no silent conflict overwrite, and no hidden degraded state.

# **22\. Performance, scale, and outcome qualification**

## **22.1 Measurement discipline**

Every performance report records CPU, cores, memory, OS and kernel, filesystem, storage, power mode, compiler flags, build digest, dataset digest, atom, edge and blob size, index state, tokenizer, policy, warm-up, concurrency, and background load. External model, embedding, network source, and connector latency are measured separately.

Microbenchmarks use statistically rigorous sampling and store raw results. Black-box load tests exercise installed cigard. Dedicated pinned runners are required for release gates. At least 30 post-warm samples and less than 5% calibrated host variance are required before a regression decision.

## **22.2 v1 performance gates**

| Operation | Dataset and profile | Gate |
| :---- | :---- | :---- |
| Warm semantic bundle cache hit | 1M atoms | p95 at most 15 ms |
| Delta compile | Representative 6k-token bundle | p95 at most 50 ms |
| Full deterministic compile | 1M atoms, 10M edges, no generative transform | p50 at most 75 ms; p95 at most 250 ms; p99 at most 750 ms |
| Claude prompt hook | Warm local sidecar | p95 at most 150 ms; p99 at most 1 s |
| MCP summary retrieval | Local sidecar | p95 at most 250 ms |
| Daemon ready | Existing 1M-atom catalog | p95 at most 2 s |
| Durable journal prepare | SQLite durability profile | p95 at most 25 ms |
| Local event propagation | 32 attached sessions | p95 at most 100 ms |
| Same-region shared event | PostgreSQL and object profile | p95 at most 1 s |
| One-file incremental reindex | No remote embedding | p95 at most 500 ms |
| Ingestion | Small source atoms, no embedding | At least 250 atoms/s |
| Local active sessions | Mixed workload | At least 32 without correctness loss |
| Local scale | 1M atoms, 10M edges, 100 GB referenced blobs | All latency and resource gates |
| Shared scale | 10M atoms | Published curve and no correctness degradation |
| Idle daemon | Memory-mapped indexes excluded | RSS under 300 MiB and negligible CPU |
| Hard budget | At least 1M generated materializations | At least 99.99% compliance |

Block merge at a statistically significant p95 regression over 10% or throughput or RSS regression over 15%. Warn over 5%. Any SLO breach blocks release even when the relative change is smaller. A faster result with changed digest, lower recall, weaker durability, or higher leakage is a correctness failure.

## **22.3 Load matrix**

Measure 1k, 10k, 100k, 1M, and 10M atoms; 10 through 10k candidates; 1 through 100 GB blobs; 1, 8, 32, 64, and 128 clients; cold and warm cache; exact, lexical, graph, and vector combinations; strong and bounded-stale consistency; local and shared stores.

Report full latency distributions, throughput, allocations, CPU, RSS, disk amplification, database and index size, lock time, queue depth, cache hit rate, invalidation lag, and failure rate.

## **22.4 CIGARBench harness**

The benchmark repository includes LongRepo-Change, MultiProject-Switch, Agent-Handoff, Temporal-Truth, Needle-and-Distractor, PolicyBoundary, EffectCrash, CrossRuntime-Replay, and CatalogMutation.

Baselines are full transcript or project, fixed window, native provider memory and compaction, transcript summary, lexical or semantic top-k RAG, human oracle, and CIGAR ablations. For each paired run pin model or deterministic consumer, runtime, tools, task, repository, output budget, sampling, tokenizer, source, adapter, and compiler.

Measure physical tokens, cache read and write separately, verified success, critical recall, context precision, prohibited-context rate, stale harm, rework, latency, intervention, and cost per verified success.

## **22.5 Outcome gates**

* Median physical input reduction at least 40%; twenty-fifth percentile at least 25% versus raw or native baseline.  
* Cost per independently verified successful job improves at least 10%.  
* Task success is non-inferior within two percentage points.  
* Critical-context recall at least 99% on the v1 adjudicated reference set.  
* Selected-context precision at least 90%.  
* Context-caused harm below 1%.  
* Unauthorized context rate zero.  
* Against a strong summary or RAG baseline: at least 30% less median physical context with no more than one point success loss, or at least five points higher success at equal budget.

Report per-stratum distributions and 95% bootstrap intervals. A global mean cannot hide a failing PolicyBoundary, EffectCrash, or MultiProject-Switch stratum.

# **23\. Observability and production operations**

## **23.1 Trace tree**

cigar.session  
  cigar.job  
    cigar.context.plan  
    cigar.context.compile  
      cigar.context.scope  
      cigar.context.retrieve  
      cigar.context.authorize  
      cigar.context.reconcile  
      cigar.context.transform  
      cigar.context.pack  
      cigar.context.materialize  
    cigar.agent.turn  
      cigar.tool.observe  
      cigar.handoff  
    cigar.decision.capture  
    cigar.effect.prepare  
    cigar.effect.dispatch  
    cigar.effect.reconcile  
    cigar.outcome.verify

Fan-out and fan-in use span links. High-cardinality IDs belong in traces, not metric labels. Trace attributes include blinded tenant and workspace, contract, plan, bundle, manifest, materialization, decision, handoff, and effect IDs; compiler and policy fingerprints; candidate and token counts; phase duration; index lag; degraded state; and stable error code.

## **23.2 Metrics**

Required metrics include ingestion atoms and bytes, parser failures, quarantines, index lag, invalidation fan-out and age, candidates and selected blocks, lane tokens, compile phase time, conflict and stale counts, cache hits, physical and cache tokens, handoff acceptance and merge conflicts, effect state and unknown age, reconciliation, queue depth and age, worker lease, database pool, blob integrity, API request and stream backpressure, daemon resources, and demo or benchmark outcome.

Metric labels have bounded cardinality. Raw path, prompt, source, artifact, user, or secret values are prohibited.

## **23.3 Logging**

Logs are structured JSON in service mode and concise human text in foreground local mode. Each event has timestamp, level, component, stable event code, trace ID, operation IDs where safe, result class, duration, and redacted diagnostic. Raw content capture is off and requires a separate explicit debug profile that cannot run for protected classifications.

Panic hooks produce a redacted crash ID and no context bytes. Production builds catch no panic across FFI, plugin, hook, or network boundary without converting it to a typed internal error and terminating the affected operation safely.

## **23.4 Operational commands**

* cigar doctor checks configuration, keys, store, migrations, blobs, indexes, policy, daemon auth, MCP, adapter, tokenizer, workers, unknown effects, and version compatibility.  
* cigar doctor \--deep verifies hashes, journal chains, sample blobs, projections, and replay completeness.  
* cigar backup create, verify, and restore operate with signed inventories.  
* cigar effect reconcile \--all-unknown processes bounded batches and reports unresolved age.  
* cigar context revalidate \--active checks active tasks and handoffs.  
* cigar gc plan previews tombstones, blobs, and retention blockers.  
* cigar diagnostics bundle creates a content-free support archive by default and prints its exact file inventory.

## **23.5 Service operations documentation**

Runbooks cover daemon start and stop, socket and TLS setup, OIDC, key creation and rotation, database and blob backup, restore, migration, index rebuild, scale tuning, unknown-effect backlog, journal quarantine, blob corruption, revocation propagation, degraded compiler, high queue age, SDK compatibility, and safe adapter disablement.

# **24\. CI, packaging, and release engineering**

## **24.1 Pull-request pipeline**

1. Verify toolchains, locks, generated files, schemas, and golden-vector drift.  
2. Format, lint, public docs, doctests, SDK type and lint.  
3. Unit, canonical vectors, schema compatibility, property smoke, and changed integration.  
4. Static security, secret, dependency, advisory, and license scans.  
5. Fuzz smoke for affected parsers, protocol, policy, compiler, effect, and MCP surfaces.  
6. Changed microbenchmarks against pinned baseline.  
7. Dry-run package creation and contents validation for touched artifacts.

Target feedback is under 15 minutes using path sharding. Caches speed compilation but cached test results never count as evidence.

## **24.2 Merge pipeline**

Run full workspace integration, all conformance profiles, end-to-end demos, PostgreSQL and object integration, offline no-egress, tier-1 platforms, microbenchmarks, and coverage against the exact merge commit.

## **24.3 Nightly and weekly**

Nightly runs full platforms, extended properties, sanitizers, model checking, extended fuzz, chaos and crash matrix, migration, macrobenchmarks, leak soak, 32 and 64-agent concurrency, install and uninstall, and fresh vulnerability scans.

Weekly and release candidate run mutation, seven-day-equivalent fuzz accumulation, 24-hour daemon soak, 100,000 effect fault operations, 1M and 10M scale, CIGARBench, reproducibility, clean package smoke, and every supported retained upgrade.

## **24.4 Artifact matrix**

Produce:

* Rust crates intended for public consumption.  
* cigar and cigard archives for supported Linux, macOS, and Windows architectures; Linux musl where claimed.  
* Platform installers or package-manager formulas supported by clean tests.  
* Multi-architecture non-root OCI image for shared service.  
* npm package for TypeScript SDK.  
* Python wheels and source distribution for supported CPython and platforms.  
* Go module tag and generated client artifacts.  
* Claude Code plugin archive with manifest, hooks, skills, compatibility, schemas, and checksums.  
* Schema, conformance vector, benchmark fixture, source, documentation, and license archives.

Every artifact reports one semantic version and Context ABI declaration. Binary version JSON, daemon diagnostics, SDK constants, plugin manifest, schemas, archive names, and SBOMs must agree.

## **24.5 Package contract tests**

For each artifact:

* Compare contents to an allowlist.  
* Reject VCS data, CI credentials, developer paths, test secrets, private fixtures, unnecessary debug data, and unpinned binaries.  
* Validate licenses, notices, modes, symlinks, line endings, and archive traversal safety.  
* Install as an unprivileged user in a clean machine without a compiler when a binary package is claimed.  
* Run version, help, doctor, local init, ingest, compile, explain, handoff, replay, daemon lifecycle, and uninstall.  
* Test spaces, Unicode, read-only parent, long Windows path, and non-admin user.  
* Verify no network during offline operation.  
* Upgrade a retained prior package while preserving catalog and journal.  
* Run ecosystem-specific package validators.  
* Scan final archives and unpacked content for vulnerabilities, malware indicators, secrets, and unexpected endpoints.

## **24.6 Reproducible builds**

Pin compilers, package managers, SDKs, builder images, generators, and locks. Set SOURCE\_DATE\_EPOCH, locale, timezone, remapped source paths, deterministic archive order, timestamps, ownership, and modes. Do not embed wall clock or workspace path.

Two isolated runners build from the signed source archive with empty caches and compare payload SHA-256. Platform signing or notarization may add outer metadata; publish the unsigned reproducible payload digest and signed distribution digest, and prove the signed envelope contains the payload.

## **24.7 SBOM, signing, and provenance**

Generate SPDX and CycloneDX SBOMs from final artifacts, including language packages, native libraries, extension modules, plugin executables, installers, and image layers. Sign checksum manifest, artifacts, SBOMs, plugin manifest, conformance result, benchmark result, and provenance with the chosen release system.

Provenance binds source archive, workflow, builder, locks, commands, artifacts, and release evidence. cigar release verify \<directory\> validates offline with supplied trusted roots.

## **24.8 Release evidence**

release-evidence.json references every test, coverage, mutation, fuzz, sanitizer, model, chaos, migration, conformance, benchmark, package, SBOM, signature, provenance, reproducibility, and demo artifact by digest. The assembler rejects missing, stale, wrong-commit, wrong-artifact, threshold-failing, skipped, or tampered evidence.

cargo xtask release verify dist/ is the single technical go or no-go command. It cannot pass after deleting a required report.

## **24.9 Stop-ship conditions**

* Unauthorized content or existence leak.  
* Nondeterministic canonical digest.  
* Mandatory omission, lane promotion, or materializer semantic drift.  
* Dispatch before durable intent and authorization.  
* Unsafe retry or duplicate logical effect.  
* Network or mutation in non-live replay.  
* Lost committed journal event or partial canonical visibility.  
* Exploitable critical or high vulnerability.  
* Fuzz, sanitizer, memory-safety, or model-checking defect.  
* Failed supported migration.  
* Missed SLO or outcome gate.  
* Broken install, uninstall, offline use, version consistency, signature, SBOM, provenance, or reproducibility.  
* Any release-blocking flake, skip, quarantine, or missing evidence.  
* A claimed platform not tested using its distributed artifact.

# **25\. Documentation and user-facing deliverables**

## **25.1 Documentation site**

The generated site includes:

* Five-minute local quickstart.  
* Product concepts: atom, contract, bundle, manifest, delta, context space, handoff, effect, replay.  
* Install and uninstall for every platform.  
* Project initialization and source policy.  
* Multi-project and task focus workflow.  
* Agent handoff and merge.  
* Effect connector and recovery.  
* Replay and comparison.  
* Claude Code integration.  
* Embedded, local daemon, and shared service deployment.  
* Rust, TypeScript, Python, and Go SDK guides.  
* Protocol, OpenAPI, gRPC, schema, error, CLI, configuration, metric, and extension references.  
* Backup, restore, migration, security hardening, troubleshooting, and performance tuning.  
* Demo walkthroughs and expected outputs.

## **25.2 Documentation correctness**

Every command is executed in docs CI. Code blocks are compiled or tested. API examples are generated from schemas where possible. Links, anchors, and version selectors are checked. Screenshots are optional; stable JSON and terminal transcripts are generated from demo runs and redacted automatically.

## **25.3 Root README**

The README states what CIGAR is, what it is not, the five-minute result, architecture diagram, supported platforms, installation, one compile example, one handoff example, one effect-recovery example, benchmark evidence link, protocol stability, and security reporting link. It does not claim universal exactly-once effects or deterministic model output.

## **25.4 Open-source release files**

The repository contains LICENSE, NOTICE, SECURITY.md, code of conduct if desired by the publisher, third-party attribution, release checksums, and verified source archive. This specification does not define organizational governance or community process.

# **26\. Dependency-ordered implementation work packets**

## **26.1 Execution waves**

![Six implementation waves from repository bootstrap through protocol foundations, persistence, kernel services, product surfaces, and release, with explicit quality gates and a plan-implement-verify-demonstrate-record cycle for every work packet.][image4]

*Figure 4\. Codex implementation waves and release gates*

WP00 bootstrap  
  \-\> WP01 protocol \-\> WP02 canonicalization/crypto/errors  
  \-\> WP03 store contracts \-\> WP04 SQLite/blob/recovery  
  \-\> WP05 catalog/atomizers \-\> WP06 indexes/retrieval  
  \-\> WP07 policy \-\> WP08 compiler \-\> WP09 materializers/cache/deltas  
  \-\> WP10 context spaces \-\> WP11 handoffs  
  \-\> WP12 effects \-\> WP13 decision/replay  
  \-\> WP14 daemon/API \-\> WP15 CLI  
  \-\> WP16 SDKs \-\> WP17 Claude adapter  
  \-\> WP18 PostgreSQL/shared deployment  
  \-\> WP19 conformance/test hardening  
  \-\> WP20 demos/CIGARBench  
  \-\> WP21 packaging/docs/operations  
  \-\> WP22 release candidate and v1.0.0

Policy schema work may begin after WP02 while storage proceeds. Effect record types and state-model tests may begin after WP02. SDK generation may begin when the API subset freezes. Shared storage may begin after WP03 repository conformance exists. No downstream work consumes an uncommitted schema draft.

## **26.2 Packet evidence contract**

Every completed packet writes artifacts/work-packets/WPxx.json:

{  
  "packet": "WP08",  
  "source\_commit": "\<digest\>",  
  "prerequisites": \["WP01", "WP02", "WP05", "WP06", "WP07"\],  
  "owned\_paths": \["crates/cigar-compiler", "schemas/vectors/compiler"\],  
  "commands": \["cargo xtask test unit \--package cigar-compiler"\],  
  "tests": \[{"id": "CTX-P001", "result": "pass"}\],  
  "metrics": {"deterministic\_digest\_equivalence": 1.0},  
  "artifacts": \[{"path": "reports/wp08.json", "sha256": "..."}\],  
  "known\_limitations": \[\],  
  "status": "complete"  
}

The release evidence assembler rejects a packet whose commit is not an ancestor of the release candidate, whose artifact digest differs, whose prerequisite is incomplete, or whose required acceptance metric is missing.

## **26.3 WP00 \- repository, toolchain, and quality skeleton**

**Prerequisites:** none.

**Owned paths:** root build files, .github/workflows, crates/xtask, empty crate manifests, IMPLEMENTATION\_STATUS.md, docs skeleton.

**Build tasks:**

* [x] Create the complete directory tree and Cargo workspace with dependency direction lints.  
* [x] Pin Rust and package-manager toolchains and locks.  
* [x] Implement cargo xtask bootstrap, format, lint, generate, test, docs, package, and verify command stubs that fail clearly until later capabilities exist.  
* [x] Add strict workspace lints, dependency policy, secret scan, source allowlist, coverage output, and nextest.  
* [x] Create Linux, macOS, and Windows build CI plus local development containers for PostgreSQL and object storage.  
* [x] Implement version metadata embedded without nondeterministic time or paths.

**Tests:**

* [x] Stale generated file and dirty code generation fail.  
* [x] Forbidden dependency edge fails.  
* [x] Unpinned dependency fails.  
* [x] Warning and undocumented public item fail.  
* [x] Placeholder macro fails.  
* [x] Missing tool fails with supported version and installation help.

**Exit:** [x] clean workspace runs bootstrap and fast CI commands; empty binaries print semantic version, source revision, protocol range, build profile, and enabled features in stable JSON.

## **26.4 WP01 \- Context ABI domain types and schemas**

**Prerequisites:** WP00.

**Owned paths:** cigar-protocol, spec/context-abi, schemas/json, schemas/proto, protocol fixtures.

**Build tasks:**

**Progress:**

* [x] Foundational ABI slice: named limits, bounded aggregated validation, schema-major fail-closed handling, UUIDv7/multihash identities, idempotency/revision wrappers, stable extension grammar, unknown mandatory extension rejection, depth/entry bounds, and secret-safe debug views.  
* [x] Core atom slice: typed URI/path/time/duration/fixed-point primitives, `ContextAtomV1`, ordered multi-error validation, closed governance/lifecycle discriminants, base64url byte paths, reproducible JSON Schema, compiling Protobuf contract, and reference documentation.  
* [x] Catalog and contract slice: immutable `SourceSnapshot`, typed `ContextEdge`, normalized `ContextContract`, exact lane-budget arithmetic, requirements, target fingerprints, consistency invariants, reproducible JSON Schemas, Protobuf messages, and redacted debug views.  
* [x] Compilation output slice: deterministic plans/lanes/dispositions, provenance-complete blocks, bundles, selection manifests, base64url materialization, deltas, token and transform-receipt invariants, generated JSON Schemas, Protobuf messages, and reference documentation.  
* [x] Coordination slice: immutable commits and overlays, attenuated capability grants, signed handoff capsules, recipient acceptance reauthorization, evidence-backed child deltas, leases, coordination events, generated JSON Schemas, Protobuf messages, and reference documentation.  
* [x] Effect slice: intent-before-dispatch records, approval requirements, attempts, receipts, hash-chained journal events, reconciliation, compensation links, and an explicit fail-closed effect-state transition graph.  
* [x] Replay slice: replay requests and executions, dependency completeness, decision records, verification receipts, diff records, and non-live egress/effect-dispatch prohibition.  
* [x] Service slice: bounded cursors and idempotency keys, optimistic revisions, stable numeric error codes and mappings, bounded problems, health aggregation, and compatibility reports.  
* [x] Wire generation slice: checked-in Rust, TypeScript, Python, and Go Protobuf bindings generated by pinned tools, compiled/imported in each language, and reproducibility-enforced by `cargo xtask generate --check`.  
* [x] Complete record families, transport schemas, generated multi-language wire types, and the 200-fixture matrix required for the WP01 exit gate.

* [x] Implement all newtypes, records, discriminants, limits, schema versions, validation, redaction views, and stable extension rules.  
* [x] Author Protobuf service-family messages, generated JSON Schemas, and compatibility annotations.  
* [x] Generate Rust, TypeScript, Python, and Go wire types without putting transport types in semantic services.  
* [x] Create valid, maximum, boundary, invalid, extension, and unsupported-version fixtures.  
* [x] Generate error catalog placeholders for WP02 integration.

**Tests:** [x] at least 200 valid and invalid fixtures; every enum and union variant; limits at minus one, exact, and plus one; unknown major version; unknown optional versus mandatory extension.

**Exit:** [x] schemas render complete reference docs; generated artifacts are reproducible; no network, storage, or async-runtime dependency enters cigar-protocol.

## **26.5 WP02 \- canonicalization, hashing, crypto, and errors**

**Prerequisites:** WP01.

**Owned paths:** cigar-canon, cigar-crypto, spec/canonicalization, spec/errors, schemas/vectors.

**Build tasks:**

**Progress:**

* [x] Canonical foundation slice: strict duplicate-aware JSON, null/float rejection, compact normalization, bounded deterministic CBOR encoding and strict re-encode decoding, encoded-key ordering, NFC as an explicit field transform, v1 digest domains, SHA-256 multihash output, known-answer tests, and profile documentation.  
* [x] Cryptographic primitive slice: non-clone zeroizing secret bytes/strings, redacted formatting, OS-random XChaCha20-Poly1305 nonces, exact associated-data authentication, Ed25519 key derivation/sign/strict verification, tamper rejection, and RFC 8032 known-answer coverage.  
* [x] Provider and identity slice: scoped create/resolve/rotate/sign/verify/wrap/unwrap/destroy key-provider oracle, signature purpose/tenant/status/time binding, historical verification, monotonic concurrent UUIDv7 generation, rollback handling, and destruction zeroization.  
* [x] Generated error slice: one validated 34-code catalog generates Rust metadata and behavior, Protobuf, OpenAPI, TypeScript, Python, and Go bindings with stable HTTP, gRPC, retry, message, and remediation mappings.  
* [x] Cross-language conformance slice: six frozen semantic-envelope profiles and digest domains, published enum/union discriminants, 348 valid and 15 invalid golden vectors, independent Rust/TypeScript/Python/Go verifier executables, explicit Unicode/map-order cases, and the 100,000-record differential gate in every language.  
* [x] Complete semantic envelopes and discriminants, cryptographic primitives and providers, generated errors, 200+ cross-language vectors, verifier executables, and the 100,000-record differential gate.

* [x] Implement strict JSON parsing and normalization, deterministic CBOR, domain-separated multihash, UUIDv7 monotonic IDs, secret types, key provider, XChaCha20-Poly1305 envelopes, Ed25519 signatures, and signature verification.  
* [x] Implement stable generated error registry and HTTP/gRPC mappings.  
* [x] Publish cross-language vectors and verifier executables.  
* [x] Add canonical streaming limits and noncanonical input rejection.

**Tests:** [x] all canonical and crypto known-answer vectors, randomized permutations, Unicode, invalid forms, corruption, wrong key and associated data, clock rollback IDs, signature expiry and scope, safe formatting, and 100,000 cross-language generated records.

**Exit:** [x] identical bytes and digests across Rust, TypeScript, Python, and Go; every invalid form produces the expected safe stable error; semantic digests exclude only documented fields.

## **26.6 WP03 \- store traits and transaction contracts**

**Prerequisites:** WP01 and WP02.

**Owned paths:** cigar-store interfaces, in-memory reference implementation, migration framework, repository contract tests.

**Build tasks:**

**Progress:**

* [x] Define typed read and write transactions, tenant and purpose context, snapshot selection, expected revisions, outbox, context commits, effect events, blobs, and request-digest-bound idempotent result retrieval.  
* [x] Implement a whole-state MVCC in-memory store as a behavioral oracle, not a production backend.  
* [x] Prevent mixed snapshot or cross-tenant handles through transaction lifetimes, immutable capabilities, and snapshot-pinned cursors.  
* [x] Create the reusable repository conformance suite used by all backends, including derivation acyclicity and migration metadata validation.

**Tests:** [x] atomic commit and abort, repeatable and historical snapshots, revision conflict, request-bound idempotent mutation, outbox causality, tenant scoping, concurrent read/write, mixed-cursor rejection, derivation-cycle rejection, and cancellation.

**Exit:** [x] every repository method is covered by the black-box suite and the in-memory model; dropped, cancelled, stale, invalid, and injected-abort writes expose no partial state.

## **26.7 WP04 \- SQLite, blob storage, backup, and recovery**

**Prerequisites:** WP03.

**Owned paths:** SQLite implementation, local blob implementation, local migrations, backup and restore, integrity checker.

**Build tasks:**

* [x] Implement complete schema, indexes, FTS capability detection, WAL and durability settings, one-writer task, bounded readers, migrations, encrypted blobs, atomic publication, orphan reconciliation, backup, restore, and GC.  
* [x] Implement OS keychain and encrypted development keystore.  
* [x] Add named failpoints around every file and transaction durability boundary.

**Tests:** [x] repository conformance, [x] process kill at publication boundaries, [x] WAL damage, [x] disk full, [x] permission change, [x] blob corruption and swap, [x] backup during reads, [x] restore to empty, [x] key rotation, [x] one-million-atom open and query.

**Exit:** [x] committed journal RPO zero under durability profile; [x] restored state has identical canonical roots; [x] corruption quarantines and invalidates without plaintext leak; [x] local scale resource target passes.

## **26.8 WP05 \- catalog, ingestion, code intelligence, and invalidation**

**Prerequisites:** WP04; protocol atom schemas frozen.

**Owned paths:** cigar-catalog, cigar-code-intel, source connectors, atomizers, ingestion and invalidation workers.

**Build tasks:**

* [x] Implement discovery preview, ignore and secret policy, Git and filesystem identity, staged snapshots, atom publication, lineage, supersession, tombstones, provenance edges, change watch, refresh, and invalidation DAG.  
* [x] Implement text, Markdown, structured-data, Git, interaction, and required Tree-sitter language atomizers.  
* [x] Implement symbol, diff, decision, and checkpoint capsules.

**Tests:** [x] interrupted ingestion invisibility, [x] exact retry idempotency, [x] rename and line-ending source ranges, [x] parser error regions, [x] symlink and worktree safety, [x] secret corpus, [x] bitemporal queries, [x] derivation cycles, [x] precise invalidation, [x] watcher overflow and restart.

**Exit:** [x] one-file refresh invalidates exact dependents; [x] secret scan precedes indexing; [x] sustained ingestion at least 250 small atoms/s; [x] source and symbol provenance resolves end to end.

## **26.9 WP06 \- index manager and authorized retrieval**

**Prerequisites:** WP03, WP05, policy partition interface draft.

**Owned paths:** cigar-retrieval, FTS and graph projections, optional vector adapters, index workers, query planner.

**Build tasks:**

* [x] Implement exact, scope, path, symbol, entity, temporal, authority, FTS, graph, active-state, and optional vector projections.  
* [x] Implement generation rebuild and atomic activation, watermarking, strong and bounded-stale consistency, authorized partitions, staged retrieval, feature quantization, evidence, and caps.  
* [x] Implement vector-disabled and outage fallback paths.

**Tests:** [x] delete and rebuild, [x] lag and deadline, [x] corruption, [x] query cancellation, [x] graph depth and cycle bounds, [x] exact feature and tie order, [x] cross-project isolation, [x] vector processor denial, [x] fallback, and [x] one million candidate stress.

**Exit:** [x] strong never uses behind watermark; [x] bounded-stale discloses exact lag; [x] unauthorized content never reaches candidate content, external embedding, or caller-visible logs; [x] semantic result set survives rebuild.

## **26.10 WP07 \- policy, redaction, and capabilities**

**Prerequisites:** WP01, WP02; may proceed parallel to WP04-WP06 using in-memory records.

**Owned paths:** cigar-policy, policy profile schema, capability and redaction tests.

**Build tasks:**

* [x] Implement hard gate order, compiled declarative rule DAG, immutable snapshots, partition decisions, content and processor decisions, bundle and handoff reauthorization, effect decisions, structural redaction, capability signature and attenuation, denied-existence views, and cache.  
* [x] Implement policy change invalidation event.

**Tests:** [x] generated authorization lattice, [x] monotonicity, [x] non-interference, [x] deny precedence, [x] processor confinement, [x] instruction self-promotion, [x] cross-project and tenant negative matrix, [x] revocation, [x] policy outage, [x] redaction exactness, [x] timing classes.

**Exit:** [x] zero unauthorized signal in negative suite; [x] no lower rule overrides deny; [x] protected outage fails closed; [x] policy change prevents old bundle use before background invalidation completes.

## **26.11 WP08 \- planner and deterministic compiler**

**Prerequisites:** WP01, WP02, WP05, WP06, WP07.

**Owned paths:** cigar-compiler planning, reconciliation, dependency closure, packing, manifest, profiles, compiler fixtures.

**Build tasks:**

* [x] Implement contract normalization, input freezing, lane construction, query stages, hard gates, candidate canonicalization, claim conflict groups, dependency closure, representation generation, feasibility, lane quotas, deterministic knapsack and local swaps, stable order, token repair, seal, manifest, explanation, and invalidation registration.  
* [x] Implement balanced v1 fixed-point features and profile versioning.  
* [x] Ensure no default model or network call.

**Tests:** [x] golden bundles, [x] brute-force small-set oracle, [x] permutation and parallel determinism, [x] mandatory overflow, [x] generated budgets, [x] exact pinning, [x] conflict policies, [x] dependency cycles, [x] adversarial ranker, [x] all disposition codes, [x] redacted explanation, [x] cache input fingerprint.

**Exit:** [x] deterministic cross-platform digests, [x] 100% mandatory include-or-error, [x] full provenance and disposition, [x] one-million materialization budget gate, [x] p50/p95/p99 compile targets.

## **26.12 WP09 \- materializers, tokenizers, caches, and deltas**

**Prerequisites:** WP08.

**Owned paths:** materializer modules, tokenizer adapters, cache implementations, delta engine.

**Build tasks:**

* [x] Implement JSON, Markdown, fact-set, Claude prompt and MCP materializers.  
* [x] Implement exact tokenizer interfaces and conservative estimator mode.  
* [x] Implement atom, transform, retrieval, plan, bundle, and materialization caches with revocation recheck.  
* [x] Implement provider-present accounting, delta generation, application, acknowledgement, and target overflow repair request.

**Tests:** [x] materialization goldens, [x] delimiter and bidi attack, [x] tokenizer differential, [x] cache poisoning, [x] corruption, [x] eviction, [x] revocation, [x] delta round trip, [x] wrong base, [x] tamper, [x] target change, [x] compaction and present-state invalidation.

**Exit:** [x] semantic blocks preserved, [x] no lane escape, [x] no silent truncation, [x] exact delta digest, [x] token-accounting fields distinct, [x] cache-hit p95 target.

## **26.13 WP10 \- context spaces, overlays, commits, and events**

**Prerequisites:** WP03, WP04, WP07; compiler integration may follow WP08.

**Owned paths:** cigar-space hierarchy, commits, overlays, merge, leases, event stream, project links.

**Build tasks:**

* [x] Implement space creation, base and overlay view, fork, checkpoint, publish, optimistic revisions, deterministic safe merge, conflict objects, advisory leases and fencing, scoped at-least-once event stream, resumable cursor, focus branches, and project federation.

**Tests:** [x] two through 64 writers, [x] stale revision, [x] safe and conflict merges, [x] overlay existence isolation, [x] event duplicate and reconnect, [x] slow subscriber, [x] revocation priority, [x] offline branch, [x] task switch and resume, [x] project cap and link preview.

**Exit:** [x] no lost update or silent decision/instruction overwrite; [x] no overlay leak; [x] cursor has no semantic gap; [x] Project B remains invisible to A-only context.

## **26.14 WP11 \- handoff and agent result protocol**

**Prerequisites:** WP07, WP08, WP09, WP10.

**Owned paths:** handoff types and service, capsule signing, acceptance, result and merge, fixtures.

**Build tasks:**

* [x] Implement creation preview, capability intersection, signed capsule, nonce and expiry, revocation, recipient validation, per-source reauthorization, partial acceptance, role bundle compile, acceptance receipt, topic subscription, child result and parent merge.

**Tests:** [x] forged, [x] modified, [x] expired, [x] replayed, [x] wrong audience or recipient, [x] revoked key and principal, [x] inaccessible source, [x] target restriction, [x] clock boundary, [x] generated grant lattice, [x] transcript exclusion, [x] merge conflicts, [x] recipient inspection.

**Exit:** [x] zero authority amplification; [x] accepted bundle is deterministic and inspectable; [x] inaccessible source does not leak; [x] reference handoff stays within 20% baseline and passes first-action outcome gate.

## **26.15 WP12 \- effect journal and reference connectors**

**Prerequisites:** WP02, WP03, WP04, WP07. May develop state model before compiler completion.

**Owned paths:** cigar-effects, effect migrations, connector SDK, reference connectors, crash harness.

**Build tasks:**

* [x] Implement state machine, intent and approval digest, event hash chain, current projection, outbox, attempt and fencing, dispatcher, receipt storage, unknown, reconciliation, compensation link, expiry, cancellation, and operator actions.  
* [x] Implement demo issue service, filesystem, idempotent HTTP, and optional GitHub issue connector.  
* [x] Implement stable failpoints and reference model.

**Tests:** [x] model-generated transitions, [x] invalid events, [x] approval staleness, [x] key collisions, [x] connector capability lies, [x] two-worker claims, [x] EFX-C01 through C24 process-kill matrix, [x] idempotent and non-idempotent unknown behavior, [x] journal corruption, [x] compensation.

**Exit:** [x] no dispatch before durable authorization; [x] 100,000 fault campaign has zero duplicate logical effects; [x] every possible remote ambiguity is explicit; [x] unsafe retry is impossible through public API.

## **26.16 WP13 \- decision records and replay**

**Prerequisites:** WP08, WP09, WP12.

**Owned paths:** cigar-replay, decision capture, recorded providers and tools, replay diff, completeness.

**Build tasks:**

* [x] Capture observable input and output envelopes, verification, usage, and effects.  
* [x] Implement evidence, invocation, observational, and live modes.  
* [x] Implement recorded consumer, tool, and connector providers; no-egress barrier; structured diff and completeness report.

**Tests:** [x] exact evidence and invocation, [x] missing source and component, [x] tampered input, [x] no network under OS isolation, [x] connector panic guard, [x] live new execution, [x] new effect authorization, [x] cross-SDK reproduction.

**Exit:** [x] non-live replay has zero external calls; [x] missing dependencies never substitute current data; [x] deterministic fixture reproduces through every SDK.

## **26.17 WP14 \- daemon, APIs, authentication, and operations**

**Prerequisites:** WP04 through WP13 for complete composition; transport skeleton may start after WP01.

**Owned paths:** cigar-api, cigar-daemon, cigar-extension-host, OpenAPI and Protobuf generation, auth, worker runtime, deployment base.

**Build tasks:**

* [x] Compose services and bounded workers with Axum and Tonic.  
* [x] Implement local socket and token fallback, TLS, OIDC, service mTLS, deadlines, quotas, compression and body limits, idempotency and revision middleware, pagination, SSE and gRPC streams, health, readiness, configuration, graceful shutdown, and OTel.  
* [x] Implement the signed extension manifest, WASI and isolated-subprocess hosts, framed canonical-CBOR ABI, capability broker, opaque handles, deadline and resource enforcement, deterministic vector runner, and remote extension bridge.  
* [x] Add non-root container and systemd unit.

**Tests:** [x] HTTP/gRPC semantic differential, [x] exact route enumeration, [x] malformed and oversized input, [x] auth attacks, [x] cursor forgery, [x] stream backpressure and resume, [x] cancellation, [x] worker exhaustion, [x] shutdown at dispatch, [x] broken dependency readiness, [x] local public-bind refusal, [x] extension signature and ABI confusion, [x] sandbox capability escape, [x] extension resource exhaustion and crash isolation, [x] load target.

**Exit:** [x] semantic conformance identical in embedded and daemon modes; [x] restart loses no commits or effects; [x] API errors stable; [x] readiness reflects migration, journal, blob, policy, and index state; [x] hostile extension fixtures cannot escape declared capabilities or mutate trusted state outside a validated host call.

## **26.18 WP15 \- complete CLI**

**Prerequisites:** WP14 for remote mode; embedded service interfaces available.

**Owned paths:** cigar-cli, shell completions, man pages, CLI tests.

**Build tasks:**

* [x] Implement every command in Section 15, text and JSON output, dry run, confirmation, noninteractive mode, embedded and daemon target, progress, cancellation, deadline, config explanation, doctor, backup, and release verify entry points.

**Tests:** [x] golden JSON and errors, [x] TTY and pipe, [x] no color and Unicode fallback, [x] narrow terminal, [x] secret redaction, [x] paths with spaces and Unicode, [x] confirmation absence, [x] interrupt, [x] stale daemon, [x] corrupt store, [x] unknown effect, [x] package-installed E2E.

**Exit:** [x] installed CLI completes init through replay and effect recovery; [x] commands are documented and completion scripts pass shell syntax checks.

## **26.19 WP16 \- Rust, TypeScript, Python, and Go SDKs**

**Prerequisites:** WP01 and stable API subset from WP14.

**Owned paths:** sdk/, generated clients, high-level helpers, SDK examples and package metadata.

**Build tasks:**

* [x] Generate wire types and clients; implement idiomatic high-level APIs, streams, cancellation, deadlines, stable errors, idempotency, safe retry, digest and delta verification, version negotiation, and examples.  
* [x] Rust supports embedded and remote. Other SDKs support remote and local digest operations.

**Tests:** [x] protocol vectors, [x] API contract, [x] pagination, [x] stream resume, [x] cancellation, [x] server compatibility, [x] retry classes, [x] idempotency preservation, [x] handoff, [x] effect reconciliation, [x] replay, [x] package install in minimum supported runtimes.

**Exit:** [x] capability manifest shows parity; [x] each quickstart produces the same semantic bundle ID; [x] no SDK automatically retries unsafe dispatch.

## **26.20 WP17 \- Claude Code plugin, MCP, hooks, and skills**

**Prerequisites:** WP09, WP11, WP12, WP14, WP15.

**Owned paths:** adapters/claude-code, cigar-mcp, hook executable, installer, fixtures.

**Build tasks:**

* [x] Implement plugin, compatibility matrix, MCP tools and resources, hook parser and mappings, idempotency, task and present-state accounting, compaction checkpoint, subagent handoff, skills, installer, uninstaller, and doctor.  
* [x] Use documented public surfaces only and keep descriptions and outputs bounded.

**Tests:** [x] fake-home install and byte-preserving uninstall, [x] every event fixture, [x] malformed and oversized event, [x] duplicate event, [x] daemon unavailable, [x] socket permission, [x] compatibility mismatch, [x] prompt timing, [x] no model call, [x] bootstrap budget, [x] no duplicate injection, [x] governed effect before dispatch, [x] static private-path scan.

**Exit:** [x] fixture demo passes on all supported platforms; [x] live controlled smoke passes for each claimed Claude range; [x] adapter failure does not corrupt host; [x] all injections are explainable.

## **26.21 WP18 \- PostgreSQL, object storage, and shared deployment**

**Prerequisites:** WP03 repository suite, WP12 effect suite, WP14 runtime.

**Owned paths:** PostgreSQL and object implementations, shared migrations, OIDC/mTLS profile, Compose and Kubernetes deployment, shared runbooks.

**Build tasks:**

* [x] Implement transactional metadata, row-level tenant defense, object CAS, outbox and invalidation workers, shared event wakeup, pool and timeout tuning, backup and restore integration, rolling-compatible migrations, deployment manifests, and observability.

**Tests:** [x] repository and semantic differential against SQLite, [x] serialization storms, [x] failover, [x] replica lag, [x] outbox claims, [x] object partial upload and missing object, [x] credential expiry, [x] 64 clients, [x] 10M scale, [x] rolling adjacent version, [x] backup restore.

**Exit:** [x] all claimed conformance profiles pass in shared mode; [x] no lost update or duplicate effect; [x] 10M benchmark publishes curve; [x] S3 failure leaves no metadata pointing to unavailable committed blob.

## **26.22 WP19 \- conformance, security, fuzz, and quality hardening**

**Prerequisites:** All feature paths required by claimed profiles.

**Owned paths:** conformance runner and vectors, fuzz, security, chaos, compatibility, traceability, quality reports.

**Build tasks:**

* [x] Implement all conformance profiles and sandbox runner.  
* Complete tests/invariants.yaml, cross-language differential, security corpus, fuzz targets, property suites, concurrency models, sanitizers, mutation, crash and chaos harness, no-egress, migration and install matrices.  
* [x] Implement content-free support bundle and deep doctor.

**Tests:** reference passes; intentionally faulty implementations fail each hard invariant; seven-day-equivalent fuzz; mutation thresholds; full adversarial and chaos corpus; no canary leak.

**Exit:** every normative requirement maps to evidence; no critical or high exploitable defect; all stop-ship security and integrity gates pass.

## **26.23 WP20 \- demos and CIGARBench**

**Prerequisites:** WP15 through WP19.

**Owned paths:** demos/, benches/cigarbench, baselines, analysis, installed-artifact test driver.

**Build tasks:**

* [x] Implement seven demos and four SDK quickstarts with deterministic recorded mode.  
* [x] Implement datasets, manifests, baselines, runners, raw event schema, statistical comparator, reports, replay, and environment capture.  
* [x] Prevent benchmark-specific compiler configuration from entering default profile.

**Tests:** demos assert outcomes offline; installed artifact mode; paired and randomized benchmark dry runs; report reproduction from raw events; hidden seeds; canary scan.

**Exit:** all demos pass with distribution artifacts; performance and outcome gates pass with confidence intervals and per-stratum reports.

## **26.24 WP21 \- packaging, documentation, and operational readiness**

**Prerequisites:** WP19 and product surface completion.

**Owned paths:** packaging, installers, images, docs, runbooks, SBOM and provenance, release verifier.

**Build tasks:**

* Build artifact matrix, package contracts, clean install and uninstall, source archive, docs site, API references, runbooks, license and notices, SBOMs, signatures, provenance, reproducibility, release-evidence schema and assembler.  
* Execute backup, restore, key rotation, migration, index rebuild, unknown-effect, journal quarantine, and adapter-disable runbooks.

**Tests:** clean unprivileged machines, offline use, Unicode and long paths, upgrade, archive contents, version consistency, double build, corrupted signature and swapped artifact, docs commands and links.

**Exit:** every artifact installs and verifies; two builders produce matching payloads; docs examples execute; operations exercises create evidence.

## **26.25 WP22 \- release candidate and v1.0.0**

**Prerequisites:** WP00 through WP21 complete at the exact candidate commit.

**Owned paths:** release manifest, candidate evidence, final version changes, distribution staging.

**Build tasks:**

* Freeze schema v1 and versions.  
* Build source and binary artifacts in isolated release workers.  
* Run the qualification sequence in Section 28 using installed candidate bytes.  
* Run 24-hour soak, 100,000 effect faults, scale, efficacy, migrations, clean installs, demos, and reproducibility.  
* Generate and verify release-evidence.json.  
* Promote the exact verified bytes without rebuild.

**Exit:** cargo xtask release verify dist/ passes with no waiver or skipped condition; all claimed platforms and profiles are backed by actual artifact tests; the v1.0.0 tag points to the evidence source commit.

# **27\. Codex execution control protocol**

## **27.1 Kickoff procedure**

On an empty repository, Codex SHALL:

1. Create the WP00 skeleton only.  
2. Copy the machine-readable templates from Appendices A and B.  
3. Set WP00 to in progress and every other packet to not started.  
4. Record the effective workspace path, available toolchains, platform, container capability, and network policy.  
5. Run the existing tests before modifying any nonempty repository.  
6. Record unrelated existing changes and preserve them.  
7. Implement the smallest real WP00 vertical slice.  
8. Run WP00 exit commands and capture artifacts.  
9. Mark complete only after independent readback of generated evidence.

On an existing partial repository, Codex SHALL inventory packages, schemas, migrations, tests, and open status; map them to work packets; run current gates; and mark a packet complete only when this specification's exit criteria actually pass. Existing code is evidence to inspect, not proof of completion.

## **27.2 Work packet selection**

Select the lowest-numbered incomplete packet whose prerequisites are complete and that is not blocked. Security, data-integrity, compatibility, or canonicalization failures take precedence over feature progress. A downstream demo failure is fixed in the owning component rather than patched around in the demo.

No packet is marked complete based only on compilation. Required negative paths, tests, docs, demo, and evidence are part of the feature.

## **27.3 Parallel agent use**

Parallel agents MAY work when:

* They own disjoint crates or package directories.  
* Shared schema and trait contracts are committed and frozen for the packet.  
* One integration owner controls generated artifacts, migrations, lockfiles, and public API changes.  
* Each agent has a scoped task, exact base revision, allowed paths, required tests, and expected result capsule.  
* Results merge through ordinary code review and the affected combined tests.

Parallel agents MUST NOT independently edit the same schema version, migration sequence, canonical vector, error catalog, release manifest, or dependency lock. A generated-file conflict is resolved by rerunning the authoritative generator, never hand-merging output.

## **27.4 Change discipline**

Each packet should produce reviewable vertical slices. A slice includes behavior, tests, failure handling, docs, and generation changes together. Avoid giant placeholder scaffolds that compile but return fake success.

Before finalizing a slice, inspect for:

* Unrelated file changes.  
* Secrets or real user data.  
* Panics, unchecked indexing and conversion, or ignored results.  
* Unbounded collection, recursion, queue, output, or concurrency.  
* Blocking I/O on async workers.  
* Hidden time, random, environment, locale, map-order, or filesystem dependencies.  
* Error, trace, or metric data leakage.  
* Missing cancellation or deadline.  
* Unsafe mutation retry.  
* Cache or index behavior that bypasses current policy.  
* Migration without recovery test.  
* Public behavior without schema, compatibility, and documentation update.

## **27.5 Test order for every slice**

cargo xtask fmt \--check  
cargo xtask lint \--changed  
cargo xtask generate \--check  
cargo xtask test unit \--changed  
cargo xtask test property \--changed  
cargo xtask test integration \--affected  
cargo xtask test conformance \--affected  
cargo xtask docs \--check \--affected

Run security, fault, fuzz, performance, SDK, or package gates whenever their owned surface changes. Record exact commands and result files.

## **27.6 Blocker protocol**

For a blocker, Codex records:

* Work packet and exact requirement.  
* Reproduction command and smallest fixture.  
* Actual and expected behavior.  
* Data integrity, security, compatibility, and schedule impact.  
* Options considered and their tradeoffs.  
* Recommended resolution and downstream packets affected.  
* Whether safe independent work can continue.

It does not relax an invariant, change a released vector, or make a permissive security choice to clear the blocker.

## **27.7 Resume and context compaction**

IMPLEMENTATION\_STATUS.md and docs/execution/work-packets.yaml are the durable execution context. Before ending a session or accepting provider compaction, Codex records current packet, completed steps, changed files, commands and results, active failures, next action, and uncommitted decisions.

On resume it reads status, current diff, packet contract, relevant schemas, and failing tests before changing code. It does not reconstruct state from conversation memory alone.

## **27.8 Completion report for each packet**

The report states outcome first, then:

* Delivered behavior and public contracts.  
* Paths changed.  
* Exact test, demo, fuzz, benchmark, or package commands.  
* Evidence artifact digests.  
* Performance before and after where relevant.  
* Compatibility and migration impact.  
* Remaining limitations that are outside the packet and already represented in later work.  
* Recommended next unblocked packet.

## **27.9 No-waiver rule**

Codex cannot declare v1 ready when a required gate is skipped, flaky, quarantined, weakened, or run against workspace code instead of distributed artifacts. If a platform or feature is not tested, remove it from the release claim and artifact matrix; do not mark it passing.

# **28\. Release-candidate execution sequence**

## **28.1 Clean-source qualification**

Run from a fresh checkout of the exact candidate:

cargo xtask bootstrap \--verify  
cargo xtask fmt \--check  
cargo xtask generate \--check  
cargo xtask lint  
cargo xtask docs \--check  
cargo xtask test unit  
cargo xtask test vectors  
cargo xtask test compatibility  
cargo xtask test integration  
cargo xtask test conformance  
cargo xtask test e2e  
cargo xtask test security  
cargo xtask test offline  
cargo xtask fuzz smoke  
cargo xtask test models  
cargo xtask test coverage \--verify  
cargo xtask test mutations \--verify  
cargo xtask test chaos  
cargo xtask test migrations  
cargo xtask bench micro \--verify  
cargo xtask bench macro \--verify  
cargo xtask bench efficacy  
cargo xtask package \--all  
cargo xtask package \--smoke dist/  
cargo xtask release reproduce  
cargo xtask release sbom  
cargo xtask release sign  
cargo xtask release attest  
cargo xtask release verify dist/

## **28.2 Installed-artifact qualification**

1. Install every artifact in fresh target-specific machines.  
2. Run conformance using installed executables and SDK packages.  
3. Run every deterministic demo and quickstart from the installed artifacts.  
4. Upgrade every retained previous catalog and journal and verify integrity and replay.  
5. Run clean uninstall and verify user and host configuration preservation.  
6. Run local sidecar soak and shared-service load and chaos on exact binaries and images.  
7. Compare independent build payload digests.  
8. Assemble release-evidence.json and verify schema and signatures.

No candidate step may use \--skip, vector blessing, ignored tests, reduced fault count, lower threshold, or locally patched artifact.

## **28.3 Soak requirements**

The 24-hour profile runs mixed ingestion, compile, delta, context switching, handoff, event streams, effect dispatch and reconciliation, replay, backup, and GC. It varies 1 through 64 sessions and injects bounded dependency failures. It monitors memory, file descriptors, tasks, queue age, lock time, unknown effects, and data roots.

Pass criteria are no memory or descriptor trend beyond documented cache stabilization, no deadlock, no lost commit, no stuck lease beyond expiry, no unexplained unknown effect, no unbounded queue, no unauthorized output, and no digest difference from the reference model.

## **28.4 Final release evidence**

The release evidence contains source and artifact digests, toolchains, platform, schema and protocol, every work packet, traceability, tests, coverage, mutations, fuzz hours, sanitizer and model results, fault counts, security scans, migrations, conformance, performance, CIGARBench, demos, installs, soak, SBOM, signature, provenance, and reproducibility.

Every result is bound to the candidate source and exact artifact. Human prose may summarize evidence but cannot replace a required machine-readable result.

# **29\. Production definition of done**

CIGAR v1 is complete only when a new user can install a distributed artifact, preview and catalog a real repository locally, compile governed task context, inspect every selection, switch projects and task branches without contamination, resume from a checkpoint, delegate a constrained handoff to another agent, merge typed results, observe meaningful physical token reduction without verified outcome loss, prepare and recover a journaled effect, and reproduce the observable decision environment from another runtime.

The same canonical records and behavior must operate in embedded, local-sidecar, and shared-service profiles. Rust, TypeScript, Python, and Go must agree on protocol identity. The Claude adapter must use public MCP and hook surfaces, remain bounded and inspectable, and uninstall safely. Every published claim must be backed by a reproducible demo, benchmark, conformance result, fault campaign, package test, or recovery exercise.

The release is not complete if any stop-ship condition remains, any required evidence is missing, or any artifact differs from the verified candidate bytes.

# **Appendix A. Implementation status template**

\# CIGAR v1 Implementation Status  
   
Source specification: CIGAR v1 Production Implementation Execution Spec  
Repository revision: \<commit or workspace digest\>  
Updated: \<UTC timestamp\>  
Executor: \<agent/run identity\>  
   
\#\# Environment  
\- OS/architecture:  
\- Rust toolchain:  
\- Node/pnpm:  
\- Python/build tool:  
\- Go:  
\- Container runtime:  
\- Network policy:  
   
\#\# Work packets  
| Packet | Status | Base | Owner | Evidence | Blocker |  
|---|---|---|---|---|---|  
| WP00 | in\_progress | ... | ... | ... | ... |  
   
\#\# Current packet  
\- Objective:  
\- Prerequisites verified:  
\- Owned paths:  
\- Files changed:  
\- Tests added:  
\- Commands run and results:  
\- Performance evidence:  
\- Security/compatibility impact:  
\- Active failure or blocker:  
\- Exact next action:  
   
\#\# Workspace state  
\- Existing unrelated changes preserved:  
\- Uncommitted changes:  
\- Generated files current:  
\- Migration/schema owner:

# **Appendix B. Machine-readable requirement template**

id: FR-CTX-008  
title: Deterministic bundle identity  
criticality: safety\_critical  
source: CIGAR-v1-execution-spec  
implementation:  
  \- crates/cigar-compiler/src/compile.rs  
  \- crates/cigar-canon/src/bundle.rs  
tests:  
  \- id: CTX-G001  
    type: golden  
    command: cargo xtask test vectors \--case deterministic-bundle  
  \- id: CTX-P001  
    type: property  
    command: cargo xtask test property \--case compile-permutation  
  \- id: CTX-X001  
    type: cross\_platform  
    command: cargo xtask test compatibility \--case bundle-digest  
evidence:  
  metric: deterministic\_digest\_equivalence  
  threshold: 1.0  
release\_blocking: true

# **Appendix C. Minimal end-to-end acceptance script**

\# Start local daemon in an isolated home  
export CIGAR\_HOME="$PWD/.tmp/cigar-home"  
cigar serve \--background \--output json  
   
\# Initialize and ingest the synthetic quickstart  
cd demos/quickstart/repository  
cigar init \--non-interactive \--yes \--output json  
cigar ingest \--consistency strong \--output json  
   
\# Compile and inspect  
cigar context compile \\  
  \--goal "Fix the duplicate retry race and add a regression test" \\  
  \--budget 6000 \\  
  \--output json \> .tmp/bundle.json  
cigar context explain \--bundle-from .tmp/bundle.json \--output json  
   
\# Create and accept a read-only handoff  
cigar handoff create \\  
  \--role test-researcher \\  
  \--capability repo.read \\  
  \--budget 2500 \\  
  \--output json \> .tmp/handoff.json  
cigar handoff accept \--from .tmp/handoff.json \--output json  
   
\# Exercise effect recovery fixture  
cigar effect prepare \--connector demo-issue-service \\  
  \--operation update \--arguments demos/effect-recovery/update.json \\  
  \--output json \> .tmp/effect.json  
cigar effect dispatch \--from .tmp/effect.json \--output json  
cigar effect reconcile \--from .tmp/effect.json \--output json  
   
\# Reconstruct without egress  
cigar replay reconstruct \--decision latest \--mode observational \\  
  \--deny-network \--output json  
   
\# Verify system  
cigar doctor \--deep \--output json

# **Appendix D. Release artifact manifest**

dist/  
  source/  
    cigar-v1.0.0-source.tar.zst  
  binaries/  
    cigar-\<version\>-\<target\>.\*  
    cigard-\<version\>-\<target\>.\*  
    cigar-conformance-\<version\>-\<target\>.\*  
    cigarbench-\<version\>-\<target\>.\*  
  containers/  
    oci-index.json  
  sdk/  
    npm/  
    python/  
    go/  
    rust-crates/  
  adapters/  
    claude-code-plugin.zip  
  protocol/  
    schemas-v1.zip  
    conformance-v1.zip  
    cigarbench-fixtures-v1.zip  
  docs/  
    docs-v1.zip  
  evidence/  
    release-evidence.json  
    conformance-result.v1.json  
    performance-result.v1.json  
    efficacy-result.v1.json  
    soak-result.v1.json  
  security/  
    sbom-spdx/  
    sbom-cyclonedx/  
    vulnerability-scan.json  
  checksums.txt  
  checksums.sig  
  provenance.json  
  provenance.sig

# **Appendix E. Codex master execution prompt**

You are implementing CIGAR v1 from the CIGAR v1 Production Implementation Execution Specification. Treat the specification, protocol schemas, canonical vectors, and security invariants as binding. Begin by reading IMPLEMENTATION\_STATUS.md, docs/execution/work-packets.yaml, the current diff, and the lowest unblocked work packet. Implement one dependency-safe vertical slice at a time. Every behavior requires production error handling, limits, cancellation, tests, documentation, and evidence in the same slice. Do not add placeholder success, silent fallback, permissive authorization, unsafe effect retry, private provider dependency, or unbounded processing. Preserve unrelated user changes. Stop and record a blocker for any security, canonicalization, compatibility, migration, data-integrity, or effect-safety ambiguity. Run the packet's exact gates, update status and evidence, and proceed only when prerequisites and exit criteria pass. CIGAR v1 is ready only when the installed-artifact qualification and cargo xtask release verify dist/ pass without waivers.

# **Appendix F. Final stop-ship checklist**

* \[ \] No unauthorized content, existence, secret, project, tenant, purpose, or processor leak.  
* \[ \] Canonical digests are deterministic across all SDKs and supported platforms.  
* \[ \] Mandatory context is included or compilation fails explicitly.  
* \[ \] Instruction and evidence lanes cannot be crossed.  
* \[ \] Every selected catalog block has provenance and reason.  
* \[ \] Every considered eligible candidate has a disposition.  
* \[ \] No materializer semantic drift or silent truncation.  
* \[ \] No mediated dispatch before durable intent and authorization.  
* \[ \] No unsafe unknown retry or duplicate logical effect.  
* \[ \] Non-live replay has zero network, model, tool, or connector call.  
* \[ \] No lost committed journal event or partial canonical state.  
* \[ \] Supported migrations, backup, restore, and projection rebuild pass.  
* \[ \] Security, fuzz, sanitizer, model, mutation, coverage, and chaos gates pass.  
* \[ \] Performance and CIGARBench outcome gates pass.  
* \[ \] Claude plugin install, fixtures, degradation, and uninstall pass.  
* \[ \] Every SDK and demo passes from distributed packages.  
* \[ \] All artifacts are version-consistent, scanned, reproducible, signed, and accompanied by SBOM and provenance.  
* \[ \] release-evidence.json is complete, current, and verified.  
* \[ \] No required test is skipped, flaky, quarantined, or weakened.  
* \[ \] cargo xtask release verify dist/ passes on the exact v1.0.0 bytes.

# **Appendix G. Final execution directive**

Build the smallest correct kernel first, prove every invariant at the layer where it is enforced, expose one portable contract to every consumer, and refuse to trade context quality, isolation, durability, or effect safety for apparent implementation speed.

[image1]: <data:image/png;base64,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m9MylLN73yEdnVhLilh7tXpL619vfMCav3St3nRVWlLE2i33vk6/KQvrtyigWPMxnAwatetnhzv1/VhtLWyjWEuuhR2Acuk3s54Rbtyhv7E1e9a886DE+TTuYu1//vi0XadPv93IXq/SqIs7wVVqcRdrZ86dd13Y5NtvcR5fw/otCijWfEwa2dNvNfTEPfFGfXt54NAxa87i1U5jNE8SkvadOu1d62/WautK86dH37GXv77rZSeuQo3W1vd/eb+1Yu0WOy7fVkhiDctv/6KcJw788KaHnfDhoyfs5X/85hHftGD6nOIPNMs6Zl7NdMj7Rs021uMV6ttxUVjYASiXfpO6kvBzFZs4dVm+UjNnO04sEn/rfa874b898Z6rvuUEhHDF+h3tPgP7y2MV7biqjbs628EfH3nbcwx/fvRde1mzRQ9X2nfrdbCGXJlRx/qLlZvbS9lHti3uYk3qRRvibrzzJdd2CZd7vrq97DZwjBOPepV05ngpac380ia+c9091o9vedT6w8Nv29t/dHNxvzX7H/odwujT//brB+0wZpLeqt3ObkO5sriLNdMvOh5+++ltjzvbr/tb+WIf1S32kek3IOMoTHzwdp12rvLFL3c8XdmVV/dFOYfCpL//9oE3nf5+c7lXrZerfuAqO9sW1m9RQLHmY2fPXXAaFsBtGyz7DJ9gb5f40sSamG50ItpMJN2dT1exjp7I7eCbygpNrMGmfLbYE2em9UOn0etCmx7DnbCc9KOysANQLv2m680v7p///KczeOt8n0z63BVnijVc4Eif0TNreh8jP53lxMPOX7ho35o148TwCITOnwtLolgTgSQmYTMtljf8/QUn/Ohrda3Ll7+011OJtc3b9zhhMV2+gP7ndyygWpNuTlwuLMliTYch1sZMmePEmX7Taf18YE5EmOn98kt4z/7Dvv39B796wG4fubSwfosCirVSDI0Ht0SxfOadxk7c//3D09aq9Vudhvbd6+/zNGazjF17DzrrvYd96mnYpun8+bRCFGumqMbyyy+/cqWFL/3q+/1m3T2+QFhOJn7mV06+LOwAlEu/+dWLX5wevMVw29T0oX5mDXFrN263WnYb4vHXqTPnjJQl8Tqs97tp2x5PXC4sKWINYlqs19DxTt2s27TDVYdmGCLANNnWpd+owDw6rRnGUvc/LdZMC4rPhsVdrJl9xjS/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>

[image2]: <data:image/png;base64,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>

[image3]: <data:image/png;base64,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>

[image4]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAmsAAAFeCAYAAADaE1hnAABn70lEQVR4Xuy9ddjkxpX2/f6/zHm/b/O+m80X8GYTBzbgOGsH1rETO7bjMY0ZxzDsYWZmZmZmZmaeeYaZmcEztuvrUz1HUzpSg7qlavXz3Oe6fleViqQunSrdXVKr/9ftu18oAAAAAAAQT/6XTAAAAAAAAPEBYg0AAAAAIMZArAEAAAAAxBiINQAAAACAGAOxBgAAAAAQYyDWAAAAAABiDMQaAAAAAECMgVgDAAAAAIgxEGsAAAAAADEGYg0AAAAAIMZArAEAAAAAxBiINQAAAACAGAOxBgAAAAAQYyDWAAAAAABiDMQaAAAAAECMgVgDAAAAAIgxEGsAAAAAADEGYg0AAAAAIMZArAEAAAAAxBiINQAAAACAGAOxBgAAAAAQY2Ij1oZOmKv+4ltPOGzedcBTJh+43e8+/ronD+QH9+37Ndt58kDxwedz8Lg5nrwo4P3JdAAAAEkKLtaGT57vEmkSWT5XINbyg/tvwcrNKfMg1koHfD4h1goP+gYAQBRUrI2bscQlzP7qO0+qqk26q9cqNQ99kuL2INZyg/vPT6yB0gXEWnxA3wAAiIKKNVOoTZi1zJMvea1yC1cd4vqtzz3lpsxb6Spj7kuKtXa9R3vaPHXuspN/4/bnTvrYhLjkdNl+Os5cuOLZx6VrN538C1duOOkrNuxw0pt0HuK7j537j3rak/uU7TIkiDmf08w+2Xv4pKdN2UaqfLmy9szbdTx1Rkxe4Cpj5l29cdu1/d8vVHKV9UMeS7Zp8rgYOt9+ZVLt97n36jlp2Z4XWYagxwBkOYmsQ9CXm1TlKP7jp953tv/hP5/2lH2zaisn/6+/m/QN3s4k1szjMLfJ37nM3/3HH1zluKxfOzK9bpt+nrrmuCHomGUZYuXGna5yN+/c9ZQh/vLbv3eV6ztyuqfMwWOnPceWCrPett2HXNtcpk5r7+ci3q7e2ilDY0nmy3bk/vzyif/644eeMsSWkoOesgCAeBIbsSbzJHKiMfnWf5d3yv3kDx948k1MYfLPP/iTJ5/52o+ec8pdu3nHSaftv33owQXIvLj7QeJIts1857EHx3L24lXXPkzBabYn2zAxy9FFSObLcrwdhViTZU1+8aePsipHmJ/JDy730K/f0NsvfNjQSTt3+ZpOq9Git6c9uR+Tecs3eMqZ+5y2YLUnXbZh8tLHjTOWa9l9hGsffsg6JtmWm7lobVbliCBizYTFmkw38WvHTEs3bvzq+kHjNptyXObff/mKJ4+hMW/uV1Jy4JinjoTLftqgiydPlstGrMl0vzJ+4pNZsmar53MAAOJJwcTa9j2HnUmDvt3LfJNDJ846Zd/5rI2TToJKTk5+E1bNln2cNFOYcNoHtdp70sz6Zrop1Gq37usqI5ErRbKtVPv43z9+3on3HDrFyd+4Y7+TPneZV1Bks4/PmvfylMkk1syyfrdBOS+VWOO0v3noKU+aWW6xcfHgNLqwyf357ZvbNLcfK5dcmePtb/ziZafekPFeISLbMtP+9E5dT9q//PBZvZ3LeZH77jpooictE37tp0rPNu3//KyckxZUrHE6rX79/ff+6NsOp7XuOdKTxtvmuGnaZain3Mf1Ojlpr3zSNOVx/fPDyfPjtw+my8AJnjJmuX/9rxc8aX741b31+T3fdJqPsqlvpsvy3QZPcvIOHT+j08x+O3A0uRpofiE161++fsu1ig8AiDcFE2vrt+11JpEKdTp48k1STWRmXpXG3dW6bXsylmNhQqtxfmXp1ptfujwOv3yJuTog8zKl++WnSjdvt9C2edv16Knznn3I9sIWa9mchw79xrq2ZVm/Y/ND1je3ZZqse+LsRb3qJeuYZY+cPOdJS7Ut9yHPiyz78O/fzSiITEgE0RebTLcWOS3VypJMox/5+NXPdGx+bWbK80uX26nGzb/94iXfdLqd9/TbtX1vicp9MDMWrXG1YZYh0eOXTuJL1pFl5LGlSid+92p1l6j1K+eXlq5dmd6qxwhXGj1KsvvgcU97AIB4UzCxRsiJJRXpynH6s+/WU9MXem9PyXJ88TfbTEWqNlLlS2R5PzLVSZfnB5VbvbnEt76Ey3zz0VedtDVbdvvW5bRsxJr5w5FUZSs2TK6Y8bYsy2mZxFr7vmOdsnzLh1bQqH1uM137qfArS6uSfmVkXT/82jP53m/f9Hw2ExIjsk6m9v3SzHTepnPuVzYssZYKWVZupyPbslyOVpJkniwj0yULV3l9369upnTZrsSvfrr9pYLL/t+fv+jJI17+pImnXQBAPImNWDMfSpb87OkKnglItkECwbztQILFrxxf/H/+zEcp2/TDPNZs65m3M2WeH0++XjPtPlKl+8HlPmvW05Mny5jt/e6Vap40s+z8FZtStsNizTwP5q0W89k/Pj9+x2CmZxJrsg1i0879Trr5MDeXnzR3hZP2n799y0lPdctLtk/Qjyf88uWxpWPHviPqH7//TFZ1uQytxHAa3QL0q5suzUzn7ec/aOBbNiyxJvMkslyQccPlKjXs6klLV9+vjNwOgl97funmDx3MH9vIcjI92/1lot+oGTnXBQAUjoKKtefer++aOKonhMXp85cz3j6ifL9ffMpy9FwMPWRupvk9s2Y+6E/s2p98WNhMM/fjt99UpCrLzznxtilwaJueh5P1zF93vlGlpau9ecs3usqa+/2obvIZH7pVnKrMxas3XCuTZjlZ9p9+8Iz6+k/LefJSPbO259AJNXraIt+2/dLM9FzEml/6//OTPzvpjToMctL5WbR9R076tuHXlswPcl5olcPMNx8HkPs04TL0ELxMk3XTpZnpZhqNJ3mO8hFrdIuX8556o6Yrj86p37Nofm3TFzUzncaNn58Nm5S8lSs/A5f7w5u1XO28XuXBL8tlW/JY6Jkw+atRSf/RM1316Xk5c5vb5LmF2L73SMZ9m+nkwzzulq3b7qTTL9rNOuSD9DgDxWu16qN/pZyqTTMdABBfCirWiB8++Z5r8pCYZWWeXxm/cuYtJPPi7/dqC792ebt+uwGeNLOcH/TMmGzXry5v9xk53Ul78aMHz1NxGv2CS7bh1548Rr8yfm2lemaNLiyyrNyPfHWHLC/ryTJ+6dmINfMHJH7HJduWeea+si0v8/360q+8TGfMXzT7QV8oZB3zF4N+x+qXli6dMH/pmo9Yk/mSTGIt3bjxE2upyKYclzFf0+OH/HySDdv3ucrTD5f86st2JWab9AU2Vb5MNzHFmsxjylVo5PkMAIB4UnCxxtCrF8yJhISKLEOQYKJvmLTCYP6SS0K/BKTngGhlQ+aZXLnhfZaFjoWecZFl80Hug0Sq3zviskW29/iLlT1lCLrVRiKEfolp/rLUhITCH9+q7UkPg/Ezl+pf7dI+eo+Y5skvFMvX73D1H6WlE2skLpjZS9Z58plM58V8xo4x332XDrPOmOmLU4q1oNDrTuQKVliY7wpk0j37ZXLu0oPX2TA0bswy8v1plCa3Cb/XZchVTm5PvvbmG4+8rI9Fls0Gv2MhzB+J9Bo2NWW5TJgrhEyn/uOdfPqxhPkrbEY+pwgAiDexEWsAAFDMkAjiFUPzdUMEPQogywMAQLZArAEAQAjI1SumfMVmnrIAABAEiDUAAAiJBu0H6tv+9COchh0GevIBACAXINYAAAAAAGJMwcTaCxXru+L8dvBhU+eqhWu87/KSjJzufut6GJjHVEiyPY5sy+VDPvuI4hxlwu94/dKyJZ+6ZZEuQx883B6UY2dS/9tGUHI9b/QvEVQ3n89hMnflg78fK0bSnZOw+qhYyNWnMhFVu6B0EQuxVq5SA9W6b/KPrLN13CiEQDb7zqaMLWwcS9B9mOWzOUdB26/Q8MH/uPrh155fWrbkUzcd6S6CxUxcLuC5nreKTR/872iubZgUu1jLhric81SEcR6JsNpJRdjth90eKCwFE2v7jibfA7R1z0H94lp2LDMsOXjM5XAvVW6oduw/rOMsBFjkmVCdXQeOqpeqNFKbS5Jvsx80cZanPYrvPnRcvVwl+b4heQxVWnRVbfqNVDv3H0nsL/m2ccrjY6f4uu27ddvyGFr1Ga7mLF/n2t9rnzVTm3cfcOpuShyb34DiNJoEe4+eqpZt2Oak1evUT33WuofuC07be+Sk6j9uhho3e7F6MZHObVRr1T2RPt3pA0pbun6bLrdx1z4njVYySTCfT5wHTqPzQqHZJ3NXrHcd7zt1Wuly79Vro7epX8z+4XNEx8t1Zi1d68S5XS7fqOuABAMTx7NZdR2WfC0L5dOxdh+e/KPz9+u30eWv3/5cn2M6f7Xa9VJNug9yyr/2WVM1Y8kap47ZnzXb9lTLN27X+zGPw2Td9j3aJ6q27ObUrdKyq6rToU/ifEzRfU9pb9Zq4WqfoQt03Y59Xf7WbsBoNX/VRqffaR/0Ofizf9Cgrdqwc6/Opzobdux1+Xa3xGeZMHep0x6JPTpnVIfSPmnSUfUbO1191Mj/f3Z5xcg8XvJR6j/epj68fP2mjlMfmvvevu+Qqz59lmmLVnn2Qz43cd5S9XbtBy8HpnFEflK9dXfXOKJxVat9b0e4ckh5nQaPVU17DPa0T4ydtUhNXbjSdTzUF6u37FINOvd30sxQxhkauwMmzHTGDfvXyXOXdHnTl6csWKH9knyB2+s5crKrPT6nXI/8gMeXeRw0Dv2Oh9JojqNXCnEa9Qv3l1mH5pOdB5IvvCV/Nv2NvtRwPr2OhNLNfD8f9+srPifkv+Qf7L8EjadDJ85oPzLnRJonaAxzOebC1eu672jOpDpc3jwuCgka22/dH1+yT8nHqA7FyTfXbtvtOnbqa6pP50bOSQz5KB0njamxifmQ9011t+095FwTqJ/IP+YlxrS5D4aPn8Yd+57fl1Q6TnOsyTaOnk6eY57bzHKvVnP/LVjNxHxH8FxBac17DU2M0cP6WLckrjH06inzc/M1gsahOffTMfmNM2pf+tuC1ZvUqsQY4zSad5es25roy2VOGdqmPpPtgfwpmFgjSAjxie8waIx2JDn5nb5w2VOPaD9wtMeJGdPBON55yDgd5+1Ug6ZGmwd/z8TlU9WjOA162Q4xef5yVz2TUTMWeNo14TTzG2uq/XMo28ul3MeNvRd6ypfHW766t99pgpDt8aTFaXQhlPXkcfod3+zlD95rJlfW/MrLts1QlvcjXRsE+52ZNn7OEmfSIrFGwoHiHzZIvsC1x4hJLt9Ot7JmHuPZ++/3IlFhHrdZ3+94JXQR4osfX4j8fFR+3oZdBriOh/PkOGVIcHOcRa1Zn2BxT3RLiB8/sebk3xfcjCl6+BjSHT+dBzofJFjMdhg5L5j+Jdv16wfZnmTaYregpYu62Q59GTPz/dpM5yuEHJ+UJj+HzDf3ky6N903++5YhwAmen+Q8xch5Qn42+vLD52Xx2i16nPsdg8R8550cF6Z/ZGqHvuDk0ifM+h17tNijOL1QOZ1Yk8dp4revtv1H6XDNNvffJspyMp7u8/jlnzrvf301xx31E4U0l5n1G3cbpAWgWU9ug/AoqFgzTzwhBzeRSqzRgDDrynZl/MDx0zqkVSpZxizrV1eWyZRG3zZJfFKcv4WbDJ86z5Pm156cBM0wVZrMk3GJmSeFEOfT8fI3+FTQKqFsjyctnhD8jiPoccqLkIynS0vXvkm6Ngj2U3nLjMuQOOD+kH1KkzatuGa6AJvQaiSvSPI+gog1Wg2idBoDdFFkYc0+asL1D94fL/U69vWUYV6v4X0lRSqxZpZxibXERSGdWJO32IKKNY7zypkJfX6eF7h8Jv8y8UuTyNugtIIqy5j4tZnJV/zmk1Sfwy8tVZ9RKPfN/ktxP7GWbp6Qx5GrWDOR4yJbsea3n2zTmFRibcQ09/nwG78mfvsiaDVMpslyfnXTpUnM1TkTKdaGTnnwbyay/CtVG+sVft7uNWqKaxuEQ8HFmjmZSeeSty1NWAjQrU6Zx3XN26Bv1GyuJxLz4kPldh8+rp3N3D+FJBLptg1dkKmMmccXsha9hvoubdOPJSit79hprgu6PEa61eV3C5Xb8xNr+jZomx76s3Ha/qOn9EWSBALfvqI8On76pmPeBqUJ0bz9ah47T/CU5ncblL7B0/GaK12MKda4f8xvmJR+4cp1Tz1Kp+V2itNy/Pv127puudHKi9n/dBuN2qdbBXw7hFaKzONMdRu0O60O1GqhbzOZn1vCt4iqtfLeBu0zZqojQsy2yYc47ifWKI8+F016PJFNXrDc6SsTKkvfqOl2LW2fOn9Jiw26dcT7CCLWKG3WMu/FguLUf3Q72yzPK28MrTbTOeAJnCZv+iw0puS+krdBl7naJD+k/qDbKOZ5ovGYvA16QadlI9YIuo1Pt2DNtjjPL41WPV+p5v1HFOpf+gx0zFxeihwWc2NmLdKrYOZtIL++Jup37uecVynWuB6NoQ4Dx+iLvMyT5Z3boIn+8ssnaNzQOeL5xPwcfBuU8nmVxM/H6bhpDJqf0Twni9dtcfkvnxvK489LcZonyD/kPMG3QUnkpLsNyuXNOM0RfmOFxgWdR7Ms3wblVUvK23PY/VJi8gcS++aY8ts39dPACTP1bX+/vufjN2+DUhrdkuQVeB6/qa5n5v55buNtuv0sy9OjHHQLUs7jNM+bvly+elMt+CjO1whzLqVb4LTy7HdM+jao4W907IMnzda3t8190lxKcx+NE/J12qbrnvwSBPKnoGItKuAg8euDuB0PQwJMpgF7mMI3Klg4FytydSts4jo2iw0Wa2GRzXnJpkwu+N3KBYUFYq2UEqc+oGPhB9cBIMgniOY9h3jywoT3I9OLCYi14iBMsUbnxLz1aEIr8lH7NcRa/CiVYg0AAAAAoLQAsQYAAAAAEGMg1gAAAAAAYgzEGgAAAABAjIFYAwAAAACIMRBrAAAAAAAxBmINAAAAACDGQKwBAAAAAMQYiDUAAAAAgBgDsQYAAAAAEGMg1gAAAAAAYgzEGgAAAABAjIFYAwAAAACIMRBrAAAAAAAxBmINAAAAACDGQKwBAAAAAMQYiDUAAAAAgBgDsQYAAAAAEGMg1gAAAAAAYgzEGgAAAABAjIFYAwAAAACIMRBrAAAAAAAxBmINAAAAACDGQKwBAAAAAMQYiDUAAAAAgBgDsQYAAAAAEGMg1gAAAAAAYgzEGgAAAABAjIFYAwAAAACIMRBrAAAAAAAxBmINAAAAACDGQKwBAAAAAMQYiDUAAAAAgBgDsQYAAAAAEGMg1gAAAAAAYgzEGgAAAABAjIFYAwAAAACIMRBrAAAAAAAxpqBibdvBE2r5tv0gA+t2H1Y379z19F8Qbt65p5qMmQ8y0HLCIrXhwAlP/wVlwPz1nraBl5FLN3v6LihT1+1SzcYu8LQN3LSfvNTTd7nQLtGObBu4IX+cuWG3p++CgmtkdmzZf9zTd6WNgoi1ics2q8GzV6kLZ3cpdXMvyMBXN/ao2avXq6FzV3v6Mht+ULWzernjCHXu1lWQBV1nLdN9JvsxG6jej6p3VbtPX1Jnrt8BGVi6+6jus/KdRnn6MhO3Pr+n605av81zDoE/j9btlZdvP96gj+ccAn/GrNqRc1/zNfLc0RPqi/MXQAaunTythiT6i/pM9mVpoSBijTpUChKQGeq3oCtsL7Qdrg5dOu+ZtEFm3usx3tOfmXi7+3jPpA0yk8tFjerIcwYyM2DRGjV9fYmnP9MxfMkm3d/yvIH0nL52OyffprleChKQmWlLN3n6srRQELE2dflajxABmdlSsiXwNwdc0HIn6CR79PwVz2QNsuN3jft7+jMT8O3cCerbVP7k1Vue8wYyE7SvialLN3qECMiOGwEXNIqFgoi12avWeYQIyMyufVsh1iwSdJLde/K8Z6IG2fFs66Ge/swEfDt3gvo2VtVyJ2hfE7NWbPaIEJAdV27c9vRnaQBirYiAWLNL0EkWYi13INbsEtS3IdZyJ2hfExBruQOxFiIQa7kBsWaXoJMsxFruQKzZJahvQ6zlTtC+JiDWcgdiLUQg1nIDYs0uQSdZiLXcgVizS1DfhljLnaB9TUCs5Q7EWohArOUGxJpdgk6yEGu5A7Fml6C+DbGWO0H7moBYyx2ItRCBWMsNiDW7BJ1kIdZyB2LNLkF9G2Itd4L2NQGxljsQayECsZYbEGt2CTrJQqzlDsSaXYL6NsRa7gTtawJiLXcg1kIEYi03INbsEnSShVjLHYg1uwT1bYi13Ana1wTEWu5ArIUIxFpuQKzZJegkC7GWOxBrdgnq2xBruRO0rwmItdyBWAsRG2LtL771hPrBb19z4gTF//2RcurRZ9/zlM+Fz6/sctqmuMwPmziLNeoDCqcvX+3E/+2Rl5x4vmzev9/pa5kXFUEnWVtijfrAjC9cv9OTni/c12G2mY64irVvPVZefe93b+q46X8U/vzZjzzlc6FR10FO2995/HVPfhQE9W1bYk36tl88DGz6dtC+JmyIte/+qrwTp77YuHKDjv/7L15Sv3ymgqd8LpjzyEP//WB/UQKxFiK2xBrhFz+6f42nfC5QW9/79avqxoXtTvtRUgxi7V9/+oIT536XZXPhwJlTOgyrvWwIOsnaFGvVW/bV8b/6zpPq24+97qTLsvkSRZt+xFWsLd60xdefKdx84ICnfC6sLdmtwxc/bWTNv4P6dmkTazRmwm4zFUH7mrAh1kic1W/aXcepL1hMUfzQ9t2e8rlAbcm0qIFYCxEbYm3u3MnaUSjOkyzHKfz2r15SvQf2Uz9+8k1P3sZ183X87pUSHb5frb4O23Xt5toHpd28sMNVN0qKQaxR+Kf36zrxeWsTE0Kn/qr9wDGqTvu+rnJ/89BTasH6Ta6016u10GHjboM9+zD3Y4Ogk6xNsUb88Kn3ne0GnYbokLZfr9pKdR02zSnXYeAkJ4/CsXNXqu/++g3d/2aeH+nywiSuYo0w/dOMU0i+3W/8DPXwk++68nafOObx7a7DJujQz7e57ZcqNvbkRUFQ37Yp1lr3Gat9+0/v1Ve/eqGS9u05q7bqfNO3py3doP2X/JjrcpjOtymtXofBvnlRELSvCRtijaA+4NCMU/jtR19Ro0ZMUT9+4h1PHpe/ffqMDvsPGOvkyfaZsaOmefKjAGItRGyINYIcZNzEUer5d6qqX7/woXr1o5o6jfNMKO2bvyynuvftrbd/U+5DfRvVr5zZ/vGDyT+ll3lREHexNnDSLB3S9gsfNXDif/e9P7r6kNJOX7/kbP+qXEWnDVlOkio9CoJOsrbEWs+RM50+om2OD5u2xLUty8hQljE5dfWWTn/49+958qIg7mKNfPuP79RSj77waUbf/sYvX3ZtcxuynGTwlDkp88ImqG/bFGumT5rxtbsOufJ/+2p1p8xH9bt46ph1mb/7jz+obsOnQazdh/rg6deqq+feTF4bBwwYp0POM6G0bz7ykurafZiz/f3fJBc7mDYdBnj2QfyxfHWnTtRArIWITbFG+G1TSIIsXRl+Ju1/XvpIvVO5rnrosVd82//508lvHnL/YRNnsdasx1DdBz95+gO9zX3DcRJkT79b20mTZXj78ZcqqybdB6tvP/6aZx+D7otBCmVeFASdZG2JNYL7juK0SsZxzus4KLmqwOmdBidXmicuWKO36dko2u41epb6t0de9m2///i5asDE+Z68KIi7WJN+2mnIOCfeeeh43zJyu2mPIap8lWYe36a83mOmeupESVDftiXWmnYf4fQDbZvxio176Dj7tinWCPZt3ibf5roM+TNR7uMmOm/UzOWeYwiboH1N2BRrBMX/4/6cwNsU9u03xpUm69w6lVxZa9dpoGrbcaBv+8OHPZiLZH4UQKyFiC2x9vifP9AOwtsUf/qNSjq+cMFU9fff+4OTbpYxt+9dLdErbG98WtvTPvFJrcbq+78t70mPgjiLNYL6bf2ePU7892985uTRCsS2w8lvxpw2YcFS1/apa5f0w9w/fPJdT9vcJiPzoiDoJFsosbZs8x4nTjz1Zm31cYOunudyzDjxauUW6q+/+6RqN2BCyvZlnaiIs1j75Z8/cfmc9L+HfvOGJ136Kfn2v/zwWd/bnFOXrNS37X7zalVPXlQE9W1bYo0w/U76IPs2pbFYGzd3lcdP2bfXlRz2tE9gZS0J9y/Ft63drOO0Ckbb82YuVt9LCDguZ9bZu2Wnsz1+7Az1tYefVT/5/Tue9mdNna/+ITH316jfyZMXFRBrIWJLrJU24i7WShtBJ1mbYq20EWexVhoJ6ts2xVppI2hfE7bEWmkEYi1EINZyA2LNLkEnWYi13IFYs0tQ34ZYy52gfU1ArOUOxFqIhC3WKnzWUC/N/sN//lFVqtvUk19aKIRY42VyRubnCrX1Vo1WnnQ/wtxvEIJOsmGJNe7rHzzxricvW6g+3eqR6XEl7mKNfJX9cInxOo+wCLu9TAT1bRtijf3+X370nP7FsszPBNWVaXEgaF8TUYu1D6smf3X/9xluUT75chVdTqbHGYi1EIlKrFGcB7wsk4oRo5O/bJHpTND2oqRQYk2mhQG1m0qs/bZ8Vc9D2IUg6CQbplijsEL9zup7v3vbk58vcbyoFYtY++ajr0QyJqJoMx1BfduWWPOLZ0vQOkHL50rQviZsiTWK8zVOliEg1uJDqRJrzL6S5eq7jyV/Pj9g6EAd3rq4w/l156BhyTeGU1qV+s10fPykUbotio8ZP0KVe6+aOrwv+eCqzO/cs6eu919PvaXb//pPn1df++GfnPx/+v7TqknbDjoujzUfCiXWJPQi1tZ9R+o4l6Ffs3HcrMe/cqM0vtCRGKOQLoD/81p1/d6pik2SP72ncvTOqq//rJzzq0/Z5t//59OetJ6jkr925LSabXrr9rsMHe/5TNkSdJINW6x9WC8p1l6rkhQKb9do5+TRw9UUp1+8cZ2eo2aqh37zprPNK2v/+T/vqO4jpus0+iUchxv2HHHet/bE68mf7nPdv/z279XHDbu50gj6td7ijSXq+KUbejvVu6yCUixijeA0eoCdtr/3u7ecdC7TbcREZ5t+WEDhI89/4qQ9XyH57sb36rR10uQ+oySobxdKrHF/0jvXXq7YXMf5V57kh7/8c0Udf+7D5DXArMNxHgcUr99xiHrrs7aecSCPJUyC9jVhS6zt2bRDh+07DVLvVmyq4z16Jn+RS+VMsUbhy+/V0+Enn7XWaVVqt1P9+id/MUo/MvjGz1/U8YED3a8AoTZpvNBrQuSxhA3EWohEJdaGjUq+PoKhCw7l/81DT6qf/uEt/TdTnEb5lCZX1rhug5btXNtmPsepLXN/Mt+Mh0GhxBqJJoa2zTwO/cQavTBUpm3Yu9eJ0wWwRuterj6kPLmyZtbvPnKSE1+0MfnrJbnvv33oDzr+5mctnTZyIegkG6ZYY+Q2p5FY45eBchn6xW2/cXOdbfMiRbeW6N1pvO23L3N/Zj6H9H43Tv/5s8lfSDKdh0xx8nKhmMTaofNndJrsuzW7ki/Rrt2+r1OPtims1a6Pjpf7JPkvBSZmOVsE9W1bYs2E0yYtXOvKl2UnLVznpPmVo3Fw6NwV9ZtXqnn2J48hCoL2NWFLrDGUZm4Tb37c2CPWMtVp2bavDv/1J3929iXLyGMJG4i1EIlKrFGc/5GAoTQK6YW4b1eu60kbOcb/NqhZzsyX8a9u7FGLFydXLfzyZbv5UCixJrePXTrnyqOQ3o0m06SIonDotLlOnC+A9KJRs9zvyldLKdYq1O/gxPefOanD6ctWucqZ9WRaEIJOsmGKNbkt00is8d9MMUfOJz8z1zGfWdt17Kwrz2z75JWbnv3JOIUvftLUSX+lUgv19Z+96KqXD8Uk1tinKCz3cUNXOUpjv+dtCumLC8VpxZfTZD2ZFiVBfduWWPNL27j3qBM3/ZH/2q5Fr9Gu+vyiYk7jcUAr8rJtub8oCNrXhC2xRnEK/zbxxY/71ywnxZpsx8wz84/sTF7/UtWLEoi1EIlKrNFKF/1bAacPHj5Y/+ig/5CBnjT+myiCbmNSfYrTC3D/6ju/Vx9Ub+Dk019T8bvUuBzRb/AA9S8PP6OO7Ev+ebmZT21yubDwE2s/qDlLc/jcdU8/6/w8L2j0eWQavQ/qn37wJ1caTZBnb15xylMoxRpBtzf5fWt0ATxz47L6h+8/rY5fPu8q94/ff8bVFqd/ULe9euT5j51typNijfzrnx/+k3rqrZquYwyKnGSbTdiu+/rRhvM8/UxEJdaImYnJm/qc/nqHtqVYe/b9BvpiRH/Vw23wRepb//2arsuijN8Ez3XpnVRf+9HzzjupzDwzTv9H+v0n3kn42hW9PWjSgpTvaQuKn1hj375++64nT+fn6dtBMH9gYPp5uwGjtWigv5yibdPveZtCFmtcn271061QWc4W0rd/VHu27uuFO057+pn7Wp6zsPHze0pjsUaMmZN8J922QyedNHqp84pt+1z1H/1zJfXjP3zoGgf0YmiaV35b/jO9LcdBVMi+3nb0ku7rioPWe/qZsSnWCI6vXLRKr4o9/1YtvW2KtXvnzuu/nvrBb9906j36pwqKXoZLZXRf7jukfleukr4lau6P2qSX7srjiAKItRAJW6zFCXJYmRYW6cQa8eM6sz19bfOCVtqQkyyLNeb8NfekEJZYK4ukE2vE2FVHvPnw7ZyRvs1ijfHra3nOQHbIvmaxxviJtqjFWmkGYi1EINZyg8WaOdD9uPX5PaevcUHLHeq7x5ss8PSvhPsaYi13SKxtOHjB07cScx6Bb+cO9Z3sW8nC7Q9W2SDWcof6rsn4bZ7+NflhLfcXbYi13IFYC5HSLNaiJNPKGmEKNZ2PC1rOyG/EcmVtY0JcmPkQa7mTaWWt0dit3nz4ds5I38bKWnTIvpYra0+0WOTpb4i13IFYC5FiFGvdBw/ypC1aNsuTZnLn8i5PWj6kE2vztp3y9LPOxwUtZ+Qka4o12c9EMYi1rQdPeNLS8ULF+jnVC0o6sXbwzDVPns6Hb+eM9G0Wa11n7fb0M/e1PGdhwT5mk/fqtXHivH8OpyxJ/vo0LGRfs1jzE2lMsYm1lyo39KQVCoi1EAlDrO3bvVKHmzYt0iENtI8atlIrV89zytRu20l9fqVEVWrS1lPfD2rDDFetSbb1cpWGjljjvP17Vmmx1rJHL3Xx1BadduviTleZHduXubbPn9zs2WcQ/MRaJnBByx05yWYiV7HWYfB4Ha7eud+VTn5Tcvys6jsh+S61Ixeu6rB2x746/KhxB09bZt3D56+ojXuP6Fd2jJu/wkmnsGrrHon8q852/4mzdbhsy24dDp+xyFWew1Gzl7i2B06eq1Zs26uPk9NW7djnOZ5M+Im1TMC3cyeob0ch1vrd92v2G+KlxFxL4aKNO3T42mfNdPhOnVausuUqJcNPmnZWxy5d1/FdR8+oHUdOqUbds/vnjnKVGrja5DBqsZYN6cTaB3Vb64f9t2/YorfrtumhQzp+M/ywXvJdaD0GjtLh1GnznDa4zM2Tpz3tM1z/0pFj6tapM+ru2XPq0M49Tv07p8+q16o38d23X0j1KVyxdLXq2HuYTl+9fK3+LJWbdNTbo8dP1yGdGwpLNm93juf9uq10mEkYQqyFSBhijSERxZBYM/PIMWT5dHQdlPzVaNeBD349yu2wWPu0cRsnXa6sDRg1XF06vSXhVC30Nos1Ljd2yjhX+aBArNkl6CSbq1gjyldvqgZPmedKGzBpjg7NixnRftA4B9kOI+ukSvfb3n/6opMuQ4YvdAyJNgo/aNBOVWnZ3ZWXDRBrdgnq21GINYZ8a23JQTVi1mKXgPPz8VT+2GXEZC3WZNt+fNK0k6rVvo96o2Zz37biLtboeOV2t/4jNbTNgofLyfIXDx/TYee+w9W14yc97fvtp3mX/k58z5YdTt7C+ctcZbv0G+G0TWHD9r1d+bwt9yGPkbaXL1nlSuPPyJ8zFRBrIRKmWFuxaq4OaaWNxNrqtfOdPFpZu3u1RFVulnzBbSq+uLZbh+QgZrh2XbKtdCtrZjvVWnRwlYFYK26CTrK5ijW56sXQ9p4T55yVNaZ2h746nLFig6cts65MM9OrtempV+pkOd5OFY6Zu8y3fRJrCzckV0NkXjZELdbaDx6tSk4c86TbhvpGpgXBr34unyuob0ch1swvI7Rie+TCNcd35q3dpkN+kTMj/bFi8y763zQonq1Yk/4pt+Mu1t6v00qvRu3cuE1v12zZTYcXDh3VYSqxNn3GfKeN9avW67DvkHGe9p393F/JerCydl4d2bXX1aYUazLMRqyReOR8M51CEoacRiuKFG5dl7pvCIi1EAlTrJnIlbXSRlhi7ZVqjV3bNDAWbdqsb0HwNrFixw69TbcguGyj7gPUu/Va6/i4BYvVK1UbO290T8fp65f0N9kZK1er3SePqffrt1F1Oyff9E77+qRpR7Xn5HG9vaZkl2ufdBwvV23kaVNCxz9u/mId33xgvxozb6EaPnOes49BU2clLmxHExN8JyeNoHjfCdPUa581dbUXdJLNVawVglNXb6sDZy6pxj2S720rNGGItUmLl6nmfYY62y9XeeAzUqy9XqOZatlvmDp2+byTRmPAbM+E/Nds79VqTdSJKxd0/OTVi3oc0DsDeWwQtL/Xarh9iv2NeKNmMyc+f/0GV56k26iJqkKjdk6ZWavXqPcbtHH2M3XZSsef6VjLJ3yZfJrryjEf1LejEGtlhaB9TaQTayA9EGshEpVYK+2EIdY27d+nQ570tx85pMMdRw+70lmo8Xa6C0mbASM8aSSMzO22A0e6tgdMnqEvoBSX+1i6datrmy5EFNIFiutzGpPq+N6rn7x40r8umMe09/QJp42h0+c46at37XLiQSfZYhJrcSMMscZ0GjbW8Qd6tolCU6x1GeH9v9gRs5KinpH+ZPov59Vs39O3DockwGRb8rjkfmQ5CaXPXbve2e4/abrzucw6JNB4fNEXIdlOUN+GWMudoH1NQKzlDsRaiECs5UYYYo1WnOTEToQt1iTtBo1y4rItuQ8p1vhYpEDza8OP2WvW6tAl1k4dh1iLEYUUa7T6lc5/CD//zSzWNrq2/coEherR6rSZJsUar0ofv/Jg1fDMjStq6ZbkuCKC+jbEWu4E7WsCYi13INZCJGqxRpMWhVNmTdKh32s3ciXMtoIShlijv7qRt0SIhRs3ObdBiSotuzoi6e06D/4QvV6Xfs5qFd1ypNuT2dwGPXntor4o0urYqWuX9G2jdXt26zx5ASPBZO4zG7FG0PGPX7jEN51CEmu7jh9VnzZ7sNLwZq3mOuwzfqq+dWTWCzrJRinW/J7HqdOxnyetWAlDrNG5b9Z7iLNNty3J3ykub4PSuW7df7iOj5w939WOH+S/5q14GkOmGCKkH+vboMKnTJFGt1LHzl/k2ZcfXUdOUB82fHAblMYr+S7d8uTPRV86OL989SZaoFG8etsertuzRFDftiXWNu5L/rXU8JmLnB+tMPTjFVmeob6k59vo9r5Zlp59+7hJJx3nMcS/JLVF0L4mbIg18hWZFiW29gexFiJRirUZ86Z40kyBRQ/7d+rfX02aOdFJY3FHIf0YgX48wHkXTm5W79Rurqq3TP54gH4NumDxDHXq6AbVoV8/p27b3n00NVt39Ow/LMIQa2UNvhVEyFuzmQg6yYYp1nqOnpYQE6OcbbrQVGrRNSFGhieEdDedVqNdb9Wiz4jExaijs815qXixcgNVr3N/HX+vfltVp1M/dfrabdcv78inSWTwg9sEPd9Gzxxy+0OnL0gc32hdVu4jF8IQa7liCqgwyeXBf1sE9W0bYm30nOSPV5ggYk36oVn2zVotdEhjiEQdxY9dvJ74QthKvVW7paetsAna10TUYo1emcHiiX9dyQ//0zb/mjObX18OHDFRdewzTJVPfIGhbWqXfgRBcfqxA8UHj5yk04+W7PPUDxuItRCJUqx1u//6DRNTrB0/tE69UaOJs81ii+NMqjT5q1CG9yvTwwRizS5BJ9kwxRq9I43Cht0G6ZAuNG0GjNFxDvkVGbxNvkcrEmY75kWM351m5hEfNmzvSq+ZmLQ5T7Zj7ku2nw+FFGtlkaC+bUOstR041rWdSazJ13oQDboO9JTlLyf0Dja94ng/nXx38aadnjbCJmhfE1GLNYI+P4VSrBG7Nj14v1md1t196zH8+o95c5eoFl0HOHPHkkUrnF+m+tWLCoi1EIlSrBEsmKbNmaxDU6xxminYXqrcQIcNOnbV4fKVc5y8Wq07qWvnt6tLZ7bqbV45o9eCUMivBUkl4sIkCrGW6daiLeK4ChF0kg1TrPFFxXzhpxRIZkgrBRSfu3arpy2TbYdOOnF6mS2F8iJI7S3auNMlxFr0HaEFJKfxraSyJtZy8dNUY4x+DUo/Qpi8ZLk6cvGsJz8V/BwerRLJvGwJ6ts2xBqxaX/yNii9yiOTWDNpPzgp3CYuWu0qO3/dNv3iXIrzbVDy2blrkuOkRrtenrbCJmhfEzbFGock1uiVIC27DXTKLFu80lNPUr7agxfj0us9eg8e6+RBrIVHqRRrpRWItfygyUKmpSPoJBumWCsWINYyk2mMBfHLIdNme9JyIahv2xJrpZGgfU3YEGulFYi1EIFYy418xFqNdj2cidr8IQFfSBZsSP5yjb+1Hzx3Wod8IeE6/Es6+hEAPw82eOos/QC2eTGQFzV6VopCfgCc3oBvtk/l5UVLbn/QsK0OzVcR0EPUWw4e8NThB8trdejlyaNfC5pp5n74VSZE0Em2LIq1sMhHrNH5Y/+Tr2chP6CH8/kc0ytjpD90S+RT2HvcFCdPlmH4xy5rd5fokH4wU7N90sfkWOK6PcdM0qH8xXWmfRD8IwGCfiQgn7vk97jJ8Spp1GOgazuob0Os5U7QviYg1nIHYi1EINZyIx+xRrxYOSm4zJd78gVGvqqD4W0WSiTQ6FdwdNtm6+GDrrIs9PxgscYvLc1FrNXp1EeHfCxmuRrtkq9RkHVqd+ztaS+dWCP4V4JBJ1mItdzJR6wx5H/y9Szsd3yOB/qINb9znwr+EkLjZeKipTpOvySmMNVYCirWTE5fv+zalmJN/rI7XVvmu+SC+jbEWu4E7WsCYi13INZCJEqxJv8CiuG/fsqWdP+GQBOiTLNBPmKtQqP2zkROt1JaDxihLyryAkMrBfQtnF+dwXVMscbp/SclL3z0mo82A0fqNuUFgmnYrb9q0nOQU5/ezUZp6/fu0dt0Edx3+oR6u3ZLZxWQXktQrU139Vnb5HYqsUb75uNcsX27XoHgt7s3TnwWfg8cPePTYUhy/x81bq9XC2nlxbzA0cWat4NOsoUQa+me4yHos8i0OJKPWKPPyP5HYoZeaUGvhnHyEul8Tj9q0sFZZTp66Zwux4KO/Cyd2CFMsUZCin412+O+GJNjqcvwcXrftLLHx1KpRWf92g2zzUz7pHwaK/0mTvOINc7n8Xr4whlVv2s/Z4xQPQo/bdbJ+YJEBPXtsMQaHWurfqMcv5TPpaUjF1/Opk42ZfIhaF8TcRNr/LdSxQDEWoiELdZosHHcT6zR6zdMsXb2+Can3pLls3X8i+vJ/wdlSKzVa99F3bmyS2Puh0MWdLz9Qb3kH7ifPLLe1VZY5CPWCs305av0hVHeHo0zQSfZQoo1vuC89lkzHdL/ftL/ilJ63/Ez1e5EfOy85TqPfmHK76OiY6ZXd/AvSwv191P5iDUTPzEDvAT17TDEmvy1J0FijXyV4h0Gj9ch+7IZbj6QXHmnbfqxC71TzXzPIP2QQNYxQ/pxwZpdB/Q4oO1D566ofacuuMoQtTv21eHJK7fU8q17nDL5ELSviXzEGr1Cg34o8GG9Nk7a2pXrdLh6+Rod7tm608l7PfGFw6z/Vs3mOjy176B+JQf9SCDVf4C+VLmha9uP/dtLdDh56hwdHtixW4f05YHCio076HDtinWqRuKLP8V3bkr+72kuQKyFSNhirUmXHgkh0FDHTbFGDkT0GDIopVijkG6fbN682NUmCTGuz+U+rN/SVc/cD72bjcvSu9jM/LAoZrFWjASdZAsp1pZt2a1D8r9hMxY6+aYPE2Y6hbTaaObRBPpps/wvzEEJS6yB7Ajq29GKteQfuLMPytD8w3cOpT837TnUlSbr0LvWKM6/GmVmrtzklBkxc7HTRqehE7RYM8vmStC+JvIRa/wqDfocHJpxsyy/D80sR5RsfvDqjnRi7cTeA77tmitxr1Rp5Mp7pWpy+8Se/a50gh7R+aRhO3X37DlPXrZArIVI2GKNWbVmnvPajYkzJjjp9FqN3btWONurE+UoJAfjtNGTx7raYrFmpvE2h7wv3g56qzUoEGt2CTrJFlKs8YWFfNH8twPaptu9Zp3Ji9eopVtKdLz7qKmeNgsBxJpdgvp2GGKNOH75wYuWCRJr7J/82g3yWTN8vUZz1zatesl2M9Whl0zTvuW72ejVOFyGVtFoxY3zilWsDR01WYf0uXoNGqPjl44c02H15p1dZS8cPqpXz8w0U3hdOXo8rVjj9s06ku4DRrm2ewxMbvN+j5Ts9dRJ114mINZCJCqxZpt715K3Tqu1SP67QdRArNkl6CRbCLFWWoBYs0tQ3w5LrJVFgvY1kY9YC5O+Q8Z50kyuHjuhb7nK1bNCArEWIqVFrNkGYs0uQSdZiLXcgVizS1DfhljLnaB9TcRFrBUjEGshArGWGxBrdgk6yUKs5Q7Eml2C+jbEWu4E7WsCYi13INZCBGItNyDW7BJ0koVYyx2INbsE9W2ItdwJ2tcExFruQKyFyIyVEGu5sH3PFog1iwSdZA+cvuiZqEF2/KH5IE9/ZgK+nTtBfZvK0yte5HkDmQna18SMZZs8IgRkx9Vbdzz9WRooiFgjwSGFCMjMqPmr1YzV2z39mQ5c0HInl0kWF7TcyKWv4du5E7S/qXyPOWs85w1kJmhfE3SNlCIEZObuufOeviwtFEysrdqSfNcZyJ6gq2rEgm37cVHLga6zlqn1+497+jMTuF0UHHoVQy4XtIr9pqjfN02+oR9kTy59ffPOPfh2DjxWv4+qP3Kupz8zQXM9/cpSihGQnlyukcVCQcQasWRLUnyA7JF9mC3T1pfoiRZkT/VB0z39mA1Xbt5RD1fztgdS81j93p5+zJYes1Z52gPpodv1sh+zRbYF0tNv3lpPH2bLiPlrPdcAkJohc1bpLxWyH0sLBRNrAAAAAAAgMxBrBs3GLlAVek30pINooG+eMg1Ew89r9VCzN+3xpIPw2XbkNHzbIuhre+AaWTgg1gyqDJimXmgzzJMOogGTrD2or4cv2eRJB+GzePsB+LZF0Nf2wDWycECsGcAR7YJJ1h4Qa/aAWLML+toeuEYWDog1AziiXTDJ2gNizR4Qa3ZBX9sD18jCAbFmAEe0CyZZe0Cs2QNizS7oa3vgGlk4INYM4Ih2wSRrD4g1e0Cs2QV9bQ9cIwsHxJoBHNEumGTtAbFmD4g1u6Cv7YFrZOGAWDOAI9oFk6w9INbsAbFmF/S1PXCNLBwQawZwRLtgkrUHxJo9INbsgr62B66RhQNizQCOaBdMsvaAWLMHxJpd0Nf2wDWycECsGcAR7YJJ1h4Qa/aAWLML+toeuEYWDog1AziiXTDJ2gNizR4Qa3ZBX9sD18jCAbFmAEe0CyZZe0Cs2QNizS7oa3vgGlk4INYM4Ih2wSRrD4g1e0Cs2QV9bQ9cIwsHxJoBHNEumGTtAbFmD4g1u6Cv7YFrZOGAWDOAI9oFk6w9INbsAbFmF/S1PXCNLBwQawZwRLtgkrUHxJo9INbsgr62B66RhQNizQCOaBdMsvaAWLMHxJpd0Nf2wDWycECsGcAR7YJJ1h4Qa/aAWLML+toeuEYWDog1AziiXTDJ2gNizR4Qa3ZBX9sD18jCAbFmAEe0CyZZe0Cs2QNizS7oa3vgGlk4INYM4Ih2wSRrD4g1e0Cs2QV9bQ9cIwsHxJoBHNEumGTtAbFmD4g1u6Cv7YFrZOGAWDOAI9oFk6w9INbsAbFmF/S1PXCNLBwQawZwRLtgkrUHxJo9INbsgr62B66RhQNizQCOaBdMsvaAWLMHxJpd0Nf2wDWycECsGcAR7YJJ1h4Qa/aAWLML+toeuEYWDoi1BDM37NYDXiLLgXCQ/Yy+jhbZ10fPX/GUAeEg+/qPzQd5yoBw+GG1Lp7+lmVAOPhdI/vOXespB6IDYu0+0hEvXLvlKQPC4ee1erj6+o3OYzxlQHhI35b5IDzQ13ZBf9sDfV1YINbuI785yHwQLuhre5h9jVW1aLl88w582yLoa3uYfY1VNftArBlg0Nuj49Rluq+X7jzkyQPhA9+2B/f19dt3PXkgXPaePK/7utqg6Z48ED6YRwoHxJrBsMUbVdOxCzzpIBow6O3xTIvBau+p8550ED6XbtyGb1sEfW0PXCMLB8QaAAAAAECMgVgDAAAAAIgxsRJrk5ZtVoNnryrTbD900tMvUXDywlXPvssaw+auUTfv3PP0TRSMmL/Ws/+yxuEzFz39EgUlR8949l3WWL3LzrOgV27e8ey7LCL7JSpwjbR3jYwbsRFroxeuV3fvfaHKulE/LNi429M/YXLuyg3t9DCl+0H2T9igr5PGk63snzCh9kmEl3VbvHlP5H1NwLeTRv1w6/Nov/jRPnCNtHONjCOxEWsY9A8s6kkWff3Azl2+5umfMNlz7Cz62zD4tj2Luq9nrdmhvvjyS7nbMmlTV2xRYxdv8PRRWNy8cxe+bVjUvh1HINZiaFE7IvrabbTSKPsoLKivN+49KndZZg2+bc9mrN7u6Z8wQV8/sK+++ipS316+bb8atWCd3G2ZtSj7Oq5ArMXQonZE9LXbzly+7umjsKC+3rL/mNxlmTX4tj2bvXaHp3/CBH3ttih9e+nWfXrlDpa0KPs6rkCsxdCidkT0tdsg1uwZfNueQazZtSh9G2LNbVH2dVyBWIuhRe2I6Gu3QazZM/i2PYNYs2tR+jbEmtui7Ou4ArEWQ4vaEdHXboNYs2fwbXsGsWbXovRtiDW3RdnXcQViLYYWtSOir90GsWbP4Nv2DGLNrkXp2xBrbouyr+MKxFoMLWpHRF+7DWLNnsG37RnEml2L0rch1twWZV/HlTIt1t6u1kr9xbeecLbb9R6lRk2e76RRePTEGSfflkXtiIXoazLqz7MXLjnbV6/f0OGytVtd58G2lUaxRv0pfXve0gc//S9Uf5dG3+Z5hH370pVrrnzKq9K4myvNhpVWsSbnETO9UH5NFqVvF0qsyT6leYTTC2lR9nVcKdNijRxu8cpNOn7k+GmN6ZwU/vrFymYVKxa1Ixairz+q08HpV+7rM+cu6m2ItfDNz7dlfiGsNPq2OWfIvpYXO5tWmsUa2fmLV5y+prTDx04VrK/JovTtQoo1v3mE/bpQ/R1lX8cViLVVm524dEAKIdbCsQq127v6lXjy9Rp6G2ItfPPzbTNPrv7YstLo23LOMPv6+KmzenvQmJlOmi0r7WLNnFO+9avyrrxCWJS+XVCxlmIe4bRCWJR9HVfKtFgjYwf0m3BLqyMWqq+/8cjLrr4lsebX/7atNIq1LTv3efp2xKR5Be/r0urbsq9l2u799v/ForSKNTmPmCa3bVqUvl0oseY3j/QcMill/9uyKPs6rpR5sRZHi9oR0dduK41iLa4G37ZnpVWsxdWi9O1CibW4WpR9HVcg1mJoUTsi+tptEGv2DL5tzyDW7FqUvg2x5rYo+zquQKzF0KJ2RPS12yDW7Bl8255BrNm1KH0bYs1tUfZ1XIFYi6FF7YiF6OvuwyfIpNgYxJo9K42+HVeDWLNrUfo2xJrbouzruAKxFkOL2hGD9vULFeurToPGqEZdBqgB46arzoPH6nQKX6zUwClD+Rxv1WeYU5+MxRrlNe0+SNVp31tvj56xQHVMtL3nYPIBbMp/sXJDHZfvUmqSqEftrtq0XW+36DVEfdCgra5DVi5xLHU79FHzV643q2U0iDV7FjffLs0GsWbXovRtiDW3RdnXcQViLYYWtSPm09ebd+3V4adNOupwS8k+Hb5Xr7VThsWTaSzWvvrqK9Vj+ESnDAsy2u45cpJT3swzbeik2U5dFnVyf3I7k0Gs2bM4+3ZpM4g1uxalb0OsuS3Kvo4rEGsxtKgdMWhff373rhNnAcXCqtP9VTa2/mOnOfEr15L/UEDGYu3Nms11KAUVbS9as0l9+eWXTtq9L74wSjyokyrM1SDW7FncfLs0G8SaXYvStyHW3BZlX8eVohFr+V6QwzBbxxC1I2bq62KzfM8LxJo9Kw2+XejnLz9q1F4m+VoxiLV8x24qGztzoUzyTQvTovTtXMUaP5pSCEt1bnfsPSiTsvZptij7Oq4UnVjjZ6RertJIh/NWJP/v0FxluXHrtn5+iWzv4eSFcuXGbTrMxsxbc2S9R012bacyudLTsvdQ13a2FrUjZurrQlqVFl1Vk24DZbKvLVm7WVVs2kkmBzZbYk36B/soba/duksdPHbCWVmkVcZmPQbr+J3PP9ehNG6nw8DR6vylyzpO9W7duaMqNGxnFk1r3M5btVro29Tclum3w6bMURcuX/F8BgrvfH5XTZq3VF27cVOnkZjhz7Fh++5kA/etUL7dc8REHVLfkPG8QPNIjTY91PWbt9St28k8Nv6MG3ckPwNvs1h7v14bHU5dsFyHpnEfyPmqVtueThnaL5l5u5/2sf/IcR0/efa8k0ZW835dvrBx+u4DR3QorZBijfyIrOvQ8TqUfkPPmtKKveljptVu30uHMr9ex76udNkHp85dUO0HjHIJs1lLVut0Lrtp5x4dvlGjmQ7fq5t8hKNay+T/t/K4rNy8i/Ztssb356QDR0/o0M+i9O1MYs3sJ/p8R0+dUdsTosh8jpjspfuPjpDxOeI8mmfkWGbjMtv3HFAXLl3RcXpm2MyT10kOyb/b9R+lx1elZp21WGMf53lK+jTNh+ksyr6OK0Un1k4nBp25zSYdxAy/SEyaQZS7FGtsclua3LdMz9aidsRMfV3WrFBizQylj5DoYvugfht19+49zzdSqtN3zFRne+Wm7U49WTadmcdBIoPFSC/jGUIuM2r6fB3SFyK2Ss07O/WOnz7nWnl6pWpj1+3sQvo2iV/+HHy8hOx7Nplu1iWbuST1vrgMi4aR0+aZ2apN3+Hq5JmkGJNijcSDKQp4v1zOnMsozqJPWiHFWvOeQ5z+LTlw2OkH+ix7Dz34NwfaJp9N1df1O/VzbUsf5XZp22zXFGtcd9CE5F9+yTbYTGFjfrnvNzY5xsiXF65OLZii9O1sxdqlq9dcvs2ficQxp63evEMtWOX+EVbXoePUzcSYlmOZjX7cxUY/8qJHXO7eu6e35blbsCp5nKbfmmVobiIfpzmEn3lmnzaPM51F2ddxpejEGn3r6TJknLOiJvP9QvrGxM7wTp1WyQppLJ1YMy9g0vqPm6ba9hvhW880+mVlOovaETP1db4mP2/cLQ5ijYy+9fJKoSnWKJ+EBgswiu8+eMRV/7XqTV31chFr9E2cVot4RZjCBp376zitgtA+KjR8IBTM80zx1n2G67icaM1yhfLtz1p31/OG2Wf0a2YKz5y/qF6v0czpQ0p7uWojjx/L8yXjpkkxQWaWpRU3FnBSrNHFkFYteBWE65nzEs1DFNJ8Y/64x7RCijWyBp37qaotu+q4KdY4pC8hsv9o5XHR6o16JYz6wRQJZLSqQ+3y6pcp1sherdZYrxCb/U5f1im9+7AHfkm+ys/PsslVKAp59fSNRFna74ipc53y0qL07WzFGsdpjhieOFb+TIMnzlLt+o/UPn464e+0ovXaZw/8ncbG2YsP/IvHMhutmvF4mbZwhY6z/8pzSH3dqOsAl99evHxVX3vrdOij5yY6t3QdHD5lji7DPk3HWT0xVqmv01mUfR1XikaslSWL2hGj7msaeA279NcXPDL61SYJZn7lBk0kn9z/Nanfqzt4gqQJmCeIKM2WWMvG5I8qit3o2zrfciQrdt+WVqVFF5kUGyu0WCtrFqVvZxJrZc2i7Ou4ArEWQ4vaEaPuaxZXvJpJz+vQ8xGcTr8klQKMtuWtEzJalg9yCzsXi5NYK+1W7L5dTAaxZtei9G2INbdF2ddxBWIthha1I0bd11Ks0YPR9HAppR88dlKn8fMjbJRHD2T3HT3FSePnRqSwC9sg1uxZsft2MRnEml2L0rch1twWZV/HFYi1GFrUjoi+dhvEmj2Db9sziDW7FqVvQ6y5Lcq+jisQazG0qB0Rfe22i9duevooLIbOXa3W7z4sd1lmDb5tz6au3OrpnzBBXz+wL7/6KlLfXrnjgBoxb63cbZm1KPs6rkCsxdCidkT09QP7/O49T/+EyZqSQ+hvw+Db9izqvh61wP2L/LJsy7ftU0Mi7O/zV27Atw2L2rfjCMRazGzzvqNq/JKNnv4Jk33Hz6kxi4L92XlpNRuDHr6dtMnLt0Te39T+sq375K7LnF28mry4y/4Jk5t37sG37xv1w+Ubtz19FCbo66TZuEbGkdiINYKcsawzfN4aT79EwYzV2z37LoscOn3B0zdRIPdbFpm0bLOnX6KAVnzkvssisl+iYOPeo579lkVufh7tCj0j91sWsXWNjBuxEmsAAAAAAMANxBoAAAAAQIyBWAMAAAAAiDEQawAAAAAAMQZiDQAAAAAgxkCsAQAAAADEGIg1AAAAAIAYA7EGAAAAABBjINYAAAAAAGIMxBoAAAAAQIyBWAMAAAAAiDEQawAAAAAAMQZiDQAAAAAgxkCsAQAAAADEGIg1AAAAAIAYA7EGAAAAABBjINYAAAAAAGIMxBoAAAAAQIyJhVg7euq8+otvPQEAAAAAEAv+z8/KefRKoSi4WHv8xcqeDgIAAAAAiANStxSCgos12SkAAAAAAHGhXIVGHu1iG4g1AAAAAIA0SO1im6ISa9Keer2Gp0yxwCbTo8LmvgAAAIDShNQutik6sfY/r1Zz+N8/es5TpliIu1g7cvx04DoAAABAaURqF9sUnVjzSzPTzW1pf/PQU0768VPnRK5/G8zUucudtKvXb3jKy7pkQ8fPcaXvP3xCh7Va9nbKpNqfWe/E6QfH+sizH3v2Q1avTT/fY5i+YJXrGL/+0xd0fMW6bXr70LFTZnGdxkLNTAMAAADKKlK72KboxJoUEU+/VUvHG7Trrx59/lMdb997lBo9dYGOt+o+3FVXxokmnQY52yMnz9fxf/2vF3z3L+t3HTjeiX/55ZdO/Gs/fM6Jc50Ll666tsnu3fvCVU5CRsck92uya+9hJ12uiFVu2NWp+88P/4mb0GkPP/GOjn/38dc97ct2AAAAgLKK1C62KTqxJtM43TS/NDbOO3PuoqeNkn2HXeUkZJNmLdXh//uTPzsiicubcd7+oFY7Jy7bYpP7keVkHVmfTZaR7cg8XumTRnkQawAAAEASqV1sUyrE2mPlKjlCg1bYKG38jMV6e8b924DE3KXrnHZIjJht0EoaG61AyX0QB448EDfcDhkJN9rOtLJmtsXGK3OVGnbx7I/L+a2skW3YttuTLkUWt2vW4/iPnnxPx2l1ksufOnNBh9t3H3C1AwAAAJRVpHaxTdGJNdNGTJrnyUtXnozTpVhL1YbJNx55WecPGDU9ZXnTWGRxul85GZeQ7T14zCnj98za8rVbdSjbJpPPrMn9yefTOP1bvyrv2gYAAADKKlK72KaoxFqUPPtuXS1M/vq7T3ryCgnEEgAAAFBYpHaxDcTafeK6ihTHYwIAAADKElK72AZiDQAAAAAgDVK72AZiDQAAAAAgBddu3vFoF9sUXKwRsmMAAAAAAArNa5WaezRLIYiFWCOmzFvp6SQAAAAAgEIgdUohiY1YAwAAAAAAXiDWAAAAAABiDMQaAAAAAECMgVgDAAAAAIgxEGsAAAAAADEGYg0AAAAAIMZArAEAAAAAxBiINQAAAACAGAOxBgAAAAAQYyDWAAAAAABiDMQaAAAAAECMgVgDAAAAAIgxEGsAAAAAADGmKMTa8Hlr1ODZq4BF5DnIhZuf3/O0C6Jl5Y4DnvOQC7JdEC0j56/1nINcuIUxZ52bd+55zkMuyHZBtAybu8ZzDuJM7MXa5OVb1L0vvlQwu0bOLM9FUKiNM9fvAIss3X5Anbp41XMugjBn3U7pDrCI7fO7SZElz0UQzly6hjFXAPI9bwS1AbNrXyR0xcRlmzznIq7EXqzBiQtjQ+bkNwGdunhNrd1zzDOxgejJ9+KBMVcYC+O8Ld1+0OMPIFrW7zuuTl7I7wsSxlxhLN8xZxOINZivzVi1zXMugrD72Bl14OwVz8QGoiffCQhjrjAWxnnbdfy8xx9AtBw6f1XtOnLacz6CMHXlVukOMAuW75izCcQazNdmrIZYK1bynYAw5gpjYZw3iDX7hCHWpkGsFcTyHXM2gViD+RrEWvGS7wSEMVcYC+O8QazZB2KteC3fMWcTiDWYr0GsFS/5TkAYc4WxMM4bxJp9INaK1/IdczaBWIP5GsRa8ZLvBIQxVxgL47xBrNkHYq14Ld8xZxOINZivQawVL/lOQBhzhbEwzhvEmn0g1orX8h1zNoFYC9kq1G6v/uJbT8jkorOyItboXMm0YiffCajYxlwqM8fh02/Vjv24DOO8QazZB2ItN4vDeMx3zNkEYi0PI2cz6TN8KsTafWyItZ6jZuYttvKtHwRb+8p3AorTmKM+69BntGs7W6vetIcTp3rmdhwtjPMWpliT89tTb9XxlLEFH4NMTwfND29+1saTHjalRazJ8x212dhHJst3zNkEYi0PM52a46ZYMx3/7WqtdFrLbsOsDohcrdjEGoXfeOQVp1//7ZGXdfhG9eRkTfFFG3Y5+dyGjJv53P5ffefJlPVb9BrtpM1ZtdXTDpf1S4uKfCegOI057i+yd6q3duJmX5plm3Ye7Cojy7bomhx/Zp24WBjnLQqxRvFlm/c48YNnLzt5v321uk6bumSDq58nzF/tqk/888PPOmlHL1xz9tF9xHRX2X2nLrjaMo/F3CYhlirfL+0HT7zrbJ++dtv1WfOhNIk1v/g//eAZp9/Ynnk7uVJtpv3iTx950ig+Y8EqJ43zm3UZ4ipXKMt3zNkEYi0PY8djfvzU+y6xduv2HX3xoG/0nMZijez/e/TVWDisnxWjWKPw2KXrTvy7v37Dld97zGwn3rrPWFc9PodmXLZvxv/r6Qpq/LzkBYnSdiYm61Rln/uwoWtfUZPvBBSnMUdjiPqNjPuVIavSuJsrf/f+o05dTk8VN9uJg4Vx3qISa7zdf/xcTxqFLNZkPQq/9qPnXWm8zfn/9xcvudr6y2//3rUP2abf9uZ9x1T1ln3V9594x0mXK2uyvtl+PpQmscZ889FXXGl+cdMee6GSk/Zx3Y6ucgPHzNDxL7/80kn/6quvPG0UwvIdczaBWMvD2HlrNO+pbt66rdNSraxxminWnny9Riwc1s+KVayZcfrWnyr/D28nb+mY+RLZvhn/9mOvqwr1O3vq+JXl1QdOi5p8J6C4jTnqt/2HT+jw6Ikznj4nuJys5xfv3H+cWrgiKS469RvrpBfawjhvUYu1oxeTX4ZMKC+dWJNla7cb6MqnccZx3hevjMt2zGPhVfOTV2767sdPrMkyYVCaxBpZ3dZ9nbjsM+LcxeTKqmmcR3bw6ElXfbb1W0tc27KNQli+Y84mEGt5mOmgbFKsPftuXVc5iLXwkGKK0zkuxRrxbu0OvmUfef5THf+gbif19Z+W03HZvhknscbxp9+tp577oGHKsqZY+87jr6uuw6Y5+4+CfCeguI25oeNnO31K9p3HXtPxXz73ifqfV6o56Ryymdt+eTKt0BbGeYtCrP3rT1/w+DTxfp3kCgqlZRJrw6cv0eGrlVt48qVY++ajr6qHfvOWXnGjtFNXbzl1PqzX2SnLQoxW1Wi7fJWWrrZXbNun4x836OrUoVU787jDoLSJNY7/7JkK+jlsir/wQQP18P1VS84n6NEEshs3k+eoUsMuOvzWr8p72uTtf/y+97ZqoSzfMWcTiDWYrxWDWAtCmJNz3Ml3AioLY478gW/PxMXCOG9hijWQHaVFrJVFy3fM2QRiDeZrEGvFS74TUGkfc3H5Vi8tjPMGsWYfiLXitXzHnE0g1mC+VtrEWlki3wkIY64wFsZ5g1izD8Ra8Vq+Y84mEGswX4NYK17ynYAw5gpjYZw3iDX7QKwVr+U75mwCsQbztdIm1j5o0M6TZpPlW/d40qIi3wmoUGPuo0btZZKvvVCxvkwK1aJuP5WFcd4g1uwDsZafjZ25UCZZs3zHnE0g1mC+FnexRhfUcpUaqFerNXG2W/cfreOUTtsU33LguGrVb5Qj1jidwxrteqvaHfvq+EeNO6j2g8Y5+3i/flvVsu9IVb/LAL3drNcw1bjHEFW1dQ/XsVRo1EFVbN7Fabd6m55q4qLVevut2i1V+epNtFijVwy8Uq2xs++oyHcCinLMsSBjQfRi4lxVTvSdzOs+fEKygo9xXQo7DR6rVm/eoY6fPqea9xyiw+17D6q2/UaobsPGO+Ve+6yp2pFIJ+s/dprauGO3U5/e+bR26y5nn+ax1W7fS8fJXq7SKFIhF8Z5g1izTzGItSMnTqt2/Ufp+bJ+p37a1xesWq+qtOiiarXrpaYtXKHHD6VPmrfUNcbI3q3bSr1Tp5XZpMfqJeZRmutOn7ugGnTu56S/UbO5qz0eZzS+mnYf5Ii1l6s2UlVbdnXKteozLNlAhJbvmLMJxBrM14pBrFHYf2LyRbe8TQPer1yqsM2AMU5ZU6gl85Li7926rXVYp2M/V12CXitg1mGozLTl651tEmtmvSjJdwKKcsxJscZ26eq1lHnS5IWEQxZjvE0Cbcm6zTpu5s9dvlaHX3zxheo7Zqqq3rq7U4aM628t2a/DT5t2MrPVig3bXNthWRjnDWLNPsUg1sbNWqju3r2n44vWbHLSyZdJPJHP8/ggk2Nr6botTh6bHKcfJ77skvUcMVGHew8d1SKQbd6KdZ46ZCTWvvjyS3UqIfLY/MpFYfmOOZtArMF8rayItbYDsxdrnM91ibRibRnEmrS3a7fUoZyMz164FLpYI1uy1ivWOKTVAjJ5+5XrpxJr5sUuTAvjvEGs2acYxBrbS5Ub+vov+Xw6sUb2YYN2TtzPGnUZoENeKaP2JsxZbBbxHdss1mhFzrTrN2+5tqOwfMecTUqlWKNbIUHNz4lSGZelNzmb21FauttCfsYDJ1crBrE2bv4KtWn/UWeb8xp2G5QQYcm/kyJIwPFt0M37j6lKzbs65Y9fvuF6ns1s58CZS7ou3b6kbT+xRlD9Ki276Xiz3sPV23VaOXnv1mujeo+b4Tyz1rTXMOeWaVTkOwHlMuaytZIDh9Wy9Vs8Y8YUa3RbU+abJi8kHH7WurtzwaFVNbqdQ9Z39BQ1fMocdfLMeb3NZeavXK/erNnc2S+vDHB7uw8ccQSdaX4XuzAsjPMWplhjv5dI/5ekez605PhZT9rWgyd0mKndbBk4ea4nLUqKQaxt2L5bz2WrNm3X22/VaqGvKZWaddaPArDPv5f4YkrXjvOXLquKiS8pnP5B/TZqxuKVTnt+5ifWyJr1GKzHJhmN8xcTgtE0Lk+3arlcp0FjPF+SorB8x5xNSqVYIwcjx1m4eoPevvP553p76oLlav32EqcMGTuYnPivXb+pQz9LVZcuEGT0zMy42Yt0fOf+Qzr0s/1HjuvnZY6fPqu3aSDxLRY+fm6bxRo5e4WGyYvL5avXdUgDj4w/G5k8tu17Djh52VgxiDWZBpLkOwHlMubibHU69FE12/aUybGzMM5btmKtw+DxOly9c78Oy1dv6uTx2Np19Ixru++EWa7tjfuSX5To2U4zXY7Nqq2667DX2OnOowT83Oexi9c99Wge5brjF6zUYo4u8Gabsg4zZclal1ijL0cULt1S4pT9uEknV10Wl/U699dht5FT9H8My5X2VBSDWIP5W75jzialWqyx0TdhudLEIkaKmhpteiQfkjx/0Skrza/ulWs3dEjQUjP9aS1/SzDNb6nZz7htFmmmWGOj4+R97j18zEkn4/q0okAPkQa1uIs1kJp8J6BcxhwsfwvjvGUr1kyRtGbXAVcep0uxJvN57uHtAZPm6PD1Gs085elHPhRnsUY/1uBHEMz25P7kPpilm0t0SD8mMtOlWDPhRyYYXn2fvHiNDlN9rkxArBWv5TvmbFKmxNr0RSvVxp17nDJ+IS3/ksmlWtO4rBR6byQmKbItJfucZ2U4z8/23RdYfNt27dadzjK1FGv0gCiZKdZoteDW7eTkQsafjYyWs8l4ZS/dcfhZaRVr2X5bZjJN2KkuDIUk3wkolzFn08xnzOSXsFyNx0cxv0YgiFijRwgoZP82V7M4TYo1+Xzout2H1OlrtzVmut+YeUf8SOfklVv6ec8uIyZ76pmrfKPnLFNrSw6qE5fdt2Rlnb0nz6uDZy9rsTZ16TqnXPPew3Vorqx90jT5/6I8F1Ads63OwyfpkH/RnYm4irWgc362RtfTTI8CZBpPfF0La/zmavmOOZuUSrHmZ4V2imKzYhBr9E3evDDQt3d5oaDtlv1G6tdu0DZP0C36jHDKNu05VNVq38d51oyEOt+6oTL1uw5MXMySqwX03Ae9IoRXEUis0QWHbqG8UrWxTpu5cqN+Ls28oFCdis26qCaJfckfQYRNvhNQWGMuk9FP93lSv3Dpin62hbdb9BqiOg4a42w3SPQvrdh8fveuei1xMafJ/ur1G3pc0/M0ptGzL616D1NNug9ypb9arbFq0m2gGjh+hv51W+NEnM4ZGe2H2qSLywcN2upVazJK62w80xOlhXHeshVrQZBjCriJu1hr13+kDmk80CttzHwagxynxQJ+XIAez6E083k2NlOsUR61TyEtEHBZHk90d4lei0NzavsBo5zFiE+bdNSvDjEXPDoMHK3jtCDRfdgE50sZ/dCH8ujZ07At3zFnkzIj1mDBrBjEGn/z33vqguo4ZIKOH790Q+05cc4pwxcavl3CYq37qKk6vmHPYS3UZHm5zSF/2+ZtEmuyTrlKye39py962jh0Lto+IfKdgGyPOXpth7wg8Mo2p0+cu0RP/rR67beytn5bib7lb9ap0iL5ziZpnE+r1fwNn9PMlQC6OJBAtGVhnLcoxBpIT5zFGn8ZkUZiiYzuApF1GTJOlzfHIcdZ7LFJsUY2dNJsHda6L/bkeKIvVr1GTnLSzZU1+tERG/16lMQavVaHrcfwifrXolFYvmPOJhBrMF8rBrHGkGjj12RMWLjKlWcKJQpJoH2cmKgovmTzLv0rTfO5lzdrtUhbv1aHpLDjbVOs8a0a3pZtpNoOm3wnINtjjiZn8yJBxtt+6fQrNTbzmzmtWHLcz+7eu6dDypdl6BkqMlOsmb/AluWjsDDOG8SafeIs1obd/wIjrWdCOJHRyhlb/3HT1JVr11WFhslXdLDPyzcR+Ik1Hjfy0aBR0+frcMbi5JzC6V2HjtMhlb/z+V217f4P4OgX2OajPqZFMQbzHXM2gViD+VoxibV0RC2M4ki+E1CcxlwUE3RcLYzzBrFmn7iKNVhmy3fM2QRiDeZrpUWslUXynYAw5gpjYZw3iDX7QKwVr+U75mwCsQbzNYi14iXfCQhjrjAWxnmDWLMPxFrxWr5jziYQazBfy9eJz1y+rlaVHPFMbCB68j13GHOFsTDO26Kt+zz+AKJl9e6j6tTFq57zEQSMucJYvmPOJrEXa1sPnFBTV+Bbh027fP1mKE5MbciJDURLGOdt7/Gz6vqtO9ItYBHahKWbQjl3GHP2Ceu8Xbp2Q7oFLEKj1czN+455zkVcib1YI8iRiRHz16oxi9aDCOG+vnLjtuc8BGVdyWGnvVEL14MIGTIn2c9hXDgIZ8zNw5iLmjDP27aDJ3Rb5A/SR0C48Hlbs+uQ5zwE5crNpOgjpH+AcBmZ0BFhjjlbFIVYI259fk+t3HFALdu2D0QITfay7/NlU+Lbi9wPCJcwLhiSkxeuYsxZgO4eyL7PlzUlhzz7AeGyce9RT7/nC82/cj8gXFZsP6COnbvs6fu4UzRiDQAAAACgLAKxBgAAAAAQYyDWAAAAAABiDMQaAAAAAECMgVgDAAAAAIgxEGsAAAAAADEGYg0AAAAAIMZArAEAAAAAxBiINQAAAACAGAOxBgAAAAAQYyDWAAAAAABiDMQaAAAAAECMgVgDAAAAAIgxEGsAAAAAADEGYg0AAAAAIMZArAEAAAAAxBiINQAAAACAGAOxBgAAAAAQYyDWAAAAAABiDMQaAAAAAECMgVgDAAAAAIgxEGsAAAAAADEGYg0AAAAAIMZArAEAAAAAxBiINQAAAACAGAOxBgAAAAAQY2Iv1g6euaR+/FlX9WK74er8tZs6rfvMlZ5yUfKDqp09afkQtD3bnzcV5nFMWLVdnxuK+30eTuPwyaYDnHgcPg8du3k8czfv9ZQJG79+YoL0Sbp26LwQMj0IZr9kc1zXb9/VdVIdF517Cs0+Dwve768b9FUbD5zw5OdDqs8uP4Pp2+nK5UK6fuX0TGMxTGicDF60wZMeBDpG9lGzj/M5djqudOcrn7b9kO1FsY98CPNYwmwrHdIXUp3PskrsxRqdtE0HT+rBuGDrfidNlivNxOXzpjqOVOmp8vzSCgkdT73hczzpYZPuc6fLC8I73cZpZHouZHsBqjdiTlblohJrA+avV6v3HNXxyWt2esrkSqpjTZUuybZcOrJpwxRrUUPjhMV3GJifL5vPmgo6rnzqB8XmvnIhzOMLs6102NpPsVIUYo14v8cEvc0TPoUc/3ObYWra+hLnZFPYZ84aVaHXRI8DVOo/VacNXLDeVZ4YsXSzpzznc/hyh5FOeZlHF8k9J86rNXuPqSU7Dnra33LolKvOR70nqb0nL+jtR+r0dPK2Hznj1DE/rzwu8/iebjFYLdj2QMy+1XWsGrtiq+sYZm7c7bS769hZz/Hxfimt0eh5auvhU2rUsi3q2VZD1MXrt5zjOHLusufbPPU3t2N+Rg559YHqcjv82faduqDaTlqiPuiZPMcSKkNifUzi81BI27TauvvEOaf9H1XvopqMma823xf2lM7fzMxjIaieKRworDpwmpPGFyPOlxw7f0XnrSg57GmbvljIY/9R9a7qoz6TnLLlO45KnPfzTh0ux31Se+gsfS7IR6me3L/c57p9xx+03WmUhtrZcTR5Ptcm/FHWaTByrieN2uHtExeuOunnrt7U/U3xYYs3OfUY6jtKo32+1H6E7hfqey7nt7Im983xPzYfpMXXq4k++l2jfmr4Eu/+TCiPV2mu3Lzjamvx9gM6fLiauz4dz+MN+rjGO4Wdpy13jsf0U/J9uc+d98cPzUvmyhqFszbu0e2baXM2JX2SQrMtmjNoRZDyyIfNPHPs0xxH80rd4bNd7VIoxyKHhPyM/eetUxX7TXHSGF4d3ZyYoziP5jI6XnOfdK5/17if3t+Ji9d0Ovm8bE8eiwz5mCluHvuynYecY5dtEbuOn3W2aT41j0u2ReOO5kSuW23QdE89CnkxQB4/84vaPXQ5mj8rJ64fXI+vBebxcXz5rsN6/z+r2d3pb5rnHq/fx9M+Q2Wmrtulz7XZ1ns9xusxIcvScfHY7zZjpZ6nzXoU0ngqOX5OtZqw2JVnilvuFzonZpk/NBvo8mMT+nwb7vstl6exT+N12+HTepu+OK3ff1yvxPI4Jp+i8PKN2864oWuR6Qs8jmkOoboU5/FG54mPff7Wfa798/7ksZYWYi/WmGdaDnadGE73i/ulmds0IcnyvLIiy8tyFJqOTg5Kgoa32QEZrjdu5Tbf9vzKmnmpjslE5pvbsg26OMg0Cocu3uhJS3VshN8FYvamPZ6yHMoLGrcz6L5oNtP84DJtJiYnnXTHxttdpq9w5VH4ZkLEUlwKB3NljbZJLN24c9dzHARNijShyrblMZj5fmVTHX+qfFmWQnkOzJU1ulD4tXPmyg1PO/sTF5JUxymPa1FCBHEaYY4Hc3+cFkSsyX3JY5BQHos1FmdmW5/2neypb64MyfJnLl/3pEnksafybVmOkW2lysvUBod+Y5FCOaeZ7ct9NR2zwOMXfnOZubL2XOuhrnw+BnMfNYfMVEsTAowu7uZx8DnzOya/VTLa5jm0//x1rv3SRV3WkXE/qN7JS0nBScjjNyHhQmWebDrQ1SYJsP+/fftnjSKKwjD+lQQNVgraC2JjI4iFrYiSQrERgoWCGgNREDSd4r80BgQjKKgRrEIEmxTpgoWlIFjEfWfzhrNnJ8uSYHJ2fYofd/bO3Jm7O7N3zj2zG1+3HVul7hNanrg83bdvcT9yu1gX5W2j3D6v+9E5z1o+tNmXvE2caOVjSZzUeN2v3382JjbHG03o4n4vPOwG0pHGqPzzgbzsfrjey/Ea9Dpn1uM+xk35YE2za2Wfjl170HPSdHLWNwfWnWTWHCR4+zywRXE7lW0Dw+HJma1lzaReLq30tIu/I4r1mimqzMfIdcrUeTk/hlDdianHPducne7PrKncLliTmFlT+eLzSpOtcp1m/pqFKtOSbxDDZtZcpwA3to/9y4/xNAjEz8mUOVJA4r5df/q2mTVr9qWMhzIqefblfefA4ciV2db+xPdgzqx9/L7Ws4+8netzZk2lZ/exThkZZ3QU+Dpb0LZPl/kmPTm3sHHw0t1mP8tr3Rmuvj9Tz99tbafPJWfW4o0q1ouyLnrtDEPuTw7WFMyeu/dsq267YM2ZyVjnfSprceDinWZG7QBb6/O1obq2x6BaHpRZi+1dxpuQ63Sdxra5jeRrW+cuZ9ZmFj419fn3hG3HzetdalxRpiTWqczfRZd5TFN5/83Stpk1fU456yTxmO6rjufsq66vW/MfWvue9+XlGKytrv/s6WceX3Mbv15cXt14tNj9/VzsV9xXPLaDBrU737k3aJ2uVfVf50sZptxWTneuRWUYNcbH9/D6a/dJRTyGl3VtO7OmpwbzX741Ga64TTyG65RZO5Uya3m7XK9ljXf6Dng8jO01TjlYdJ0m537tz0VjrD8XvdZ5b8us6Z58vCM+WdCToRgw6b3ru+vJtTPyelqj+5LatAVrMfgdlFnLwZru9T5efMIU+z3qygdrOzFuJynSe9OXItfvhvaZbyJ7SYOkHtdoWbM9PSLM2+wlPxLSsgakkzfm+rYZBzv5ntx89b6vDqNn0LkftO5/sNv3P0z7YbYBIoI17GuwpmPrn765fr8oczPodyWjTtkmzUqVucrrBtH14Vk7RpMyQcpSn7n9pG+d6Lo4enW2ycTkdRge9x/8C2MZrAEAAIwLgjUAAIDCCNYAAAAKI1gDAAAojGANAACgMII1AACAwgjWAAAACiNYAwAAKIxgDQAAoDCCNQAAgMII1gAAAAojWAMAACiMYA0AAKAwgjUAAIDCCNYAAAAKI1gDAAAojGANAACgMII1AACAwgjWAAAACiNYAwAAKIxgDQAAoDCCNQAAgMII1gAAAAojWAMAACjsL5nn322nT29CAAAAAElFTkSuQmCC>
