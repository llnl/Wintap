# Wintap — Project Rules & Development Methodology

**This file is the standing rule set for every session.** It is loaded
automatically by Claude Code. It plays the role that `AGENTS.md` plays in the
OpenCode workflow. If this file and the code disagree, the code wins.

---

## Project Summary

Wintap is a researcher-first host-telemetry collection and analytics platform
(LLNL, `LLNL-CODE-837816`). Full-fidelity process / network / file / registry
telemetry, an MEF plugin architecture, an Esper CEP engine for live EPL queries,
and open output formats (Parquet, CSV) queried with DuckDB.

- **Stack:** .NET 10 (SDK 10.0.402) | MEF | Esper CEP | DuckDB | TraceEvent | Parquet
- **Platforms:** Windows (stable), Linux (in development), macOS (experimental)
- **Unified data model:** all telemetry flows through `WintapMessage`.

---

## Repo Layout

| Path | Purpose |
|---|---|
| `Wintap.sln` | Solution root |
| `wintap/Wintap.csproj` | Windows agent (primary) |
| `wintap/Lintap.csproj` | Linux agent |
| `wintap/Mactap.csproj` | macOS agent |
| `shared/WintapAPI/` | Shared API library |
| `shared/ai/wintap_mcp_server/` | DuckDB-backed MCP server |
| `shared/Wintap-Workbench/` | Workbench tooling |
| `platform/windows/` | Windows-specific platform code |
| `documentation/` | Human-authored docs (developer guide, ETL flow, Esper) |
| `devtools/` | Python dev/analysis tooling |
| `tests/` | Test projects (xUnit) — see Verification |

---

## Build & Verification Commands

| Action | Command |
|---|---|
| Build (Release) | `dotnet build -c Release` |
| Build (Debug) | `dotnet build` |
| Run all tests | `dotnet test` |
| Run a unit's tests | `dotnet test --filter "Category=P1.1"` |

**Test framework: xUnit.** Tests live under `tests/` (e.g.
`tests/Wintap.Tests/Wintap.Tests.csproj`). Every test is tagged with an
xUnit trait so it can be filtered by unit:

```csharp
[Trait("Category", "P1.1")]
```

> **Standing up tests is unit P1.1** — the first instruction the Engineer
> should write. Until that project exists, the Developer's verification gate
> falls back to a passing `dotnet build -c Release` plus a documented manual
> run. After P1.1 lands, every unit with testable behavior must ship passing
> tests filtered by its category.

**Unit naming convention (2026-08-17).** Instruction units are named
`<feature-abbrev>-<nn>` with a descriptive slug in filenames — e.g. feature
`improve-windows-process-collection` declares abbreviation `wpc`, giving
instruction `developer_docs/instructions/wpc-01-sid-helper.md`, trait
`[Trait("Category", "wpc-01")]`, and audit
`developer_docs/audits/wpc-01-sid-helper.md`. Each feature declares its
abbreviation once in its implementation plan, so numbers never collide across
features. Run one unit with `dotnet test --filter "Category=wpc-01"`; run a
whole feature with `dotnet test --filter "Category~wpc"`. The bootstrap unit
**P1.1** (and its owed follow-up P1.2) predate this scheme and are
grandfathered — do not rename them.

---

## The Methodology — Three Roles

This project uses a role-separated workflow (adapted from the OpenCode
Architect / Engineer / Developer pattern and the Karpathy "LLM wiki" idea).
The persistent ecosystem wiki is the compounding project memory.

> **Wiki location.** The Wintap ecosystem wiki lives in
> `../Wintap-Analytics/wiki/`. The old per-developer `dave-wiki/` has been
> retired; see
> `../Wintap-Analytics/wiki/decision/consolidate-developer-wiki-into-analytics-wiki.md`.
> Collision avoidance now comes from feature-scoped work folders under
> `../Wintap-Analytics/wiki/work/<feature-slug>/` plus the low-volume shared
> `../Wintap-Analytics/wiki/log.md`.

### Architect — *the human*
The decision-maker, the only approval gate, and the **sole liaison between
Engineer and Developer**. The Architect decides direction, approves instruction
documents, dispatches the Developer, and manually relays any Developer output
(audits, test results, logs) the Engineer needs to see.

### Engineer — *Claude, in the main session*
Design collaborator and **maintainer of `../Wintap-Analytics/wiki/` for Wintap
ecosystem knowledge plus `developer_docs/` process artifacts in this repo**.
Explores options, writes ADRs, maintains wiki pages and `log.md`, and writes
self-contained instruction documents for the Developer. **Never writes source
code or tests.** Interfaces only with the Architect — never dispatches or
communicates with the Developer directly.

### Developer — `.claude/agents/developer.md`
Implements **exactly one approved instruction document at a time**, dispatched
by the Architect. Writes code and tests, runs the verification command, and
files one audit artifact per unit. **Never edits `../Wintap-Analytics/wiki/`
or `developer_docs/instructions/`.**

### The loop
1. Architect works with the **Engineer** in the main session to explore a
   problem and draft an instruction document.
2. Architect reviews and **approves** the instruction (the gate).
3. Architect dispatches the **Developer** to implement that one approved unit.
4. Developer reports full test/build output and files an audit artifact.
5. Architect relays results to the Engineer, who folds them back into the wiki.

> The Developer runs in an isolated context and cannot pause for approval
> mid-run. Approval happens in the main session before dispatch — never hand
> an unapproved instruction to the Developer.

### Engineer access boundary

The Engineer can only access content under `C:\PUBLIC`. Anything outside —
logs, test results, machine or environmental details — is opaque to the
Engineer. The Architect manually shares such data when relevant; the Engineer
may ask to see it but must never attempt to access it directly.

### Feature metrics mini-lab

Features using the LLM-assisted workflow may carry the velocity/ROI mini-lab in
`../Wintap-Analytics/wiki/decision/ai-velocity-roi-mini-lab.md`: feature open
adds two sealed estimate questions to the interview; feature close asks whether
the human would have attempted the feature without AI. At close, the main
session computes the 15-minute-gap attention proxy and gives it to the Engineer;
metrics never gate or nag the workflow.

---

## Directory Ownership

| Path | Engineer | Developer |
|---|---|---|
| `../Wintap-Analytics/wiki/**` | Read / Write | Read only |
| `developer_docs/instructions/**` | Read / Write | Read only |
| `developer_docs/design/**`, `features/**` | Read / Write | Read only |
| `developer_docs/audits/**` | Read only | Read / Write |
| Source dirs (`wintap/`, `shared/`, `platform/`) | Read only | Read / Write |
| `tests/**` | Read only | Read / Write |

These boundaries are enforced by subagent tool limits plus instruction
discipline, not by hard filesystem ACLs. Respect them.

---

## Source of Truth Order

When information conflicts, resolve in this order:

1. The codebase as it currently exists
2. The approved instruction document
3. Relevant decisions in `../Wintap-Analytics/wiki/decision/`
4. Prior audit artifacts in `developer_docs/audits/`
5. General standards in this file

If resolving a conflict would require an architectural decision, **stop and
raise it to the Architect.** Do not resolve architectural ambiguity unilaterally.

---

## Design Brevity Standard (Engineer)

Design the smallest solution that fully meets the stated requirements.

- **Scope:** One instruction unit covers one change. Do not design for
  requirements that have not been stated. If you see a plausible future
  need, note it in one sentence and move on — do not design for it.
- **Options:** When exploring alternatives, present at most 2–3, each in a
  few sentences, with a recommendation. No exhaustive surveys.
- **Instruction documents:** State requirements, files to touch, the
  verification command, and acceptance criteria. Omit background the
  Developer can get from the code. Specify *what* and *why*; leave *how*
  to the Developer unless a constraint is real. Target one page.
- **New anything is a cost:** New layers, interfaces, config keys,
  dependencies, or files require a stated justification tied to a current
  requirement, observed behavior, or material correctness/security risk.
  Default to existing project patterns and localized change.
- **Writing style:** Wiki pages, ADRs, and reports are short and factual.
  Lead with the decision or finding. Cut hedging, restatement, and
  boilerplate sections that have nothing to say.

---

## Coding Standards

- Target .NET 10.0 (SDK 10.0.402; Windows-qualified TFMs where required); match the style of surrounding code.
- Do not add NuGet dependencies without flagging them to the Architect first.
- Never store secrets, API keys, or connection strings in code — use
  environment variables or gitignored local config.
- Do not introduce abstractions, error handling, or features beyond what the
  active instruction requires.
- Implement the smallest clear solution that fully meets the instruction.
  Justify any remaining non-obvious complexity in the audit artifact, not in
  code comments.
