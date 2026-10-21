# AI Agent Architectures

This document explains how the `security-agent` scaffold in this repository is
structured, and how that compares to other common ways of building AI agents.
It is written to answer a simple question: *is every AI agent built the same
way as this one?* The short answer is no — this scaffold is one design among
many, shaped heavily by its specific problem (authorized, human-supervised
security testing) rather than by a universal template.

## 1. How this `security-agent` is built

The scaffold (see [`ARCHITECTURE.md`](../ARCHITECTURE.md) for the workflow it
implements) is a **deterministic, pipeline-shaped orchestrator with safety
gates**. Its main parts:

| Part | File | Role |
| --- | --- | --- |
| `EngagementConfig` | `src/security_agent/config.py` | Typed, validated engagement policy: who authorized it, the scope (domains, IP ranges, exclusions, time windows, rate limit), and off-by-default permissions. The single source of truth for what is authorized. |
| `ScopeGuard` | `src/security_agent/scope.py` | Fail-closed target gate. Anything not explicitly in scope is denied. Enforces *where* the agent may act. |
| `ApprovalGate` | `src/security_agent/approval.py` | Human-in-the-loop gate. The agent proposes bounded actions; a human confirms anything beyond standing permissions. Denies by default. Enforces *whether* an action may run. |
| `components/` | `src/security_agent/components/` | One module per workflow phase (`discovery`, `infrastructure`, `webapp`, `automation`, `reporting`). Each `run(targets)` passes every target through `ScopeGuard` before acting. Currently stubs. |
| `Agent` | `src/security_agent/agent.py` | Orchestrator + CLI entry point. Validates config in preflight, then runs the five components in a fixed order. |

**Defining traits of this design:**

- **Deterministic sequence.** The components run in a fixed, predefined order.
  There is no model deciding what to do next.
- **No LLM reasoning loop (yet).** Nothing in the current code calls a language
  model. The "AI" capability (e.g. an agent like Strix or Fennec, per
  `ARCHITECTURE.md`) would be plugged into the components later.
- **Safety-first, fail-closed.** Scope enforcement and refuse-by-default
  approval are central, because acting out of bounds in a security context is
  harmful.

## 2. What most AI agents share with this one

Even though the architectures below differ, a few ingredients recur across
almost all serious agents, and this scaffold has them too:

- **A config / policy object** defining what the agent is allowed to do
  (allowed tools, boundaries, budgets). Here: `EngagementConfig`.
- **Guardrails / gates** between the agent and the real world, often with
  human-in-the-loop approval and fail-closed defaults. Here: `ScopeGuard` and
  `ApprovalGate`.
- **An orchestrator / entry point** that drives the steps. Here: `agent.py`.
- **Discrete capabilities / tools** the agent composes. Here: the `components/`
  phases.

What differs between architectures is mainly *how control flows* — who decides
the next step, and how knowledge is brought in.

## 3. Other common agent architectures

### 3a. Single LLM + tools in a loop (ReAct / tool-calling)

The most common "agentic" pattern. A language model is given a set of tools
(functions it can call) and a goal. It loops: **reason → pick a tool → observe
the result → reason again**, until it decides the task is done.

- **Control flow:** the *model* decides each next step at runtime, rather than a
  fixed sequence.
- **Strength:** flexible, handles open-ended tasks, adapts to results.
- **Weakness:** less predictable, can loop or wander, harder to bound — which is
  exactly why a security tool may prefer the deterministic approach this
  scaffold uses.
- **Contrast with this repo:** `security-agent` runs phases in a fixed order
  with no model in the loop; a ReAct agent would hand the ordering decision to
  the model.

### 3b. RAG-style agents (Retrieval-Augmented Generation)

Built around **retrieval**: before (or while) answering, the agent fetches
relevant information from an external knowledge source and feeds it into the
model's context.

- **Typical pipeline:** user query → embed the query → search a vector store /
  database / documents for relevant chunks → insert those chunks into the
  prompt → the model answers grounded in that retrieved material.
- **Why it exists:** keeps answers current and grounded in data the model
  wasn't trained on (internal docs, recent records, a specific codebase), and
  reduces hallucination by citing retrieved sources.
- **Where it fits:** question-answering over private or large corpora, support
  bots, documentation assistants.
- **Contrast with this repo:** RAG centers on *knowledge retrieval*, whereas
  `security-agent` centers on *taking bounded actions*. A security agent could
  use RAG as one component (e.g. to pull known-vulnerability data), but
  retrieval is not its backbone.

### 3c. Graph / state-machine frameworks (e.g. LangGraph)

Instead of one free-running loop, the agent is modeled as a **graph of nodes and
edges**: each node is a step (call the model, run a tool, make a decision), and
edges define the allowed transitions, including branches, loops, and parallel
paths.

- **LangGraph** (part of the LangChain ecosystem) is a well-known framework for
  this: you declare the nodes and the edges between them, keep an explicit
  shared **state** object that flows through the graph, and the framework runs
  it — supporting conditional branching, cycles, persistence/checkpoints, and
  human-in-the-loop interrupts.
- **Strength:** combines structure with flexibility — more controllable and
  inspectable than an open loop, more expressive than a straight pipeline. Good
  for complex workflows that still need branching and retries.
- **Where it fits:** multi-step business workflows, agents that must pause for
  human approval mid-run, anything needing durable/resumable state.
- **Contrast with this repo:** this scaffold is essentially a *linear* pipeline
  (a degenerate graph: five nodes in a row). Expressed in LangGraph, each
  component would be a node, the `ApprovalGate` would become a human-in-the-loop
  interrupt edge, and scope checks would guard transitions — gaining branching
  and resumability the current straight-line orchestrator doesn't have.

### 3d. Multi-agent systems

Multiple specialized agents coordinate, usually via a **planner/orchestrator**
that decomposes a goal and delegates sub-tasks to specialist agents (e.g. a
"recon" agent, an "analysis" agent, a "reporting" agent), then aggregates their
results.

- **Strength:** separation of concerns, parallelism, specialists that are
  individually simpler to reason about.
- **Weakness:** coordination overhead, higher cost, harder to debug end-to-end.
- **Contrast with this repo:** the `components/` here are *modules* called by one
  orchestrator in sequence, not autonomous agents negotiating with each other.
  The security-testing agents referenced in `ARCHITECTURE.md` (Strix, Fennec)
  are themselves multi-agent internally.

## 4. Summary

The ingredients in this scaffold — a policy/config object, guardrails, an
orchestrator, and composable capabilities — appear in most agents. But its
particular shape (deterministic phases, safety-first fail-closed gates, and no
LLM reasoning loop) reflects the security-testing goal, not a standard everyone
follows. Depending on the problem, you might instead reach for a single LLM
tool-calling loop (3a), a RAG pipeline (3b), a graph/state-machine like
LangGraph (3c), or a multi-agent system (3d) — and these are frequently
combined (e.g. a LangGraph graph whose nodes use RAG and delegate to
sub-agents).
