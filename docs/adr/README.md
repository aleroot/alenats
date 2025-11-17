# Architecture Decision Records (ADRs)

## What Are ADRs?

Architecture Decision Records document the **why** behind technical choices. They are the iceberg beneath every decision:

```
         [What We Chose] ← Visible (10%)
        ═══════════════════════════
                  │
        [What We Rejected] ← Invisible (90%)
        [Forces & Context]
        [Tradeoffs]
        [Consequences]
```

### The Iceberg Principle

For every choice we make, we reject many alternatives for good reason. ADRs capture:

- ✅ **What we decided** - The visible outcome
- ❌ **What we rejected** - Often more important than what we chose
- 🤔 **Why we rejected it** - The reasoning and tradeoffs
- 📊 **Context & forces** - What constraints shaped the decision
- ⚖️ **Consequences** - Both positive and negative outcomes

### Why Document Rejections?

Documenting rejected alternatives prevents:
- **Circular discussions** - "Why don't we use X?" → "We already considered X in ADR-0003"
- **Revisiting bad ideas** - Understanding why something was rejected
- **Lost knowledge** - When team members leave, the reasoning stays
- **Second-guessing** - Future developers understand the context

## ADR Index

| ADR | Title | Status | Date | Tags |
|-----|-------|--------|------|------|
| [0001](0001-testing-infrastructure.md) | Testing Infrastructure and Quality Standards | ✅ Accepted | 2025-11-17 | testing, ci-cd, quality |

## ADR Format

Each ADR follows this structure:

```markdown
---
title: ADR-XXXX: Short Decision Title
status: proposed|accepted|rejected|deprecated|superseded
date: YYYY-MM-DD
tags: [tag1, tag2, tag3]
supersedes: ADR-XXXX (if applicable)
superseded_by: ADR-YYYY (if applicable)
---

# ADR XXXX: Full Decision Title

## Status
[proposed | accepted | rejected | deprecated | superseded by ADR-YYYY]

## Context
What forces are at play? What problem are we solving?
What constraints exist? What are the business/technical requirements?

## Decision
What did we decide to do? Be specific and actionable.

## Alternatives Considered
### Alternative 1: [Name]
- **Pros:** What's good about this approach
- **Cons:** What's bad about this approach
- **Why rejected:** The deciding factor(s)

### Alternative 2: [Name]
- **Pros:** ...
- **Cons:** ...
- **Why rejected:** ...

## Consequences

### Positive
- What benefits do we gain?
- What problems does this solve?

### Negative / Trade-offs
- What do we give up?
- What new problems might this create?
- What technical debt are we accepting?

### Risks
- What could go wrong?
- What assumptions are we making?

## Implementation Notes
Practical details for developers implementing this decision.

## References
- Links to related ADRs
- External documentation
- Research papers or blog posts
- Related issues or PRs
```

## When to Create an ADR

Create an ADR when making decisions that:

1. **Are difficult to reverse** - Database schema, protocols, public APIs
2. **Have significant impact** - Architecture patterns, framework choices
3. **Involve tradeoffs** - Performance vs. simplicity, flexibility vs. constraints
4. **Generate debate** - Multiple valid approaches exist
5. **Need historical context** - Future developers will ask "why?"

## When NOT to Create an ADR

Skip ADRs for:
- **Trivial choices** - Variable naming, minor refactoring
- **Obvious decisions** - Following established project conventions
- **Experimental code** - Proof-of-concepts, temporary hacks
- **Reversible changes** - Easy to change later without breaking things

## ADR Lifecycle

```
┌─────────────┐
│  Proposed   │ ← Draft, open for discussion
└──────┬──────┘
       │
       ├─────→ ┌──────────┐
       │       │ Rejected │ ← Not pursued
       │       └──────────┘
       │
       ├─────→ ┌──────────┐
       │       │ Accepted │ ← Implemented
       │       └────┬─────┘
       │            │
       │            ├─────→ ┌────────────┐
       │            │       │ Deprecated │ ← No longer recommended
       │            │       └────────────┘
       │            │
       │            └─────→ ┌─────────────┐
       │                    │ Superseded  │ ← Replaced by newer ADR
       │                    └─────────────┘
       │
       └─────→ ┌───────────┐
               │  On Hold  │ ← Deferred for later consideration
               └───────────┘
```

## Using ADRs with Claude Code

ADRs are designed to be Claude Code skills. The metadata headers enable:

1. **Searchability** - Claude can find relevant ADRs by tags
2. **Context awareness** - Claude understands decision history
3. **Consistent reasoning** - Claude follows established patterns
4. **Knowledge preservation** - Decisions survive team changes

### Querying ADRs

```bash
# Search by tag
grep -r "tags:.*testing" docs/adr/

# Find all accepted decisions
grep -l "status: accepted" docs/adr/*.md

# List recent decisions
ls -t docs/adr/*.md | head -5
```

## Example: The Iceberg in Practice

**Visible:** "We use Catch2 for testing"

**Invisible (from ADR-0001):**
- ❌ **Rejected Google Test** - More complex setup, older C++ standard
- ❌ **Rejected Boost.Test** - Unnecessary dependency just for tests
- ❌ **Rejected doctest** - Lighter but less mature
- ✅ **Chose Catch2** - Modern, header-only, C++23 support, readable syntax
- ⚖️ **Tradeoff:** New dependency vs. better developer experience
- 📊 **Context:** C++23 project, minimal dependencies preferred
- 💡 **Consequence:** Easier onboarding, faster test writing

Without the ADR, future developers only see "Catch2" and might propose Google Test, restarting the evaluation cycle.

## Contributing

When proposing a new ADR:

1. **Copy the template** from this README
2. **Number sequentially** - Next available ADR number
3. **Fill all sections** - Especially alternatives and consequences
4. **Open a PR** - ADRs should be reviewed like code
5. **Update this index** - Add your ADR to the table above

## Guidelines for Good ADRs

### Do:
- ✅ Document alternatives you seriously considered
- ✅ Explain *why* alternatives were rejected
- ✅ Be honest about negative consequences
- ✅ Include relevant data, benchmarks, or examples
- ✅ Link to related ADRs, issues, or PRs
- ✅ Use clear, concise language
- ✅ Date your decision (context changes over time)

### Don't:
- ❌ Justify decisions post-hoc (write ADRs during decision, not after)
- ❌ Hide downsides or risks
- ❌ Dismiss alternatives without explanation
- ❌ Use ADRs as documentation (use docs/ for that)
- ❌ Make ADRs unnecessarily long (aim for 1-2 pages)

## Revisiting Decisions

ADRs are not immutable. When context changes:

1. **Create a new ADR** - Don't edit old ones (preserve history)
2. **Reference the original** - Link with `supersedes: ADR-XXXX`
3. **Update the old ADR** - Mark as `superseded_by: ADR-YYYY`
4. **Update this index** - Show the relationship

## Further Reading

- [Michael Nygard's ADR article](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions) (original ADR concept)
- [GitHub ADR organization](https://adr.github.io/)
- [Joel Spolsky on "Don't Repeat Yourself"](https://www.joelonsoftware.com/2001/04/21/dont-let-architecture-astronauts-scare-you/) (why document decisions)

---

**Remember:** ADRs are for significant, hard-to-reverse decisions. If you're unsure whether something needs an ADR, discuss it with the team first.
