export default {
  async fetch(request, env) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Content-Type": "application/json",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    if (request.method === "GET") {
      return new Response(
        JSON.stringify({ status: "OK", message: "Stremini Security & Scalability Analysis Worker is running." }),
        { status: 200, headers: corsHeaders }
      );
    }

    if (request.method !== "POST") {
      return new Response(
        JSON.stringify({ status: "ERROR", message: "Method not allowed." }),
        { status: 405, headers: corsHeaders }
      );
    }

    try {
      let body;
      try {
        body = await request.json();
      } catch (_) {
        return new Response(
          JSON.stringify({ status: "ERROR", message: "Invalid JSON body." }),
          { status: 400, headers: corsHeaders }
        );
      }

      // ── Payload shape ──────────────────────────────────────────────────────
      // Option A — GitHub repo analysis (preferred):
      //   { repoUrl: "https://github.com/owner/repo", focus?: "security"|"scalability"|"both", history?: [] }
      //   The worker fetches the repo contents using GITHUB_TOKEN secret.
      //
      // Option B — Raw code / pre-assembled dump (fallback):
      //   { query: "<raw code or assembled file dump>", focus?: ..., history?: [] }

      const { query: rawQuery, repoUrl, history = [], focus = "both" } = body;

      // ── GitHub repo fetch path ─────────────────────────────────────────────
      let assembledQuery = rawQuery || "";

      if (repoUrl && typeof repoUrl === "string" && repoUrl.trim()) {
        const parsed = parseGitHubRepoUrl(repoUrl.trim());
        if (!parsed) {
          return new Response(
            JSON.stringify({ status: "ERROR", message: "Invalid GitHub repo URL. Expected https://github.com/owner/repo or owner/repo." }),
            { status: 400, headers: corsHeaders }
          );
        }

        if (!env.MBZUAI_API_KEY) {
          return new Response(
            JSON.stringify({ status: "ERROR", message: "Worker secret MBZUAI_API_KEY is not set." }),
            { status: 500, headers: corsHeaders }
          );
        }

        // Fetch repo files server-side using the GITHUB_TOKEN secret
        let fileDump;
        try {
          fileDump = await fetchRepoFileDump(parsed.owner, parsed.repo, env.GITHUB_TOKEN || "");
        } catch (ghErr) {
          return new Response(
            JSON.stringify({ status: "ERROR", message: `GitHub fetch failed: ${ghErr.message ?? String(ghErr)}` }),
            { status: 502, headers: corsHeaders }
          );
        }

        // Prepend any user-supplied context (focus notes, known issues, etc.)
        assembledQuery = rawQuery
          ? `${rawQuery.trim()}\n\n${fileDump}`
          : fileDump;
      }

      if (!assembledQuery || typeof assembledQuery !== "string" || !assembledQuery.trim()) {
        return new Response(
          JSON.stringify({ status: "ERROR", message: "Provide either a `repoUrl` (GitHub repo) or `query` (raw code / file dump) in the request body." }),
          { status: 400, headers: corsHeaders }
        );
      }

      if (!env.MBZUAI_API_KEY) {
        return new Response(
          JSON.stringify({ status: "ERROR", message: "Worker secret missing. Please set MBZUAI_API_KEY." }),
          { status: 500, headers: corsHeaders }
        );
      }

      // ── Validate focus ─────────────────────────────────────────────────────
      const VALID_FOCUS = ["security", "scalability", "both"];
      const resolvedFocus = VALID_FOCUS.includes(focus) ? focus : "both";

      // ── Cap query length ───────────────────────────────────────────────────
      const MAX_QUERY_CHARS = 28000;
      const query =
        assembledQuery.length > MAX_QUERY_CHARS
          ? assembledQuery.slice(0, MAX_QUERY_CHARS) +
            "\n\n[Note: input was truncated to 28 000 characters to fit the model context window.]"
          : assembledQuery;

      const trimmedHistory = history.slice(-10);

      // ── Shared preamble ────────────────────────────────────────────────────
      const PATIENCE_PREAMBLE = `IMPORTANT: Take your time. Think through every aspect of the codebase fully before writing any output. Produce one complete, deeply reasoned report. Do NOT truncate sections. Do NOT use placeholder text like "[analysis here]" — every section must contain real, specific findings tied to the actual code.`;

      // ── Build system prompt based on focus ────────────────────────────────
      const today = new Date().toLocaleDateString("en-US", {
        year: "numeric", month: "long", day: "numeric",
      });

      let systemPrompt;

      // ─── SECURITY-ONLY ────────────────────────────────────────────────────
      if (resolvedFocus === "security") {
        systemPrompt = `You are Stremini, a senior application security engineer who writes clear, elegant, and practical reports for product teams.

${PATIENCE_PREAMBLE}

Goal:
- Produce a security report that is visually clean, concise, and immediately actionable.
- Prioritize signal over volume; avoid bloated prose.
- Keep findings specific to the provided codebase.

Output rules:
- Output ONLY a single <security_analysis>...</security_analysis> block.
- Use GitHub-flavored Markdown inside the tag.
- Keep total response under ~1,200 words unless the codebase is clearly large/risky.
- Use short paragraphs and bullet points.
- Never use placeholders.
- If evidence is insufficient, explicitly say so.

Required format (exact section order):

<security_analysis>
# Security Analysis Report

**Date:** ${today}
**Stack:** [detected]
**Files reviewed:** [count + key files]
**Overall risk:** [Critical | High | Medium | Low]

## 1) Executive Summary
- 3-5 bullets max.
- Include: top risk, likely impact, and highest-ROI fix.

## 2) Top Findings (Prioritized)
List up to 8 findings, highest risk first. Use this compact template for each finding:

### [Severity] Finding Title
- **Where:** `path/to/file` → `functionName` (line/pattern)
- **Why it matters:** one sentence in business terms.
- **Evidence:** quote the exact risky code or behavior.
- **Exploit path:** brief, concrete attacker flow (1-3 steps).
- **Fix:** precise remediation guidance (short).
- **Patch sketch:** include a minimal safe code snippet only when it materially helps.

If no meaningful findings: provide "No high-confidence vulnerabilities identified" and include residual risks.

## 3) Security Scorecard
| Area | Score (0-10) | Note |
|---|---:|---|
| AuthN/AuthZ | [x] | [short note] |
| Input & Injection | [x] | [short note] |
| Secrets & Crypto | [x] | [short note] |
| Data Exposure | [x] | [short note] |
| Dependency Risk | [x] | [short note] |
| Logging & Monitoring | [x] | [short note] |
| **Overall** | **[x.x]** | [one-line verdict] |

## 4) 30/60/90 Day Remediation Plan
- **Next 30 days:** critical fixes only.
- **Day 31-60:** high-risk hardening.
- **Day 61-90:** systemic improvements and automation.
Each bullet must reference the related finding title.

## 5) Developer Handoff Prompt (for AI coding assistant)
Provide one concise, ready-to-paste prompt that asks an AI coding assistant to fix all listed findings.
Requirements for this prompt:
- include stack + file context,
- enumerate each finding with exact location,
- request complete updated files (no diffs),
- enforce secure coding standards used in this project.

</security_analysis>

Hard constraints:
- Be specific and evidence-based; do not invent files/functions not present in input.
- Do not include long generic security theory.
- Keep tone confident, practical, and concise.`;

      // ─── SCALABILITY-ONLY ─────────────────────────────────────────────────
      } else if (resolvedFocus === "scalability") {
        systemPrompt = `You are Stremini, a principal engineer and distributed-systems architect with 15+ years scaling systems from zero to millions of users. You have deep expertise in performance engineering, database internals, distributed caching, async processing patterns, cloud-native architecture, and capacity planning. You produce detailed, evidence-based reports that engineering leads use to make real infrastructure decisions.

${PATIENCE_PREAMBLE}

Wrap your ENTIRE output inside <scalability_analysis></scalability_analysis> tags. Write deeply. Every finding must reference exact file names, function names, query patterns, and data-flow traces from the submitted code. Include concrete numbers (estimated RPS ceilings, latency impacts, memory growth rates) where derivable from the code.

<scalability_analysis>
SCALABILITY ANALYSIS REPORT
============================
Language / Framework: [detected — be precise]
Analysis Date: ${today}
Files Analysed: [list every file header found]
Scalability Verdict: [NOT SCALABLE | NEEDS WORK | MODERATELY SCALABLE | HIGHLY SCALABLE] — one sentence naming the primary bottleneck

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EXECUTIVE SUMMARY
[4-5 sentences. Name the most critical bottleneck and its failure mode, estimate a concrete scale ceiling (e.g. "this will likely fail above ~200 concurrent requests due to blocking DB calls in the request path"), call out systemic design issues (missing caching layer, synchronous processing of heavy work, no connection pooling), and name the single highest-impact fix. Written for a CTO but grounded in actual code patterns.]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LOAD PROFILE ANALYSIS
Estimated Scale Ceiling (current code):
- Optimistic estimate (lightly loaded, no spikes): [e.g. "~500 req/s"]
- Realistic estimate (steady load, average query times): [e.g. "~150 req/s"]
- Failure point (spike load, slow queries): [e.g. "~80 concurrent users before DB pool exhaustion"]
Primary Bottleneck: [layer and specific cause with file/function reference]
Secondary Bottleneck: [next limiting factor]
Failure Mode: [step-by-step — what happens first when load increases: connection pool hits limit, memory grows, GC pauses, queue backs up, external API times out, etc.]
Single Node vs Horizontal: [can this run on multiple instances today, or is there shared mutable state / local file dependency / sticky sessions that prevents it?]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ALGORITHMIC COMPLEXITY
[Analyse every significant function, route handler, and data processing block. Do not skip small functions that are called in hot paths.]

► Function / Module: [exact name + file reference]
  Hot Path: [yes/no — is this called on every request or just occasionally?]
  Time Complexity: [Big-O with justification from the actual code]
  Space Complexity: [Big-O with justification]
  Problem at Scale: [concrete scenario — e.g. "with 100k records this produces 100k DB queries sequentially, adding ~50ms per record = 5-second response time"]
  Current code:
\`\`\`
[the problematic code snippet]
\`\`\`
  Optimised Approach:
\`\`\`
[complete optimised replacement — fully implemented, includes all necessary imports]
\`\`\`
  Expected gain: [e.g. "reduces 100k queries to 1 batched query, estimated 100x latency improvement"]

[Repeat for every significant function]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

DATABASE & PERSISTENCE LAYER
[4-5 paragraphs. Be exhaustive and specific.]
Para 1 — N+1 queries: [identify every loop that triggers a DB query, name the files and ORM calls, estimate the query multiplication factor]
Para 2 — Index coverage: [list every query pattern and whether appropriate indexes likely exist; flag full-table scans, unindexed WHERE clauses, ORDER BY on non-indexed columns]
Para 3 — Connection pool: [what is the pool size? is it configurable? what happens when it's exhausted — timeout, queue, or crash?]
Para 4 — Transaction scope & locks: [are transactions too broad? are they holding locks across async operations? risk of deadlocks?]
Para 5 — Schema & sharding readiness: [any UUID vs sequential ID issues, partitioning readiness, read replica potential]

CACHING STRATEGY
[3-4 paragraphs. What is currently cached (explicitly)? What is implicitly cached at the HTTP layer? What should be cached but isn't (list the specific queries or computations)? Recommend the exact caching layer (in-process LRU, Redis, Memcached, CDN edge) matched to each type of data. Include cache key design, TTL recommendations, and cache invalidation strategy for the specific data access patterns in the code.]

CONCURRENCY & PARALLELISM
[3-4 paragraphs. For each language/runtime detected: event loop blocking (Node), GIL contention (Python), goroutine leaks (Go), thread pool starvation (Java/C#). Identify every synchronous operation in async context, every missing await, every blocking I/O in the hot path. Identify work that could be parallelised (Promise.all, goroutine fan-out, async gather) but currently runs sequentially.]

STATELESSNESS & HORIZONTAL SCALING
[3 paragraphs: (1) list every piece of in-process state (in-memory caches, open file handles, module-level variables, singleton instances) and what breaks if two instances run simultaneously; (2) session/auth state — is it stored locally or in a shared store?; (3) concrete migration path to make the service fully stateless — what needs to move to Redis/DB/shared storage.]

EXTERNAL DEPENDENCIES & RESILIENCE
[For each external API / service call found in the code:]
► Dependency: [service name, file, function]
  Timeout: [configured? default? what happens on slow response?]
  Retry logic: [present? exponential backoff? max retries?]
  Circuit breaker: [present? recommended library for this stack?]
  Cascade failure risk: [if this service is down or slow at 10× load, what is the blast radius?]
  Recommendation: [specific code change with timeout value, retry config, circuit breaker setup]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

MEMORY & RESOURCE MANAGEMENT
[2-3 paragraphs. Unbounded collections that grow without limit, missing stream processing for large file/data operations, connection objects not closed in error paths, event emitter listener leaks, timer/interval leaks. Name specific files and patterns.]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SCALABILITY SCORECARD
| Dimension                        | Score (0-10) | Verdict            |
|----------------------------------|--------------|--------------------|
| Algorithmic Efficiency           | [X]          | [Pass/Warn/Fail]   |
| Database Design & Queries        | [X]          | [Pass/Warn/Fail]   |
| Caching & Read Optimisation      | [X]          | [Pass/Warn/Fail]   |
| Concurrency & Async Design       | [X]          | [Pass/Warn/Fail]   |
| Statelessness / Horiz. Scale     | [X]          | [Pass/Warn/Fail]   |
| Resilience & Fault Tolerance     | [X]          | [Pass/Warn/Fail]   |
| Memory & Resource Management     | [X]          | [Pass/Warn/Fail]   |
| Overall Scalability Score        | [X.X/10]     | [Not Scalable/...]  |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SCALING ROADMAP
🔴 Phase 1 — Quick wins (hours, high ROI):
[List specific code changes with file + function references. Each item should be actionable in < 2 hours.]

🟠 Phase 2 — This sprint (days, architectural):
[Caching layer, query optimisation, async refactors. Each item with file references.]

🟡 Phase 3 — Next sprint (weeks, infrastructure):
[Connection pooling config, horizontal scaling prep, background job queue introduction]

🟢 Phase 4 — Long-term architecture (months):
[1-2 paragraphs: what this system must look like at 10× and 100× current load — concrete patterns (read replicas, CQRS, event-driven async, CDN offload, horizontal pod autoscaling) matched to the actual code and detected stack.]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

AI FIX PROMPT
[CRITICAL SECTION — Write a ready-to-use prompt the developer can paste directly into an AI coding assistant (Claude, ChatGPT, Copilot) to implement ALL scalability fixes in one pass. The prompt must:
1. Describe the codebase context (language, framework, files)
2. List every performance issue with its exact file and function location
3. Specify the exact optimisation to apply for each
4. State the expected outcome / performance target
5. Request complete, drop-in replacement files

Format exactly like this:

--- BEGIN AI FIX PROMPT ---
You are an expert [language] performance engineer. I have a [framework] application with confirmed scalability bottlenecks identified by a professional audit. Please implement ALL the following optimisations and return complete, updated file contents for every file that changes.

CODEBASE CONTEXT:
- Language / Framework: [from report]
- Files: [list all analysed files]
- Current scale ceiling: [from report]
- Target: [e.g. "Handle 1000 req/s with p99 latency < 200ms"]

PERFORMANCE ISSUES TO FIX:
[For each finding:]
[N]. [Issue Name]
   File: [exact path]
   Function/Location: [exact reference]
   Problem: [one sentence]
   Required fix: [precise instruction — e.g. "Replace the forEach loop that queries the DB per iteration with a single batched findMany call using the collected IDs"]
   Expected gain: [from report]

IMPLEMENTATION STANDARDS:
- [e.g. Use DataLoader pattern for all N+1 query resolution]
- [e.g. Add Redis caching with ioredis, TTL 300s for user profile queries]
- [e.g. Move email sending to a background queue using BullMQ]
- [Add stack-specific standards]

DELIVERABLE: Return the complete, updated content of every changed file. Do not return diffs. Include all imports. Include brief inline comments explaining each optimisation.
--- END AI FIX PROMPT ---]
</scalability_analysis>

ABSOLUTE RULES:
- Output ONLY the <scalability_analysis>…</scalability_analysis> block. Zero words outside it.
- Every finding must reference real patterns from the submitted code — no generic advice.
- Include both current problematic code AND optimised replacement in every algorithmic complexity finding.
- The AI Fix Prompt section is MANDATORY.
- Numeric scores required in the scorecard.`;

      // ─── BOTH (default) ───────────────────────────────────────────────────
      } else {
        systemPrompt = `You are Stremini, a principal engineer combining elite application security expertise (OWASP, CVE research, penetration testing, threat modelling) with deep distributed-systems architecture knowledge (performance engineering, database scaling, cloud-native design). You have 15+ years of experience hardening and scaling production systems. You produce the kind of thorough, evidence-based, actionable reports that senior engineers and CTOs use to make real architectural and security decisions.

${PATIENCE_PREAMBLE}

Wrap your ENTIRE output inside <analysis></analysis> tags. Write at depth. Every section must be rich, specific, and grounded in exact file names, function names, line patterns, and data-flow traces from the submitted code. Do NOT omit any section. Do NOT use generic advice — every recommendation must be grounded in what you actually see in the code.

<analysis>
CODE SECURITY & SCALABILITY REPORT
====================================
Language / Framework: [detected — be precise, e.g. "TypeScript + Next.js 14 App Router + Prisma 5 + PostgreSQL 15 + Redis 7"]
Analysis Date: ${today}
Files Analysed: [list every === FILE: path === header extracted from the submission]

Overall Security Verdict:    [CRITICAL | HIGH RISK | MEDIUM RISK | LOW RISK | SECURE] — name the worst finding
Overall Scalability Verdict: [NOT SCALABLE | NEEDS WORK | MODERATELY SCALABLE | HIGHLY SCALABLE] — name the primary bottleneck

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EXECUTIVE SUMMARY
Security:    [3-4 sentences. Name the most dangerous finding and its real-world exploitability. Describe the overall security posture. Call out any systemic weaknesses. State the single most important action.]
Scalability: [3-4 sentences. Name the primary bottleneck with a concrete scale ceiling estimate (e.g. "will fail above ~200 concurrent users"). Describe the failure mode. State the single highest-ROI fix.]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 1 — SECURITY ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

THREAT MODEL
Attack Surface: [List every concrete entry point — each HTTP route with its method and file reference, file upload endpoints, WebSocket handlers, env var injection points, third-party webhook receivers, admin interfaces]
Trust Boundaries: [Trace exactly where user-controlled data crosses into privileged operations — DB queries, file system, shell, third-party APIs]
Data Assets at Risk: [Every category of sensitive data handled — PII, credentials, payment data, session tokens, API keys — with file locations]
Attacker Profiles:
- Unauthenticated external: [specific attack surface available]
- Authenticated user (IDOR/privilege escalation): [specific risk with route/function reference]
- Compromised supply chain: [blast radius]

VULNERABILITY FINDINGS
[Exhaustively find every vulnerability. For each severity tier, list ALL findings. Quote actual code. Never omit a tier — write "None identified." if clean.]

CRITICAL SEVERITY
► [Vulnerability Name]
  CWE / OWASP: [e.g. CWE-89 / OWASP A03:2021 Injection]
  Location: [exact file path + function name + line pattern]
  Root Cause: [the exact code snippet that creates the vulnerability]
  Attack Scenario: [step-by-step attack with concrete HTTP request / payload]
  Business Impact: [worst-case consequence]
  Remediation:
\`\`\`
[Complete, drop-in replacement code — fully implemented, no placeholders]
\`\`\`
  Effort to Fix: [Low | Medium | High] · Urgency: [Fix before next deploy | Fix this sprint | Fix next sprint]

[Repeat for every CRITICAL finding]

HIGH SEVERITY
[Same block for every HIGH finding]

MEDIUM SEVERITY
[Same block for every MEDIUM finding]

LOW SEVERITY / INFORMATIONAL
[Same block for LOW findings — missing headers, verbose errors, minor config issues]

AUTHENTICATION & AUTHORISATION DEEP-DIVE
[3-4 paragraphs: session / token generation and validation, JWT alg:none risk, IDOR patterns, role-based access control consistency, password hashing algorithm and cost factor, API key handling. Quote specific code.]

CRYPTOGRAPHY & SECRETS AUDIT
[3-4 paragraphs: every hardcoded secret found verbatim, secret management approach, hashing algorithms, encryption in transit/at rest, RNG quality, .env committed to git risk.]

INPUT VALIDATION & OUTPUT ENCODING
[3-4 paragraphs: where user input enters the system, validation present vs absent, parameterised queries vs string concatenation, output encoding for HTML/SQL/shell, file upload validation, regex DoS risk.]

DEPENDENCY & SUPPLY-CHAIN SECURITY
[List every imported package. Flag CVEs, unmaintained packages, wildcard version pins. Recommend lockfile, audit CI step, SBOM.]

DATA EXPOSURE & PRIVACY
[3-4 paragraphs: sensitive fields in API responses, verbose error messages leaking internals, PII in logs, GDPR surface — deletion, consent, data minimisation.]

ERROR HANDLING & SECURITY LOGGING
[2-3 paragraphs: silent catch blocks, structured security event logging, alertable events, sensitive data in logs.]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 2 — SCALABILITY ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LOAD PROFILE
Estimated Scale Ceiling: [concrete estimate with reasoning — e.g. "~150 req/s before PostgreSQL connection pool of 10 exhausts, causing queued requests to timeout after 5s"]
Primary Bottleneck: [layer + specific code location]
Secondary Bottleneck: [next limiting factor]
Failure Mode: [step-by-step cascade — what breaks first, then what]
Horizontal Scaling Readiness: [yes/no + what prevents it with specific code references]

ALGORITHMIC COMPLEXITY
[Analyse every hot-path function. Include current problematic code AND optimised replacement.]
► Function / Module: [name + file]
  Hot Path: [yes/no]
  Time Complexity: [Big-O + justification]
  Space Complexity: [Big-O + justification]
  Problem at Scale: [concrete numbers — e.g. "1000 users = 1000 sequential DB queries = ~10s response"]
  Current code:
\`\`\`
[the problematic snippet]
\`\`\`
  Optimised code:
\`\`\`
[complete, working replacement]
\`\`\`
  Expected gain: [estimated improvement]

DATABASE & PERSISTENCE LAYER
[4-5 paragraphs: N+1 query identification with file/function refs and multiplication estimates, index coverage gaps, connection pool configuration and exhaustion risk, transaction scope and lock duration, read replica potential, sharding readiness.]

CACHING STRATEGY
[3-4 paragraphs: what is currently cached vs what should be, recommended cache layer per data type, concrete key design, TTL recommendations, invalidation strategy matched to the actual data patterns in the code.]

CONCURRENCY & PARALLELISM
[3-4 paragraphs: blocking ops in async context, missing parallelisation opportunities (Promise.all candidates, goroutine fan-out, etc.), race conditions under load, queue vs synchronous processing for heavy operations, event loop / thread pool / GIL issues specific to the detected runtime.]

STATELESSNESS & HORIZONTAL SCALING
[3 paragraphs: every in-process state item and what breaks at scale, session/auth state portability, concrete migration path to stateless design.]

EXTERNAL DEPENDENCIES & RESILIENCE
[For each external call found:]
► [Service]: [file + function] — timeout: [?] / retry: [?] / circuit-breaker: [?]
  Risk: [cascade failure scenario at high load]
  Fix: [concrete code with timeout value and retry config]

MEMORY & RESOURCE MANAGEMENT
[2-3 paragraphs: unbounded collections, large data without streaming, unclosed connections in error paths, listener/timer leaks. File references.]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 3 — COMBINED SCORECARDS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SECURITY SCORECARD
| Category                        | Score (0-10) | Verdict            |
|---------------------------------|--------------|--------------------|
| Authentication & Authorisation  | [X]          | [Pass/Warn/Fail]   |
| Injection & Input Handling      | [X]          | [Pass/Warn/Fail]   |
| Cryptography & Secret Mgmt      | [X]          | [Pass/Warn/Fail]   |
| Dependency Security             | [X]          | [Pass/Warn/Fail]   |
| Data Exposure & Privacy         | [X]          | [Pass/Warn/Fail]   |
| Error Handling & Logging        | [X]          | [Pass/Warn/Fail]   |
| API & Network Security          | [X]          | [Pass/Warn/Fail]   |
| Overall Security Score          | [X.X/10]     | [verdict]          |

SCALABILITY SCORECARD
| Dimension                        | Score (0-10) | Verdict            |
|----------------------------------|--------------|--------------------|
| Algorithmic Efficiency           | [X]          | [Pass/Warn/Fail]   |
| Database Design & Queries        | [X]          | [Pass/Warn/Fail]   |
| Caching & Read Optimisation      | [X]          | [Pass/Warn/Fail]   |
| Concurrency & Async Design       | [X]          | [Pass/Warn/Fail]   |
| Statelessness / Horiz. Scale     | [X]          | [Pass/Warn/Fail]   |
| Resilience & Fault Tolerance     | [X]          | [Pass/Warn/Fail]   |
| Memory & Resource Management     | [X]          | [Pass/Warn/Fail]   |
| Overall Scalability Score        | [X.X/10]     | [verdict]          |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 4 — UNIFIED REMEDIATION ROADMAP
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[Each item references a specific finding. Ordered by combined risk × impact. Include the file and function to change.]

🔴 Fix Before Next Deploy (hours — blocking issues):
1. [Sec/Perf] [Finding name] · File: [path] · Action: [precise one-line instruction]
[continue for all CRITICAL findings]

🟠 Fix This Sprint (days — high-risk):
[continue for all HIGH findings]

🟡 Fix Next Sprint (weeks — medium-risk):
[continue for MEDIUM findings]

🟢 Long-Term Architecture:
[1-2 paragraphs: what this system must look like at 10× load with hardened security — concrete patterns matched to the actual codebase and detected stack. Name specific libraries, services, patterns.]

RECOMMENDED TOOLING
Security — [3 specific tools for this stack: tool name, what it catches, how to integrate]:
Performance — [3 specific tools for this stack: profiler, APM, load tester]:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 5 — AI FIX PROMPT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[CRITICAL SECTION — Write a complete, self-contained prompt the developer can paste directly into Claude, ChatGPT, or Copilot to fix ALL security vulnerabilities AND performance issues in one pass. Requirements:
- Must include full codebase context so an AI with no prior knowledge can act on it
- Must enumerate every finding with exact file + function location
- Must give unambiguous, specific fix instructions (not vague "validate input" — say "add zod .string().max(255).trim() validation to the username field in POST /api/users handler in src/routes/users.ts")
- Must request complete updated file contents, not diffs
- Must be comprehensive enough that a developer could paste it and get production-ready fixes

Format exactly like this:

--- BEGIN AI FIX PROMPT ---
You are an expert [language/framework] developer and security engineer. I need you to fix confirmed security vulnerabilities AND performance bottlenecks in my application identified by a professional audit. Return complete, updated file contents for every file that requires changes.

CODEBASE:
- Language / Framework: [from report]
- Files to update: [list every file that needs changes]

SECURITY FIXES REQUIRED:
[Number every security finding:]
[N]. [SEVERITY] — [Vulnerability Name]
   File: [exact path]
   Location: [function name / line pattern]
   Issue: [precise one-sentence description quoting the problematic code pattern]
   Fix: [exact, unambiguous instruction — e.g. "Replace \`db.query('SELECT * FROM users WHERE id = ' + req.params.id)\` with \`db.query('SELECT * FROM users WHERE id = $1', [req.params.id])\`"]

PERFORMANCE FIXES REQUIRED:
[Number every performance finding:]
[N]. [Issue Name]
   File: [exact path]
   Location: [function name]
   Issue: [precise description — e.g. "N+1 query: forEach loop on line ~45 makes one DB query per user, will produce 1000 queries for 1000 users"]
   Fix: [exact instruction — e.g. "Collect all user IDs into an array before the loop, then replace loop with single \`findMany({ where: { id: { in: ids } } })\` call, then map results back to users in memory"]

CODING STANDARDS TO APPLY:
- [Every specific standard derived from the detected stack — validation library, ORM usage pattern, error handling convention, logging format, secret management approach, etc.]

OUTPUT FORMAT:
Return the complete updated content of every changed file. Do not use diffs or patches. Do not omit unchanged sections. Add brief inline comments (// SECURITY FIX: or // PERF FIX:) at every changed line so reviewers can audit the changes.
--- END AI FIX PROMPT ---]
</analysis>

ABSOLUTE RULES:
- Output ONLY the <analysis>…</analysis> block. Zero words outside it.
- Every vulnerability finding MUST include the problematic code, a concrete attack scenario, and a complete working remediation.
- Every performance finding MUST include both the current problematic code and a complete optimised replacement.
- Part 5 (AI Fix Prompt) is MANDATORY and must be detailed enough to produce real, working fixes.
- Numeric scores required in both scorecards — no placeholders.
- Quote actual code from the submission in findings — do not paraphrase.`;
      }

      // ── Call the AI ────────────────────────────────────────────────────────
      let aiResponse;
      try {
        aiResponse = await callAI(env.MBZUAI_API_KEY, systemPrompt, trimmedHistory, query);
      } catch (fetchErr) {
        return new Response(
          JSON.stringify({ status: "ERROR", message: `Failed to reach AI API: ${fetchErr.message ?? String(fetchErr)}` }),
          { status: 502, headers: corsHeaders }
        );
      }

      if (!aiResponse.ok) {
        const errBody = await aiResponse.text().catch(() => "(unreadable)");
        return new Response(
          JSON.stringify({ status: "ERROR", message: `AI API returned HTTP ${aiResponse.status}. Details: ${errBody.slice(0, 400)}` }),
          { status: 502, headers: corsHeaders }
        );
      }

      let aiData;
      try {
        aiData = await aiResponse.json();
      } catch (_) {
        return new Response(
          JSON.stringify({ status: "ERROR", message: "AI API returned non-JSON response." }),
          { status: 502, headers: corsHeaders }
        );
      }

      const rawMessage = aiData.choices?.[0]?.message?.content ?? "";
      if (!rawMessage) {
        return new Response(
          JSON.stringify({ status: "ERROR", message: "AI returned an empty response. The codebase may be too large — try reducing the number of files." }),
          { status: 200, headers: corsHeaders }
        );
      }

      const aiMessage = stripReasoning(rawMessage);

      if (!aiMessage) {
        return new Response(
          JSON.stringify({ status: "ERROR", message: "Could not extract a usable response from the model output." }),
          { status: 200, headers: corsHeaders }
        );
      }

      // ── Extract structured output by focus ────────────────────────────────
      if (resolvedFocus === "security") {
        const content = extractTag(aiMessage, "security_analysis");
        if (content !== null) {
          return new Response(
            JSON.stringify({ status: "SECURITY_ANALYSIS", focus: "security", content }),
            { status: 200, headers: corsHeaders }
          );
        }
      }

      if (resolvedFocus === "scalability") {
        const content = extractTag(aiMessage, "scalability_analysis");
        if (content !== null) {
          return new Response(
            JSON.stringify({ status: "SCALABILITY_ANALYSIS", focus: "scalability", content }),
            { status: 200, headers: corsHeaders }
          );
        }
      }

      // "both" or fallback — try combined tag first, then individual tags
      const bothContent = extractTag(aiMessage, "analysis");
      if (bothContent !== null) {
        return new Response(
          JSON.stringify({ status: "ANALYSIS", focus: resolvedFocus, content: bothContent }),
          { status: 200, headers: corsHeaders }
        );
      }

      // Graceful degradation: one of the individual tags survived
      const secContent = extractTag(aiMessage, "security_analysis");
      if (secContent !== null) {
        return new Response(
          JSON.stringify({ status: "SECURITY_ANALYSIS", focus: "security", content: secContent }),
          { status: 200, headers: corsHeaders }
        );
      }

      const scaleContent = extractTag(aiMessage, "scalability_analysis");
      if (scaleContent !== null) {
        return new Response(
          JSON.stringify({ status: "SCALABILITY_ANALYSIS", focus: "scalability", content: scaleContent }),
          { status: 200, headers: corsHeaders }
        );
      }

      // ── Plain-text fallback ────────────────────────────────────────────────
      return new Response(
        JSON.stringify({ status: "COMPLETED", focus: resolvedFocus, solution: aiMessage }),
        { status: 200, headers: corsHeaders }
      );

    } catch (err) {
      return new Response(
        JSON.stringify({ status: "ERROR", message: `Worker exception: ${err.message ?? String(err)}` }),
        { status: 500, headers: corsHeaders }
      );
    }
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// GitHub helpers
// ─────────────────────────────────────────────────────────────────────────────

const SOURCE_FILE_RE = /\.(js|jsx|ts|tsx|mjs|cjs|py|go|rs|java|kt|swift|rb|php|cs|cpp|cc|c|h|hpp|scala|sh|sql|yaml|yml|json|toml|ini|md)$/i;
const EXCLUDE_PATH_RE = /(^|\/)(?:node_modules|dist|\.git|\.next|build|out|coverage|__pycache__)(?:\/|$)/;
const MAX_FILE_BYTES = 40000; // skip files larger than ~40 KB to stay inside context

function parseGitHubRepoUrl(input) {
  const cleaned = input
    .replace(/^https?:\/\/github\.com\//i, "")
    .replace(/\.git$/i, "")
    .replace(/^\/+|\/+$/g, "");
  const parts = cleaned.split("/").filter(Boolean);
  if (parts.length < 2) return null;
  return { owner: parts[0], repo: parts[1] };
}

function shouldInclude(path) {
  if (EXCLUDE_PATH_RE.test(path)) return false;
  return SOURCE_FILE_RE.test(path);
}

async function ghFetch(url, token) {
  const headers = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "Stremini-Worker/1.0",
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(url, { headers });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    let msg = `GitHub API ${res.status}`;
    try { const j = JSON.parse(body); if (j.message) msg += `: ${j.message}`; } catch (_) {}
    throw new Error(msg);
  }
  return res.json();
}

async function walkTree(owner, repo, branch, token) {
  // Try the fast recursive tree endpoint first
  try {
    const data = await ghFetch(
      `https://api.github.com/repos/${owner}/${repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`,
      token
    );
    const files = (data.tree || [])
      .filter(i => i.type === "blob" && shouldInclude(i.path) && (i.size || 0) <= MAX_FILE_BYTES)
      .map(i => i.path);
    if (files.length > 0 || !data.truncated) return files;
  } catch (_) {
    // fall through to directory walk
  }
  // Fallback: walk directory by directory
  return walkDir(owner, repo, "", token);
}

async function walkDir(owner, repo, dir, token) {
  const safeDir = dir ? `/${dir.split("/").map(encodeURIComponent).join("/")}` : "";
  const entries = await ghFetch(
    `https://api.github.com/repos/${owner}/${repo}/contents${safeDir}`,
    token
  );
  const arr = Array.isArray(entries) ? entries : [entries];
  const out = [];
  for (const entry of arr) {
    if (entry.type === "dir" && !EXCLUDE_PATH_RE.test(entry.path + "/")) {
      out.push(...await walkDir(owner, repo, entry.path, token));
    } else if (entry.type === "file" && shouldInclude(entry.path) && (entry.size || 0) <= MAX_FILE_BYTES) {
      out.push(entry.path);
    }
  }
  return out;
}

function decodeBase64Content(data) {
  if (!data || !data.content) return "";
  const normalized = String(data.content).replace(/\n/g, "");
  if ((data.encoding || "base64").toLowerCase() !== "base64") return String(data.content);
  // Cloudflare Workers support atob
  try {
    const bin = atob(normalized);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  } catch (_) {
    return "";
  }
}

/**
 * Fetch all relevant source files from a GitHub repo and assemble them
 * into the === FILE: path === format the AI system prompt expects.
 * Total output is capped at MAX_QUERY_CHARS to fit the context window.
 */
async function fetchRepoFileDump(owner, repo, token) {
  // 1. Get default branch
  const repoMeta = await ghFetch(`https://api.github.com/repos/${owner}/${repo}`, token);
  const branch = repoMeta.default_branch || "HEAD";

  // 2. List files
  let files = await walkTree(owner, repo, branch, token);
  files.sort((a, b) => a.localeCompare(b));

  // 3. Fetch file contents, accumulate until we hit the char budget
  const CHAR_BUDGET = 26000; // leave room for the system prompt overhead
  let totalChars = 0;
  const parts = [`Repository: ${owner}/${repo} (branch: ${branch})\n`];

  for (const path of files) {
    if (totalChars >= CHAR_BUDGET) break;
    try {
      const safePath = path.split("/").map(encodeURIComponent).join("/");
      const data = await ghFetch(
        `https://api.github.com/repos/${owner}/${repo}/contents/${safePath}`,
        token
      );
      const text = decodeBase64Content(data);
      if (!text) continue;
      const chunk = `\n=== FILE: ${path} ===\n${text}\n`;
      if (totalChars + chunk.length > CHAR_BUDGET) {
        // Include a partial note and stop
        parts.push(`\n=== FILE: ${path} ===\n[truncated — context budget reached]\n`);
        break;
      }
      parts.push(chunk);
      totalChars += chunk.length;
    } catch (_) {
      // Skip files that fail to fetch
    }
  }

  return parts.join("");
}

// ─────────────────────────────────────────────────────────────────────────────
// AI + text helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Extract content between <tagName>…</tagName>.
 * Finds the LAST occurrence of the opening tag so any reasoning preamble
 * that accidentally contains the same tag does not interfere.
 * If the closing tag is missing (truncated response), returns everything
 * after the opening tag so partial output is still usable.
 */
function extractTag(text, tagName) {
  const open  = `<${tagName}>`;
  const close = `</${tagName}>`;

  const startIdx = text.lastIndexOf(open);
  if (startIdx === -1) return null;

  const contentStart = startIdx + open.length;
  const endIdx = text.indexOf(close, contentStart);

  const raw = endIdx === -1
    ? text.slice(contentStart)
    : text.slice(contentStart, endIdx);

  const trimmed = raw.trim();
  return trimmed.length > 0 ? trimmed : null;
}

/**
 * Remove <think>…</think> reasoning blocks produced by chain-of-thought
 * models. Also handles models that emit reasoning before the final answer
 * without proper closing tags.
 */
function stripReasoning(raw) {
  let out = raw.replace(/<think>[\s\S]*?<\/think>/gi, "");

  if (out.includes("</think>")) {
    out = out.split("</think>").pop();
  }

  // Start from the last structural tag so reasoning preamble is skipped
  const structuralTags = [
    "<analysis>",
    "<security_analysis>",
    "<scalability_analysis>",
  ];
  let latestIdx = -1;
  for (const tag of structuralTags) {
    const idx = out.lastIndexOf(tag);
    if (idx > latestIdx) latestIdx = idx;
  }
  if (latestIdx !== -1) return out.slice(latestIdx).trim();

  return out.trim();
}

/**
 * Call the MBZUAI K2-Think model with automatic fallback to the alternate
 * model ID if the primary returns a non-2xx status.
 *
 * max_tokens: 16384 — required for the long structured reports.
 * temperature: 0.8  — keep analysis deterministic and factual.
 */
async function callAI(apiKey, systemPrompt, history, userQuery) {
  const url = "https://api.k2think.ai/v1/chat/completions";
  const headers = {
    "Authorization": `Bearer ${apiKey.trim()}`,
    "Content-Type": "application/json",
  };

  const buildBody = (model) => JSON.stringify({
    model,
    messages: [
      { role: "system", content: systemPrompt },
      ...history,
      { role: "user", content: userQuery },
    ],
    temperature: 0.8,
    max_tokens: 16384,
    stream: false,
  });

  let res = await fetch(url, { method: "POST", headers, body: buildBody("MBZUAI/K2-Think-v2") });
  if (!res.ok) {
    res = await fetch(url, { method: "POST", headers, body: buildBody("MBZUAI-IFM/K2-Think-v2") });
  }
  return res;
}
