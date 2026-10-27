# themob: pitch for the MINJEC AI contest (Youth Connekt 2026)

An AI security assistant for mobile developers, built on themob's analysis
engine. A working draft to pitch from. The security engine already runs; the AI
assistant layer and the two integrations under it (an MCP tool server, and
deeper reverse engineering) are in development. The contest accepts projects
currently in development, so this is positioned honestly as one.

Note on language: this document is in English to work from. The three form
answers are supplied in French (the form's language). I can translate the whole
document to French for the submission and the presentation.

## One line

themob lets a Cameroonian developer check a mobile app for security problems in
minutes, understand each problem in plain language, and fix it, so the app can
reach the market without waiting for an expensive external audit.

## Why now

Cameroonian developers are shipping mobile apps faster than ever, and a large
part of that speed comes from AI coding tools that write code for them. Speed is
the point, but AI-written code ships the same security mistakes again and again:
API keys left in the code, data stored unprotected, traffic sent unencrypted.
The developer rarely sees them. The market does: users lose data, and app stores
and serious clients turn away apps that cannot show a minimum of security.

## The problem

Mobile security testing today is slow, expensive, and needs an expertise most
young developers do not have and cannot pay for. So the test either does not
happen or happens too late. Vulnerable apps reach the market, and the developers
who built them lose store access and client trust they could have kept.

## The solution

themob closes that gap with two parts working together:

1. A security engine (already built) that takes an Android app, runs it through
   isolated containers, decompiles the code, and finds exposed secrets,
   configuration flaws, vulnerable dependencies, and network entry points. Every
   result is keyed to the OWASP MASVS standard and recorded in a verifiable audit
   trail.
2. An AI assistant (in development) that reads those results, explains each one
   in plain language the developer understands, and coaches them step by step to
   fix it. This is the AI at the core: it turns a raw security report into a
   teacher that a non-expert can follow.

The developer uploads an app, gets a clear list of what is wrong and why it
matters, and is walked through the fix. The tool teaches while it corrects, so
the developer gets better each time.

## The business model

License-based. A developer pays a subscription to test their apps before putting
them on the market. Room for tiers later (an individual developer, a studio or
team), but the core is simple: pay for a licence, test your apps, ship with
confidence.

## Why this is credible

Most contest entries will be an idea or an early mockup. themob's engine is a
real, working system:

- Runs end to end today as a desktop app and a command-line tool.
- Over a thousand automated tests.
- Every analysis runs in a locked-down container with no network access, so a
  hostile app cannot escape.
- Findings map to recognised standards (OWASP MASVS, the Mobile Top 10, CWE).
- A tamper-evident, hash-chained audit trail and an authorization gate on every
  run.

The full stack is documented in TECH_STACK.md. The honest status: the analysis
engine is done, the AI coaching layer is what we build next, and it rides on an
engine that already works rather than on a promise.

## Fit with the contest theme (skills, jobs, employability)

- Youth employability: the people this serves are young Cameroonian developers
  and small software businesses. It lowers the barrier for them to ship apps
  customers and stores will accept, which is what lets a small app business earn.
- Skills: the assistant does not just flag problems, it explains and teaches, so
  a developer builds a real, hireable skill (mobile security) while using it.
- Local context: it is built for the local wave of AI-assisted app-making, and it
  gives Cameroon its own security tool instead of a dependence on foreign audits.

## Impacts

- Economic: young developers and small teams get a security test at the price of
  a licence instead of a bespoke audit; they ship faster, keep store access and
  client trust, and that supports revenue and jobs.
- Social: users' data is better protected, and developers level up because the
  tool explains every flaw and teaches while it fixes, which strengthens
  employability (mobile security is a sought-after skill).
- Environmental: the analysis runs on demand, locally or on a light server, with
  no dedicated data center and no special hardware to manufacture.
- Ecosystem: a shared security baseline raises the quality of locally built apps
  and helps Cameroon build and run its own tooling.

## Build order (what the command will deliver)

1. MCP tool server: expose themob's sandboxed analyzers so an agent can drive the
   trustworthy, contained tools. Planned first because the AI assistant talks to
   the engine through it.
2. Deeper reverse engineering (REA, arms-length): reverse native and obfuscated
   code the current engine only measures the surface of, and the base for iOS
   later.
3. The AI assistant slice: the agent that explains findings and coaches fixes,
   the contest-facing product, sitting on 1 and 2.

## Honest risks

- The AI layer is the part the contest most rewards and the part not yet built;
  the plan is a narrow, working demo slice by 12 November, not the whole thing.
- "AI at the core" has to be shown, not claimed: the demo must lead with the
  assistant explaining and coaching, with the engine as the dependable tool
  underneath.
