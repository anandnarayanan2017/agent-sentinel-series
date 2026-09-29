Agent Sentinel should not be another SIEM.

It should produce the AI-agent evidence your SIEM doesn't have natively.

Every security team we'd want as a customer already has Microsoft Sentinel or Splunk, and they're good at what they do: correlating incidents, running playbooks, giving analysts one place to work. Building a competing dashboard nobody asked for would be the wrong instinct.

So Agent Sentinel's job ends where the SOC's job begins. Detect what an AI agent did. Explain why it mattered in plain language a non-technical reviewer can follow. Export clean, high-fidelity evidence into the tools your security team already trusts. Blocking before an action runs is on the roadmap, not in the product today.

Not another alert to triage. A finding that already carries the model used, the tool called, the policy clause it violated, and which regulatory control that maps to.

That last part is the actual product bet. Log ingestion, incident correlation, and SOAR playbooks are a solved problem. We're not trying to out-build Splunk at being Splunk.

What's genuinely missing from existing SOC tooling is first-class understanding of what an AI agent specifically did: which model answered, which tool executed, what data left the building, and whether any of it was allowed. That's the evidence gap this fills.

We're closing this series here, five parts covering why this exists, how it went from simulated traffic to real model calls, why rules come before statistics, and what enterprise-ready actually requires.

A second series follows, covering what came next: giving agents visibility into raw network traffic, not just their own API calls.

If you run a SOC today, what's the AI-agent evidence you most wish showed up in your existing tools instead of a separate dashboard?

![Diagram for this post: soc and whats next](../images/05-soc-and-whats-next-1.png)

Read the full article: https://anandnarayanan.net/blog/agent-sentinel-05-soc-and-whats-next/
