Start small: before blocking agent behavior, record it well enough that a CISO can trust the evidence.

A lot of security tooling builds the enforcement layer first, because blocking things feels like the real work. We deliberately did the opposite.

Phase one of Agent Sentinel didn't touch a single real model call. It ran entirely on simulated fintech traffic: a reconciliation bot going about its normal business, plus a scripted attack scenario, both feeding the same pipeline a live agent would use later.

The point wasn't to fake a demo. It was to prove the recording and policy-check logic was trustworthy before wiring it to anything that could move money or touch customer data.

Only once that held up did phase two swap the simulator for real calls to Azure OpenAI and Anthropic, through a thin wrapper around each provider's SDK. Same pipeline, same policy engine, now watching real traffic.

One deliberate choice came with it: if the recorder is ever unreachable, the agent's real work still goes through. A monitoring system that can accidentally take down production the moment it hiccups is worse than no monitoring at all.

Recording can fail open. Enforcement, later, won't get to.

That ordering holds up as a general rule for anything sitting this close to regulated systems: prove it on safe data first, then point it at real traffic, and fail toward availability while you're still just recording.

Where would you draw the line between recording everything and failing safe if recording breaks?

![Diagram for this post: simulation to real models](../images/02-simulation-to-real-models-1.png)

Full write-up, with code links: https://github.com/anandnarayanan2017/agent-sentinel-series/blob/main/docs/blog/technical-details/02-simulation-to-real-models.md
