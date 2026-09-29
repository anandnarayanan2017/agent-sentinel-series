A wire-transfer tool call is legal. The same call before the identity-verification step is a breach.

No YAML allow-list can tell the difference. The rule has to understand order.

We built Agent Sentinel's first detection layer as a plain rulebook on purpose: is this model allowed, is this tool allowed, is this host allowed, is this payload too big. Boring, deterministic, and something a compliance auditor can actually read and agree with.

No black box gets to be the primary judge of whether a money-moving agent is behaving.

But a rulebook checks one event at a time. It can't see that step 3 happened before step 2, or that a session looks nothing like how that role normally behaves. That's a different kind of question, and it needed a second, separate model that only advises, never blocks.

The most interesting bug we found wasn't in the rules. It was in how we scored session suspicion.

Our first version averaged the surprise of every step in a session. It looked fine in testing, then we found it was missing a quarter to half of real attacks. A couple of genuinely alarming steps were getting diluted into an average pulled down by eight ordinary ones.

The fix wasn't a bigger model. It was scoring on the most surprising steps instead of the average. Same model, one change to the aggregation, and detection went from catching three-quarters of attacks to catching effectively all of them in testing.

We then built a second, harder test role specifically to find where this breaks, and it does: small, quiet, single-step attacks buried in a long normal session are still the hardest thing to catch. We're publishing that limit, not hiding it. Advisory-only, fused with hard rules, is the right design exactly because no anomaly model catches everything.

Where else have you seen an averaged score hide the thing that actually mattered?

![Diagram for this post: rules first statistics second](../images/03-rules-first-statistics-second-1.png)

Full write-up, with code links: https://github.com/anandnarayanan2017/agent-sentinel-series/blob/main/docs/blog/technical-details/03-rules-first-statistics-second.md
