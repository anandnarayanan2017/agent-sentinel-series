The bug that never shipped: a routine policy check, one line away from flagging every customer's AI agents as violators.

This is the story I actually wanted to tell this week. Not a feature working, a mistake that almost happened, and why it didn't.

Here's the setup. This system has a long-standing rule: if an AI agent's traffic goes to a host that isn't on its approved list, that's a real, high-severity violation. That rule compares hostnames, things like ledger.internal, not raw IP addresses.

An early version of our new network-monitoring feature would have recorded the raw IP address every time it saw traffic, and used that as the host the rule checks against. Reasonable-sounding default. Also completely wrong, because an IP address will never match a hostname on an approved list, no matter how legitimate the traffic is.

Play that forward. Every agent already running with a normal, hostname-based approval list would suddenly fail its own policy check on every single piece of network traffic this new feature captured. Not a missed detection, the opposite: a flood of false, high-severity alarms on agents doing nothing wrong.

A security tool that cries wolf on everything trains people to stop reading it, which is exactly when a real violation gets missed.

We caught this before a single line of the actual collector code was written, during design review. The fix: that host field is now only ever filled in from a real, verified hostname, or left blank. A blank value is invisible to the rule, not a mismatch. There's now a dedicated test proving zero false alarms result, for exactly this scenario.

The image shows the decision that got made, and the one that almost did.

The real lesson isn't that we don't have bugs. It's that the cheapest day to catch this kind of mistake is before it ships, not after a customer's on-call engineer is drowning in false alarms. What's your team's cheapest catch point?

![Diagram for this post: built to fail safe not fail quiet](../images/09-built-to-fail-safe-not-fail-quiet-1.png)

Full write-up, with code links: https://github.com/anandnarayanan2017/agent-sentinel-series/blob/main/docs/blog/technical-details/09-built-to-fail-safe-not-fail-quiet.md
