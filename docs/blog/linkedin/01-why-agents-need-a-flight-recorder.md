Your payment reconciliation agent just called an LLM, invoked a ledger tool, and sent 250KB to a host nobody approved.

Could you prove what happened?

Most teams running AI agents have logs. Fewer have evidence.

A log tells you an HTTP request happened. It doesn't tell you which agent made the call, which model answered, which tool it invoked next, or whether any of that was actually allowed.

That gap is invisible right up until you need it. An auditor asks for proof. A regulator asks what your KYC assistant did last Tuesday. A security review asks what an agent can actually reach.

A generic request log answers none of that.

So we built Agent Sentinel as a flight recorder first, before anything about blocking or enforcing. Every model call, tool call, and network connection visible through a configured collector gets normalized into one record: which agent, which identity, what it tried to do, what policy said, and why.

Detect. Explain. Export. Enforcement comes later, and it's on the roadmap, not in the product today. You can't explain what you didn't record. You shouldn't enforce what you can't explain.

This is the first post in a series on how that got built, decision by decision, including the mistakes we caught before they shipped.

The image below shows where Agent Sentinel sits: alongside your agents, recording what its collectors can see.

If an auditor asked you right now what your AI agents did last week, what would you actually be able to show them?

![Diagram for this post: why agents need a flight recorder](../images/01-why-agents-need-a-flight-recorder-1.png)

Read the full article: https://anandnarayanan.net/blog/agent-sentinel-01-why-agents-need-a-flight-recorder/
