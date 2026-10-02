Your proxy sees the traffic that goes through it.

What happens when an agent's traffic doesn't?

Most AI-agent monitoring watches web requests passing a checkpoint. That works, as long as the agent uses the checkpoint.

A compromised dependency or a manipulated agent doesn't have to. It can open a direct connection, and your proxy never sees it. Not flagged. Not logged. Nothing.

So I added a second way of watching: the agent's machine itself, not just the checkpoint. Strictly scoped to the machines your agents run on. Not a network scanner.

For a regulated firm, a single blind spot is a single place a serious incident goes unrecorded.

This is Part 6 of a 10-part series on building it.
Next week: Part 7, Visibility Without a Blank Check.

Does your current monitoring see anything that isn't an API call?

![Diagram: The Blind Spot Every AI-Agent Firewall Has](../images/06-the-blind-spot-every-agent-firewall-has-1.png)

First comment: Read the full article → https://anandnarayanan.net/blog/agent-sentinel-06-the-blind-spot-every-agent-firewall-has/
Code and tests: https://github.com/anandnarayanan2017/agent-sentinel-series

#AIAgents #AgentSecurity #NetworkSecurity #CISO
