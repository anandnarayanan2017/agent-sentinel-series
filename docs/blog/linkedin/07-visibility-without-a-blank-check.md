A network monitor that watches everything is a liability, not a control.

Here's how we scoped ours to exactly the machines that matter, and nothing else.

Once you decide to add network-level visibility, the next question is the dangerous one: visibility into what, exactly? A tool that can quietly watch or probe any device on your network isn't a security feature. It's a new thing your security team has to secure.

So we built ours around three hard rules, not best-effort ones.

It only ever looks at machines you've explicitly listed. No scanning a subnet, no discover-everything-and-sort-it-out-later. You give it a list of addresses that belong to your AI agents. Anything not on that list is invisible to it, not by convention, but because the tool is built so it can't do otherwise.

It never guesses whose traffic it's looking at. Every address on the list is mapped to a real, named identity ahead of time. Traffic from a machine that isn't on the list gets dropped and logged, never quietly attributed to someone.

It's off by default, and stays off until you flip it on twice. Once for the list of machines, once to actually enable watching them. No single setting turns on live monitoring of your infrastructure.

That last point matters more than it sounds. Enabling this tool means it will actively send traffic, capturing packets, sometimes probing ports. We treat turning it on the same way we treat any other traffic-on-your-network decision: a human choice, every time.

The diagram shows what happens to an address that isn't on the list: dropped before it ever reaches a detection engine, never silently included.

Where do you draw the line between useful visibility and a tool you now have to worry about?

![Diagram for this post: visibility without a blank check](../images/07-visibility-without-a-blank-check-1.png)

Read the full article: https://anandnarayanan.net/blog/agent-sentinel-07-visibility-without-a-blank-check/
