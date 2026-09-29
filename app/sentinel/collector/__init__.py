"""Sentinel collector package.

Phase 1:  collector.parsers   — normalise raw HTTP flows to AgentEvents
          collector.proxy     — mitmproxy addon (egress HTTPS interception)

Phase 2:  collector.sdk_base       — SentinelReporter (shared base)
          collector.azure_openai   — AzureOpenAISentinel / AsyncAzureOpenAISentinel
          collector.anthropic_sdk  — AnthropicSentinel / AsyncAnthropicSentinel
"""
