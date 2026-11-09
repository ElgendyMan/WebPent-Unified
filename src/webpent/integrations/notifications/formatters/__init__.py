# src/webpent/integrations/notifications/formatters/__init__.py
"""Pure per-platform notification formatters (PROPOSALS_ULTIMATE_V3 §4).

Each formatter is a pure function Finding -> platform-native payload
dict (Slack attachments, Discord embeds, Telegram HTML text). None of
them touch the network, read the environment, or log anything —
payloads are testable as data, and dispatch owns every send.
"""
