# Skill: Midnight Butterfly Scenario

## Category
scenarios

## Attack Type
Credential Access (CALDERA-Only)

## MITRE ATT&CK Tactics
- TA0006: Credential Access
- TA0002: Execution
- TA0003: Persistence

## High-Level Guidance

This scenario is CALDERA-only (no synthetic logs):

1. Run one execution ability to stage a credential access tool.
2. Execute a single credential dumping or token theft ability.
3. Validate access with a follow-on ability (e.g., list users or access a protected resource).
4. Optional: add a persistence ability to retain access, but keep it to one action.
