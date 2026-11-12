# kiskadee

Rules learned from review, each caught in two separate reviews before it became a rule.

- Apply every authz or validation check on every path that reaches the effect (a target named or not, mint or call), and test the path without the input.
- When a change touches a behavior an Edge Cases row covers, update that row's test, or the row itself, in the same change.
