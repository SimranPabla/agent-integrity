# Architecture

The public engine has four independent layers:

1. `protocol` defines versioned, language-neutral JSON structures.
2. `core` performs deterministic validation, hashing, receipt creation, and
   rechecking without calling an LLM.
3. `sdk` helps an agent construct a complete envelope and releases only the
   exact response bound to a `PASS` result.
4. `cli` exposes the core through JSON stdin/stdout for other languages.

The agent is allowed to propose claims and evidence mappings. It is not allowed
to calculate its own status. The deterministic core is the decision boundary.

Human-maintained project policy uses a strict YAML subset. Run artifacts use
canonical JSON so semantically identical key ordering hashes identically.
