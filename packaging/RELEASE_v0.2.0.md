Two big axes since v0.1.4 (70 commits).

### Accuracy — measured on labelled ground truth, 8 languages

Every gain came from a defect the numbers exposed, not test-fitting. Score = recall − false-positive rate (the official OWASP metric; random = 0.000).

| | before | now |
|---|---:|---:|
| Java  | 0.80 | **0.83** |
| Go    | 0.15 | **0.66** |
| C++   | 0.10 | **0.80** |
| C     | 0.19 | **0.52** |

Behind it: derived-value guards, receiver accumulation, closures/channels, ternary constant-set, and a measured storage-source policy. Honest caveats (especially why C/C++ precision reaches 100% on small corpora) are in [`bench/README.md`](https://github.com/KimJeju/cpguard/blob/main/bench/README.md).

### MCP server — an AI agent can dynamically validate the findings

`pip install "cpguard[mcp]"`. An agent (Claude Code, Cursor) drives CPGuard over MCP: scan, pull the source→sink evidence, explain a rule, and **prove a finding at runtime**. CPGuard knows the sink, so it emits a probe + an oracle (what to observe that proves the sink fired); the agent fires it with its own tools, and CPGuard judges CONFIRMED / LIKELY / NOT_REPRODUCED / FALSE_POSITIVE.

Oracle-match, not IAST — no instrumentation, so it reports "the predicted signal appeared", not "I observed the real execution path". The core opens no socket. 9 tools; design and boundaries in [`docs/mcp-server-design.md`](https://github.com/KimJeju/cpguard/blob/main/docs/mcp-server-design.md).

Windows installer attached below. From source: `pip install .` (add `[mcp]` for the MCP server).
