# tripwire

A deterministic firewall for AI agent tool calls.

Agents read untrusted content — emails, web pages, files. Attackers put
instructions in that content, and models can't reliably tell data from
instructions. You can't stop a model from being fooled, but you can make
sure a fooled model can't do damage.

Tripwire sits between your agent and its MCP tool servers and enforces
policy on every call: argument constraints, budgets, taint tracking,
human approval gates, and a tamper-evident audit log. Enforcement lives
outside the model, where no prompt can rewrite it.

Work in progress — first release later this month.
