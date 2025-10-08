# RediTrap Honeypot

RediTrap is a minimal Redis honeypot tailored to spot early attempts to exploit
CVE-2025-49844 ("RediShell"), the critical Remote Code Execution vulnerability
described by Wiz Research. The exploit abuses a 13 year old use-after-free bug in
the embedded Lua engine: Redis would store the Lua chunk name without first
anchoring it on the stack, allowing a garbage collection cycle to reclaim the
string while C code still used the pointer. The Redis patch
[`d5728cb`](https://github.com/redis/redis/commit/d5728cb5795c966c5b5b1e0f0ac576a7e69af539)
fixes the issue by pushing the chunk name onto the Lua stack (via
`setsvalue2s`/`incr_top`) before parsing and popping it afterwards, preventing
the stale pointer and closing the RCE primitive.

Because the published exploit path relies on sending malicious Lua scripts via
`EVAL`, `EVALSHA`, or `SCRIPT LOAD`, the honeypot focuses on surfacing those
interactions while pretending to be an unpatched Redis node.

## What it does

- Listens on the Redis TCP port (`6379` by default) and speaks a small RESP
  subset so basic probes succeed (`PING`, `INFO`, `AUTH`, etc.).
- Logs every command to a JSON-lines log file, with extra context for Lua script
  activity (SHA-1 digest, length, token heuristics, preview).
- Flags script-oriented commands as suspicious and returns safe error replies so
  untrusted payloads never execute.
- Mimics older Redis behaviour (for example, rejecting `HELLO`) to encourage
  attackers to continue their workflow.

## Getting started

```bash
python3 reditrap.py --host 0.0.0.0 --port 6379 --log-file logs/redis-honeypot-events.ndjson
```

Use `--verbose` for additional stdout logging during development.

## Container usage

Build a compact image (Alpine base):

```bash
docker build -t reditrap .
# or: podman build -t reditrap .
```

Run it with the Redis port exposed and the log directory mounted on the host:

```bash
mkdir -p honeypot-logs
docker run -d --name reditrap \
  -p 6379:6379 \
  -v "$(pwd)/honeypot-logs:/data" \
  reditrap
```

The container defaults to `--host 0.0.0.0 --port 6379 --log-file
/data/redis-honeypot-events.ndjson`, so logs land on the host at
`honeypot-logs/redis-honeypot-events.ndjson`.

Podman works the same way (add the SELinux flag if applicable):

```bash
podman run -d --name reditrap \
  -p 6379:6379 \
  -v "$(pwd)/honeypot-logs:/data:Z" \
  reditrap
```

Override defaults by appending arguments after the image name, for example:

```bash
docker run --rm -p 6379:6379 reditrap --redis-version 7.0.15 --log-file /data/attempts.ndjson
```

## Inspecting events

Each incoming request becomes an NDJSON entry. Suspicious Lua activity includes
heuristics to make triage easier. For example:

```json
{
  "action": "lua_eval",
  "args": ["return debug.getregistry()", "0"],
  "command": "EVAL",
  "info": {
    "arg_count": 2,
    "heuristics": {
      "length": 26,
      "matched_tokens": ["debug."],
      "preview": "return debug.getregistry()"
    },
    "key_count": "0",
    "script_hash": "763200efa15885c9fa970d45cc2b11711c739c13"
  },
  "remote": {"host": "203.0.113.42", "port": 58231},
  "timestamp": "2025-10-07T15:04:12.123456+00:00"
}
```

Pair the logs with network telemetry to trace the attacking source and decide on
response actions.

## Safety notes

- The honeypot never executes received Lua scripts; it immediately returns an
  error string after logging the attempt.
- Large bulk strings are capped at 8 MiB and arrays at 128 elements to reduce
  memory pressure from malicious clients.
- Run the honeypot inside an isolated network segment and forward Redis port
  traffic to it using firewall rules, port mirroring, or NAT as appropriate for
  your environment.
