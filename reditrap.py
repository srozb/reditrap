#!/usr/bin/env python3
"""Simple Redis honeypot that captures attempts to exploit CVE-2025-49844.

The honeypot speaks a tiny subset of the RESP protocol, records Lua script
execution attempts, and responds with safe error messages instead of running
untrusted code. Events are written as JSON lines to the configured log file so
that suspected exploitation attempts can be analysed later.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple

RESP_MAX_BULK = 8 * 1024 * 1024  # 8 MiB cap to avoid unbounded memory use
RESP_MAX_ARRAY_LENGTH = 128

_logger = logging.getLogger("reditrap")


REDIS_INFO_PAYLOAD_TEMPLATE = """# Server
redis_version:{redis_version}
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:e7873c849a0397f9
redis_mode:standalone
os:Linux 4.15.0-34-generic x86_64
arch_bits:64
multiplexing_api:epoll
gcc_version:4.7.2
process_id:1
run_id:badba07e346c19a7dba51425ef9cbdda9e16cd0f
tcp_port:6379
uptime_in_seconds:11919163
uptime_in_days:137
hz:10
lru_clock:15078568
config_file:

# Clients
connected_clients:24
client_longest_output_list:0
client_biggest_input_buf:0
blocked_clients:0

# Memory
used_memory:2709224
used_memory_human:2.58M
used_memory_rss:6471680
used_memory_peak:6141512
used_memory_peak_human:5.86M
used_memory_lua:1173504
mem_fragmentation_ratio:2.39
mem_allocator:jemalloc-3.6.0

# Persistence
loading:0
rdb_changes_since_last_save:476
rdb_bgsave_in_progress:0
rdb_last_save_time:1759893618
rdb_last_bgsave_status:err
rdb_last_bgsave_time_sec:0
rdb_current_bgsave_time_sec:-1
aof_enabled:0
aof_rewrite_in_progress:0
aof_rewrite_scheduled:0
aof_last_rewrite_time_sec:-1
aof_current_rewrite_time_sec:-1
aof_last_bgrewrite_status:ok
aof_last_write_status:ok

# Stats
total_connections_received:13496
total_commands_processed:520743
instantaneous_ops_per_sec:0
total_net_input_bytes:111855324
total_net_output_bytes:2198564329
instantaneous_input_kbps:0.00
instantaneous_output_kbps:0.00
rejected_connections:0
sync_full:0
sync_partial_ok:0
sync_partial_err:0
expired_keys:0
evicted_keys:0
keyspace_hits:753
keyspace_misses:85640
pubsub_channels:0
pubsub_patterns:0
latest_fork_usec:695

# Replication
role:master
connected_slaves:0
master_repl_offset:0
repl_backlog_active:0
repl_backlog_size:1048576
repl_backlog_first_byte_offset:0
repl_backlog_histlen:0

# CPU
used_cpu_sys:16849.86
used_cpu_user:7917.13
used_cpu_sys_children:401.81
used_cpu_user_children:1250.19

# Keyspace
db0:keys=23,expires=19,avg_ttl=84330409
"""


class RESPProtocolError(Exception):
    """Raised when incoming data is not valid RESP."""


async def _read_exactly(reader: asyncio.StreamReader, length: int) -> bytes:
    data = await reader.readexactly(length)
    return data


async def _read_line(reader: asyncio.StreamReader) -> bytes:
    line = await reader.readline()
    if not line:
        raise asyncio.IncompleteReadError(partial=b"", expected=1)
    if line.endswith(b"\r\n"):
        return line[:-2]
    if line.endswith(b"\n"):
        return line[:-1]
    raise RESPProtocolError("line missing LF terminator")


def _decode_bulk(data: bytes) -> str:
    # Redis defaults to UTF-8. Replace errors so we always get something loggable.
    return data.decode("utf-8", errors="replace")


class RESPReader:
    """Minimal RESP request parser for arrays of bulk strings."""

    def __init__(self, reader: asyncio.StreamReader):
        self._reader = reader

    async def read_request(self) -> Optional[List[str]]:
        prefix = await self._reader.read(1)
        if not prefix:
            return None

        if prefix == b"*":
            length_line = await _read_line(self._reader)
            try:
                length = int(length_line)
            except ValueError as exc:
                raise RESPProtocolError(f"invalid array length: {length_line!r}") from exc
            if length < 0:
                raise RESPProtocolError("array length cannot be negative")
            if length > RESP_MAX_ARRAY_LENGTH:
                raise RESPProtocolError("array length exceeds honeypot limit")

            items: List[str] = []
            for _ in range(length):
                items.append(await self._read_bulk_string())
            return items

        # Inline protocol fallback (very old clients). Treat the first byte as part of the line.
        line = prefix + await _read_line(self._reader)
        parts = line.strip().split()
        if not parts:
            return []
        return [part.decode("utf-8", errors="replace") for part in parts]

    async def _read_bulk_string(self) -> str:
        bulk_type = await self._reader.read(1)
        if bulk_type != b"$":
            raise RESPProtocolError(f"expected bulk string, got {bulk_type!r}")

        length_line = await _read_line(self._reader)
        try:
            length = int(length_line)
        except ValueError as exc:
            raise RESPProtocolError(f"invalid bulk length: {length_line!r}") from exc
        if length == -1:
            return ""
        if length < 0:
            raise RESPProtocolError("negative bulk string length")
        if length > RESP_MAX_BULK:
            raise RESPProtocolError("bulk string length exceeds honeypot limit")

        data = await _read_exactly(self._reader, length)
        # Bulk strings are terminated by CRLF
        tail = await _read_exactly(self._reader, 2)
        if tail != b"\r\n":
            raise RESPProtocolError("bulk string missing CRLF terminator")
        return _decode_bulk(data)


@dataclass
class HoneypotState:
    event_logger: "EventLogger"
    redis_version: str


class EventLogger:
    """Write structured honeypot events to JSON-lines log."""

    def __init__(self, path: Path):
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()

    async def write(self, event: dict) -> None:
        line = json.dumps(event, sort_keys=True)
        async with self._lock:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, self._write_sync, line)

    def _write_sync(self, line: str) -> None:
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")


def _encode_simple_string(value: str) -> bytes:
    return value.encode("utf-8") + b"\r\n"


def _resp_simple_string(value: str) -> bytes:
    return _encode_simple_string(f"+{value}")


def _resp_error(value: str) -> bytes:
    return _encode_simple_string(f"-{value}")


def _resp_bulk_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return _encode_simple_string(f"${len(encoded)}") + encoded + b"\r\n"


def _resp_integer(value: int) -> bytes:
    return _encode_simple_string(f":{value}")


SUSPICIOUS_LUA_TOKENS = (
    "debug.",
    "ffi.",
    "package.",
    "require",
    "os.execute",
    "io.popen",
    "loadstring",
    "dofile",
    "collectgarbage",
    "string.dump",
    "jit.",
)


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    state: HoneypotState,
) -> None:
    peer = writer.get_extra_info("peername")
    peer_host, peer_port = _format_peer(peer)
    connection_id = f"{peer_host}:{peer_port}"
    _logger.info("connection opened from %s", connection_id)

    resp_reader = RESPReader(reader)

    try:
        while True:
            try:
                items = await resp_reader.read_request()
            except asyncio.IncompleteReadError:
                break
            except (RESPProtocolError, asyncio.LimitOverrunError) as exc:
                await _safe_write(writer, _resp_error(f"ERR protocol error: {exc}"))
                await state.event_logger.write(
                    _build_event(
                        peer_host,
                        peer_port,
                        command=None,
                        args=None,
                        action="protocol_error",
                        info=str(exc),
                    )
                )
                break

            if items is None:
                break
            if not items:
                continue

            command = items[0]
            args = items[1:]
            response, action, info = _handle_command(command, args, state)

            await _safe_write(writer, response)
            await state.event_logger.write(
                _build_event(
                    peer_host,
                    peer_port,
                    command=command,
                    args=args,
                    action=action,
                    info=info,
                )
            )

            if command.upper() == "QUIT":
                break
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:  # pragma: no cover - best effort close
            pass
        _logger.info("connection closed from %s", connection_id)


def _format_peer(peer: Optional[Tuple[object, ...]]) -> Tuple[str, int]:
    if isinstance(peer, tuple) and len(peer) >= 2:
        host = str(peer[0])
        port = int(peer[1])
    else:
        host = "unknown"
        port = -1
    return host, port


async def _safe_write(writer: asyncio.StreamWriter, payload: bytes) -> None:
    writer.write(payload)
    try:
        await writer.drain()
    except ConnectionResetError:
        pass


def _handle_command(command: str, args: Sequence[str], state: HoneypotState) -> Tuple[bytes, str, Optional[dict]]:
    cmd_upper = command.upper()
    if cmd_upper == "PING":
        return _resp_simple_string("PONG"), "ping", None

    if cmd_upper == "ECHO" and args:
        return _resp_bulk_string(args[0]), "echo", None

    if cmd_upper == "QUIT":
        return _resp_simple_string("OK"), "quit", None

    if cmd_upper == "AUTH":
        return _resp_simple_string("OK"), "auth", None

    if cmd_upper == "INFO":
        payload = REDIS_INFO_PAYLOAD_TEMPLATE.format(redis_version=state.redis_version)
        return _resp_bulk_string(payload), "info", None

    if cmd_upper == "PUBSUB":
        if not args:
            return (
                _resp_error("ERR wrong number of arguments for 'pubsub' command"),
                "pubsub_error",
                {"arg_count": 0},
            )
        subcommand = args[0].upper()
        if subcommand == "CHANNELS":
            pattern = args[1] if len(args) >= 2 else None
            info = {"subcommand": "CHANNELS", "match_pattern": pattern, "channel_count": 0}
            return _resp_array([]), "pubsub_channels", info
        return (
            _resp_error("ERR Unknown subcommand or wrong number of arguments for 'PUBSUB'."),
            "pubsub_error",
            {"subcommand": args[0]},
        )

    if cmd_upper == "KEYS":
        if len(args) != 1:
            return (
                _resp_error("ERR wrong number of arguments for 'keys' command"),
                "keys_error",
                {"arg_count": len(args)},
            )
        return _resp_array([]), "keys", {"pattern": args[0], "key_count": 0}

    if cmd_upper == "HELLO":
        # Older Redis instances (the vulnerable ones) did not support HELLO, mimic that.
        return _resp_error("ERR unknown command 'HELLO'"), "hello", {"unsupported": True}

    if cmd_upper in {"SCRIPT", "FUNCTION"}:
        return _script_handler(cmd_upper, args)

    if cmd_upper in {"EVAL", "EVALSHA"}:
        return _eval_handler(cmd_upper, args)

    if cmd_upper == "COMMAND":
        return _resp_array([]), "command", {"description": "empty command list"}

    if cmd_upper == "CONFIG":
        return _resp_error("ERR unknown command 'CONFIG'"), "config", None

    return _resp_error(f"ERR unknown command '{command}'"), "unknown", {"command": command}


def _resp_array(values: Iterable[str]) -> bytes:
    encoded_items = []
    for value in values:
        encoded_items.append(_resp_bulk_string(value))
    header = _encode_simple_string(f"*{len(encoded_items)}")
    return header + b"".join(encoded_items)


def _build_event(
    host: str,
    port: int,
    *,
    command: Optional[str],
    args: Optional[Sequence[str]],
    action: str,
    info: Optional[dict],
) -> dict:
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "remote": {"host": host, "port": port},
        "action": action,
    }
    if command is not None:
        event["command"] = command
    if args is not None:
        event["args"] = list(args)
    if info is not None:
        event["info"] = info
    return event


def _eval_handler(cmd_upper: str, args: Sequence[str]) -> Tuple[bytes, str, dict]:
    script_body = args[0] if args else ""
    script_hash = hashlib.sha1(script_body.encode("utf-8", errors="replace")).hexdigest()

    heuristics = _lua_heuristics(script_body)
    info = {
        "script_hash": script_hash,
        "arg_count": len(args),
        "heuristics": heuristics,
    }
    if len(args) >= 2:
        info["key_count"] = args[1]

    response = _resp_error("ERR script execution disabled (honeypot)")
    action = "lua_eval"
    return response, action, info


def _script_handler(cmd_upper: str, args: Sequence[str]) -> Tuple[bytes, str, dict]:
    info: dict = {"subcommand": args[0].upper()} if args else {"subcommand": None}

    if args:
        sub = args[0].upper()
        if sub == "LOAD" and len(args) >= 2:
            script_body = args[1]
            info.update(
                {
                    "script_hash": hashlib.sha1(script_body.encode("utf-8", errors="replace")).hexdigest(),
                    "heuristics": _lua_heuristics(script_body),
                }
            )
            response = _resp_error("ERR script loading disabled (honeypot)")
            return response, "lua_script_load", info
        if sub in {"FLUSH", "KILL"}:
            return _resp_simple_string("OK"), "script_admin", info

    return _resp_error("ERR script subcommand not supported"), "script_unknown", info


def _lua_heuristics(script_body: str) -> dict:
    lowered = script_body.lower()
    matched_tokens = sorted({token for token in SUSPICIOUS_LUA_TOKENS if token in lowered})
    return {
        "length": len(script_body),
        "matched_tokens": matched_tokens,
        "preview": script_body[:120],
    }


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Redis honeypot for CVE-2025-49844 detection")
    parser.add_argument("--host", default="0.0.0.0", help="Host interface to bind (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=6379, help="TCP port to bind (default: 6379)")
    parser.add_argument(
        "--log-file",
        default="logs/redis-honeypot-events.ndjson",
        help="Path to log file for honeypot events",
    )
    parser.add_argument(
        "--redis-version",
        default="7.2.4",
        help="Redis version string to report in INFO replies",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging to stdout")
    return parser.parse_args(argv)


async def _run_server(args: argparse.Namespace) -> None:
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logger_handler_level = logging.DEBUG if args.verbose else logging.INFO
    _logger.setLevel(logger_handler_level)

    event_logger = EventLogger(Path(args.log_file))
    state = HoneypotState(event_logger=event_logger, redis_version=args.redis_version)

    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, state),
        host=args.host,
        port=args.port,
    )

    addr_descriptions = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    _logger.info("honeypot listening on %s", addr_descriptions)

    async with server:
        await server.serve_forever()


def main() -> None:
    args = parse_args()
    try:
        asyncio.run(_run_server(args))
    except KeyboardInterrupt:
        _logger.info("honeypot interrupted by user")


if __name__ == "__main__":
    main()
