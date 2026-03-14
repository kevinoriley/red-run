"""gRPC connection manager for Sliver C2 server.

Handles mTLS authentication using Sliver operator .cfg files. Provides lazy
connection initialization — the gRPC channel is created on first use and
cached for subsequent calls. Cleans up on process exit.

Config resolution order:
  1. SLIVER_CONFIG environment variable (path to .cfg file)
  2. engagement/config.yaml → c2.sliver_config
  3. ~/.sliver-client/configs/default.cfg
"""

from __future__ import annotations

import atexit
import json
import os
from pathlib import Path
from typing import Any

import grpc

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# Module-level cached state
_channel: grpc.Channel | None = None
_stub: Any = None
_config: dict[str, Any] | None = None


def _find_config_path() -> Path:
    """Resolve Sliver operator config path.

    Checks in order:
      1. SLIVER_CONFIG env var
      2. engagement/config.yaml c2.sliver_config key
      3. ~/.sliver-client/configs/default.cfg

    Raises:
        FileNotFoundError: No config found at any location.
    """
    # 1. Environment variable
    env_path = os.environ.get("SLIVER_CONFIG")
    if env_path:
        p = Path(env_path).expanduser()
        if p.is_file():
            return p
        raise FileNotFoundError(
            f"SLIVER_CONFIG={env_path} does not exist or is not a file."
        )

    # 2. Engagement config.yaml
    engagement_config = _PROJECT_ROOT / "engagement" / "config.yaml"
    if engagement_config.is_file():
        try:
            import yaml

            with open(engagement_config) as f:
                cfg = yaml.safe_load(f)
            sliver_path = (cfg or {}).get("c2", {}).get("sliver_config")
            if sliver_path:
                p = Path(sliver_path).expanduser()
                if not p.is_absolute():
                    p = _PROJECT_ROOT / "engagement" / p
                if p.is_file():
                    return p
        except Exception:
            pass  # Fall through to default

    # 3. Default location
    default = Path.home() / ".sliver-client" / "configs" / "default.cfg"
    if default.is_file():
        return default

    raise FileNotFoundError(
        "No Sliver operator config found. Checked:\n"
        "  1. SLIVER_CONFIG env var (not set)\n"
        f"  2. {engagement_config} → c2.sliver_config (not found)\n"
        f"  3. {default} (not found)\n\n"
        "Generate an operator config with: sliver > new-operator --name <name> --lhost <ip>"
    )


def _load_config() -> dict[str, Any]:
    """Load and parse the Sliver operator .cfg file (JSON with mTLS certs)."""
    global _config
    if _config is not None:
        return _config

    config_path = _find_config_path()
    with open(config_path) as f:
        _config = json.load(f)

    # Validate required fields
    required = ["lhost", "lport", "ca_certificate", "certificate", "private_key"]
    missing = [k for k in required if k not in _config]
    if missing:
        raise ValueError(
            f"Sliver config at {config_path} missing required fields: {missing}"
        )

    return _config


def _create_channel() -> grpc.Channel:
    """Create an mTLS gRPC channel to the Sliver server."""
    cfg = _load_config()

    # Build SSL credentials from operator config
    credentials = grpc.ssl_channel_credentials(
        root_certificates=cfg["ca_certificate"].encode(),
        private_key=cfg["private_key"].encode(),
        certificate_chain=cfg["certificate"].encode(),
    )

    target = f"{cfg['lhost']}:{cfg['lport']}"

    # Channel options for large messages (implant binaries can be big)
    options = [
        ("grpc.max_receive_message_length", 256 * 1024 * 1024),  # 256 MB
        ("grpc.max_send_message_length", 256 * 1024 * 1024),
    ]

    channel = grpc.secure_channel(target, credentials, options=options)

    return channel


def get_channel() -> grpc.Channel:
    """Get or create the cached gRPC channel.

    Raises:
        RuntimeError: Connection failed with helpful error message.
    """
    global _channel
    if _channel is not None:
        return _channel

    try:
        _channel = _create_channel()
    except FileNotFoundError as e:
        raise RuntimeError(str(e)) from e
    except Exception as e:
        cfg = _config or {}
        target = f"{cfg.get('lhost', '?')}:{cfg.get('lport', '?')}"
        raise RuntimeError(
            f"Failed to connect to Sliver server at {target}: {e}\n"
            f"Ensure the Sliver server is running and the operator config is valid."
        ) from e

    return _channel


def get_stub() -> Any:
    """Get or create the cached SliverRPC gRPC stub.

    Lazy-imports proto_gen modules. Raises clear error if protos not compiled.

    Returns:
        SliverRPCStub instance connected to the Sliver server.
    """
    global _stub
    if _stub is not None:
        return _stub

    _ensure_protos()
    channel = get_channel()
    _stub = _rpc_stub_class(channel)
    return _stub


# Lazy proto imports — set by _ensure_protos()
_clientpb = None
_sliverpb = None
_commonpb = None
_rpc_stub_class = None


def _ensure_protos() -> None:
    """Lazy-import proto_gen modules. Raises clear error if not compiled."""
    global _clientpb, _sliverpb, _commonpb, _rpc_stub_class
    if _clientpb is not None:
        return

    try:
        proto_gen_dir = Path(__file__).parent / "proto_gen"
        if not proto_gen_dir.exists():
            raise ImportError(
                f"proto_gen/ directory not found at {proto_gen_dir}.\n"
                f"Run: scripts/update-sliver-protos.sh"
            )

        import sys

        parent = str(proto_gen_dir.parent)
        if parent not in sys.path:
            sys.path.insert(0, parent)

        from proto_gen.clientpb import client_pb2 as cpb
        from proto_gen.commonpb import common_pb2 as common
        from proto_gen.rpcpb import services_pb2_grpc as rpc
        from proto_gen.sliverpb import sliver_pb2 as spb

        _clientpb = cpb
        _sliverpb = spb
        _commonpb = common
        _rpc_stub_class = rpc.SliverRPCStub
    except ImportError as e:
        raise RuntimeError(
            f"Sliver protobuf stubs not compiled: {e}\n"
            f"Run: scripts/update-sliver-protos.sh"
        ) from e


def get_protos() -> tuple:
    """Return (clientpb, sliverpb, commonpb) modules after ensuring they're loaded."""
    _ensure_protos()
    return _clientpb, _sliverpb, _commonpb


def _cleanup() -> None:
    """Close the gRPC channel on exit."""
    global _channel, _stub
    if _channel is not None:
        try:
            _channel.close()
        except Exception:
            pass
        _channel = None
        _stub = None


atexit.register(_cleanup)
