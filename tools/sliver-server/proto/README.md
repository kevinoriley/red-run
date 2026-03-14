# Sliver Protobuf Files

Vendored from [BishopFox/sliver](https://github.com/BishopFox/sliver) `protobuf/` directory.

## Files

| Proto | Source | Purpose |
|-------|--------|---------|
| `commonpb/common.proto` | Common types | Request/Response wrappers, Empty |
| `sliverpb/sliver.proto` | Implant types | Execute, Upload, Download, Ls, Ps, etc. |
| `clientpb/client.proto` | Client types | Sessions, Beacons, Jobs, ImplantConfig |
| `rpcpb/services.proto` | gRPC services | SliverRPC service definition |

## Compilation

Proto files are downloaded and compiled by `scripts/update-sliver-protos.sh`.
The compiled Python stubs are output to `proto_gen/` (gitignored).

```bash
# From the repo root:
scripts/update-sliver-protos.sh
```

Do not edit these files manually. To update, re-run the script which pulls
the latest from the Sliver master branch.
