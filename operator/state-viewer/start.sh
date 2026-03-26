#!/usr/bin/env bash
# Start the state dashboard web server with default settings.
#
# Usage:
#   bash operator/state-viewer/start.sh
#
# For custom options, run the server directly:
#   python3 operator/state-viewer/server.py --port 9000 --db /path/to/state.db

exec python3 "$(dirname "$0")/server.py" "$@"
