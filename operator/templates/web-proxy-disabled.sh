#!/usr/bin/env bash
# Sourced by web agents before Bash-driven HTTP(S) commands.
# Explicitly unsets proxy env vars for direct traffic mode.
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY
export RR_WEB_PROXY_ENABLED=0
export RR_WEB_PROXY_URL=
