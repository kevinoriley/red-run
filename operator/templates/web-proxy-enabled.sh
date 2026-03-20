#!/usr/bin/env bash
# Sourced by web agents before Bash-driven HTTP(S) commands.
# Replace PROXY_URL with the actual proxy URL (e.g., http://127.0.0.1:8080).
export RR_WEB_PROXY_ENABLED=1
export RR_WEB_PROXY_URL='PROXY_URL'
export http_proxy="$RR_WEB_PROXY_URL"
export https_proxy="$RR_WEB_PROXY_URL"
export HTTP_PROXY="$RR_WEB_PROXY_URL"
export HTTPS_PROXY="$RR_WEB_PROXY_URL"
export all_proxy="$RR_WEB_PROXY_URL"
export ALL_PROXY="$RR_WEB_PROXY_URL"
