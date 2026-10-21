#!/usr/bin/env bash
echo "tebamoto-platform build: environment diagnostics"
python3 ci/probe.py 2>&1 || true
