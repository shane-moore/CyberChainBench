#!/usr/bin/env python3
"""Compatibility wrapper for legacy validate_fix_attack_txs / validate_patch_attack_txs entrypoints."""

from __future__ import annotations

from .validate_patch import main


if __name__ == "__main__":
    main()
