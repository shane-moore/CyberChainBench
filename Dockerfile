FROM node:20-bookworm-slim AS base

ENV DEBIAN_FRONTEND=noninteractive

# ── System packages ──────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash curl git ca-certificates \
        procps xz-utils \
        python3 python3-minimal python3-pip python3-venv \
        build-essential \
        ripgrep jq \
    && rm -rf /var/lib/apt/lists/*

# ── Foundry (forge / anvil / cast) ──────────────────────────────────────────
RUN curl -L https://foundry.paradigm.xyz | bash \
    && /root/.foundry/bin/foundryup
ENV PATH="/root/.foundry/bin:${PATH}"

# ── Claude Code & Codex CLI & Gemini CLI ────────────────────────────────────
ARG CLAUDE_CODE_VERSION=2.1.146
ARG CODEX_VERSION=0.133.0
ARG GEMINI_CLI_VERSION=0.43.0
RUN npm install -g \
        @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION} \
        @openai/codex@${CODEX_VERSION} \
        opencode-ai \
        @google/gemini-cli@${GEMINI_CLI_VERSION}

# ── Python dependencies ─────────────────────────────────────────────────────
RUN python3 -m pip install --break-system-packages --no-cache-dir \
        "anthropic>=0.42.0" \
        "openai>=1.50.0" \
        "pydantic>=2.0" \
        "rich>=13.0" \
        "click>=8.0" \
        "mcp[cli]>=1.0.0" \
        "web3>=6.0.0b8" \
        "eth-utils>=5.3.1" \
        "eth-abi>=5.0.0" \
        "py-solc-x>=1.1.1" \
        "requests>=2.32.3" \
        "jsonschema>=4.0" \
        "pytest>=8.0" \
        "pytest-asyncio>=0.23" \
        "black>=25.0" \
        "ruff>=0.11.0"

# ── Pre-install common solc versions ────────────────────────────────────────
ENV W3BB_PREINSTALLED_SOLC_VERSIONS="0.4.26 0.5.17 0.6.12 0.7.6 0.8.10 0.8.17 0.8.20"
RUN python3 -c "\
import os, solcx; \
[solcx.install_solc(v, show_progress=False) for v in os.environ['W3BB_PREINSTALLED_SOLC_VERSIONS'].split()]"

# ── Copy project ────────────────────────────────────────────────────────────
COPY . /app
WORKDIR /app

# Ensure forge-std lib is materialized (git submodules not preserved by COPY).
# The DeFiHackLabs source tree is dataset-dependent and may be absent in a clean
# clone (data/sources/ is gitignored); skip gracefully when it is not present.
RUN if [ -d /app/data/sources/DeFiHackLabs ]; then \
        if [ ! -f /app/data/sources/DeFiHackLabs/lib/forge-std/src/Test.sol ]; then \
            cd /app/data/sources/DeFiHackLabs && \
            forge install --no-git foundry-rs/forge-std || true; \
        fi; \
    else \
        echo "[build] data/sources/DeFiHackLabs not present — skipping forge-std bootstrap"; \
    fi

ENV PYTHONPATH="/app/src"

# MCP server launcher scripts (one per task type)
# Source /app/workspace/.env.runtime if it exists (env vars injected by eval harness)
RUN for task in detect exploit patch; do \
        printf '#!/bin/bash\nif [ -f /app/workspace/.env.runtime ]; then set -a; source /app/workspace/.env.runtime; set +a; fi\ncd /app && PYTHONPATH=/app/src exec python3 -m web3mcp.server --workspace /app/workspace --repo-root /app --task %s\n' "$task" \
            > /usr/local/bin/mcp-$task && chmod +x /usr/local/bin/mcp-$task; \
    done

# Remove wget/pip. Keep curl for MCP tools (RPC calls).
RUN rm -f /usr/bin/wget /usr/local/bin/wget \
    && rm -f /usr/bin/pip /usr/bin/pip3 /usr/local/bin/pip /usr/local/bin/pip3

# ── Network whitelist (proxy-based, blocks non-whitelisted domains) ──────────
COPY scripts/whitelist_proxy.py /usr/local/bin/whitelist_proxy.py
RUN chmod +x /usr/local/bin/whitelist_proxy.py

# Proxy env vars — all HTTP libraries (requests, urllib, node fetch) will use this
COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh \
    && apt-get update && apt-get install -y --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/*

# Node.js proxy support (global-agent intercepts all HTTP/HTTPS from Node)
RUN npm install -g global-agent
ENV GLOBAL_AGENT_HTTP_PROXY="http://127.0.0.1:18080" \
    GLOBAL_AGENT_HTTPS_PROXY="http://127.0.0.1:18080" \
    GLOBAL_AGENT_NO_PROXY="localhost,127.0.0.1,api.example.com,api.anthropic.com,api.openai.com" \
    NODE_OPTIONS="--require /usr/local/lib/node_modules/global-agent/dist/routines/bootstrap.js"

# Proxy env vars — Python/curl and other HTTP libraries use these
ENV HTTP_PROXY="http://127.0.0.1:18080" \
    HTTPS_PROXY="http://127.0.0.1:18080" \
    http_proxy="http://127.0.0.1:18080" \
    https_proxy="http://127.0.0.1:18080" \
    NO_PROXY="localhost,127.0.0.1,api.example.com,api.anthropic.com,api.openai.com"

# ── Non-root user (files created in container match host user) ─────────────
ARG UID=1004
ARG GID=1005
RUN groupadd -g ${GID} agent 2>/dev/null || true \
    && useradd -m -u ${UID} -g ${GID} -s /bin/bash agent \
    && cp -r /root/.foundry /home/agent/.foundry \
    && cp -r /root/.solcx /home/agent/.solcx 2>/dev/null || true \
    && mkdir -p /home/agent/.local/bin \
    && ln -sf /usr/local/bin/claude /home/agent/.local/bin/claude \
    && ln -sf /usr/local/bin/codex /home/agent/.local/bin/codex \
    && ln -sf /usr/local/bin/gemini /home/agent/.local/bin/gemini \
    && ln -sf /usr/local/bin/opencode /home/agent/.local/bin/opencode \
    && chown -R agent:agent /home/agent \
    && chown -R agent:agent /app \
    && mkdir -p /app/workspace && chmod 777 /app/workspace \
    && mkdir -p /logs/agent /logs/verifier /logs/artifacts \
    && chown -R agent:agent /logs \
    && mkdir -p /workspace && chmod 777 /workspace \
    && mkdir -p /tests /solution && chown agent:agent /tests /solution
ENV PATH="/home/agent/.foundry/bin:${PATH}"
USER agent

# ── Pre-install Hermes agent CLI ────────────────────────────────────────────
RUN HTTP_PROXY="" HTTPS_PROXY="" http_proxy="" https_proxy="" NO_PROXY="*" \
    curl -fsSL https://raw.githubusercontent.com/NousResearch/hermes-agent/main/scripts/install.sh | \
    HTTP_PROXY="" HTTPS_PROXY="" http_proxy="" https_proxy="" NO_PROXY="*" \
    bash -s -- --skip-setup \
    && mkdir -p /tmp/hermes/sessions /tmp/hermes/skills /tmp/hermes/memories
ENV PATH="/home/agent/.local/bin:${PATH}"

WORKDIR /app/workspace

ENTRYPOINT []
CMD ["sleep", "infinity"]
