# inverba (meta-package)

`pip install inverba` — installs the standalone engine (`inverba-core`) and
the trust-scored swarm layer (`inverba-swarm`) in one shot.

```bash
pip install inverba            # engine + swarm
pip install "inverba[all]"     # + browser rendering, MCP server, Ollama extraction
pip install "inverba[cloud]"   # + the managed cloud services (proprietary)
```

Then:

```bash
inverba scrape https://example.com
```

That's it. See the main repo README for everything else.
