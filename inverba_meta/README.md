# inverba

`pip install inverba` installs the standalone engine (`inverba-core`): every web
fetch cryptographically signed and offline-verifiable, with nothing to trust but
a public key.

```bash
pip install inverba            # the engine
pip install "inverba[all]"     # + browser rendering, MCP server, RFC 3161 timestamping
```

Then:

```bash
inverba scrape https://example.com
inverba verify record.json
```

- Source & docs: https://github.com/Inverba-Systems/inverba
- Site: https://inverba.dev
