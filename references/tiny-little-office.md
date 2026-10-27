# Tiny Little Office — upstream reference

- Project: https://github.com/aboard-io/tinylittleoffice
- Pinned for this research: `399d21771dbfbe06e383992f03f523b24a999ad2` (2026-10-22)
- Website: https://tinylittleoffice.com
- Licence: MIT, "Copyright (c) 2026 Paul Ford"
- API: https://tinylittleoffice.com/api.js
- Format documentation: https://tinylittleoffice.com/llms.txt

Tiny Little Office stores document state in the URL fragment and loads its application code separately. QR-WASM explores the distinct possibility of encoding executable modules, dependency manifests and integrity information inside QR payloads, including progressive multi-QR loading.

**Integration approach** ([ADR-0003](../docs/adr/0003-link-tlo-not-vendor.md)): link to upstream instead of copying a moving JavaScript codebase. All citations use `path:line` at the pinned commit. If source is vendored later, pin an exact upstream commit, retain the MIT licence and notices, and document modifications.

**What was taken, as ideas only:** shortest-of-packings codec choice, an inflate cap, a cached app shell kept separate from state, and the fragment-leakage warnings. **What QR-WASM does differently:** `url43` mixed-segment links instead of byte-mode base64url, multi-symbol framing instead of a single v40 cap, and no preset dictionary. The scored comparison is in [docs/findings.md](../docs/findings.md) §3.
