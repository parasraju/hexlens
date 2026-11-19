# You Just Got Handed a Mystery Binary. Now What?

Draft only. Do not publish.

`invoice.exe` is in your downloads folder. You did not build it, and you have no source. That file is the mystery binary. These five commands are binary triage.

1. `npx hexlens analyze ~/Downloads/invoice.exe`. Read format, architecture, compiler, imphash, and the first risk flags.
2. `npx hexlens scan ~/Downloads/ --all`. Read the triage table (`PACKED`, `UNSIGNED`, `INJECT`, `KEYLOG`, `ANTI-DBG`, `PERSIST`). Start with the highest-risk rows.
3. `npx hexlens scan ~/Downloads/ --yara rules.yar`. Match your YARA rules.
4. `npx hexlens diff known-good.exe ~/Downloads/invoice.exe`. Compare the mystery binary against a known-good build.
5. `npx hexlens mcp`. Hand the binary to your AI agent to triage with the same three tools.
