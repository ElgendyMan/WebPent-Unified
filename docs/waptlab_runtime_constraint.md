# WAPTLab Runtime Constraint

During the authorized local validation attempt on 2026-08-18, Docker Engine and Compose were installed and the WAPTLab repository was cloned at commit `00de7bdb25a45938eb1b3d6711bf342c7cefb7b7`.

The container build could not create Docker's default bridge endpoint because the sandbox kernel does not expose the `iptables` `raw` table. The failure was:

`iptables v1.8.10 (legacy): can't initialize iptables table raw: Table does not exist`

No WAPTLab source files were modified. A Compose override was prepared outside the repository to bind ports only to `127.0.0.1`, remove the host bind mount, remove the host-root Elasticsearch mount, and run the image's internal entrypoint. No containers were left running after the failed build.

Because the target is Docker-only and the kernel restriction blocks a faithful multi-container runtime, subsequent validation uses WAPTLab source as ground truth plus a local mock HTTP harness. Findings are labeled static, mock-validated, or live-confirmed; no mock result is claimed as a live WAPTLab exploit confirmation.
