# Phase 6 WAPTLab Runtime Notes

- WAPTLab source: `/home/ubuntu/WAPTLab`.
- Docker bridge networking is unavailable in this sandbox because the kernel lacks the iptables `raw` table. The lab was therefore run with host networking using temporary runtime commands; no WAPTLab source file was modified.
- Runtime containers: `webpent-waptlab-mysql` on host port 3306, `webpent-waptlab-es` on host port 9200, and `webpent-waptlab-app` on host port 8000.
- The app image was built from the existing WAPTLab source using `docker build --network host` and tagged `webpent-waptlab-app:local`.
- Runtime aliases `mysql` and `elasticsearch` were mapped to `127.0.0.1` because the application has hard-coded hostnames in cached configuration/routes.
- The original entrypoint's OAuth client seeder is not idempotent on the persisted database and exited on a duplicate client. A runtime-only wrapper ran both seeders with `|| true` and started Supervisor; no WAPTLab source was edited.
- The app is listening on `0.0.0.0:8000`.
- Allowed scanner User-Agent prefix: `solverfileexpect_2222`.
- A fresh audit registration flow was started for `webpent.smart6@example.test`; the OTP was read from that account's local Laravel session file and used through the official `/verify-otp` and `/register` routes. The first registration attempt failed before creation because the app config cache still referenced `mysql`; the runtime alias fix was applied afterward. A new registration/login check must be performed after the final runtime start.
- No vulnerability is considered confirmed by these runtime notes; only service startup and environment facts are recorded.
