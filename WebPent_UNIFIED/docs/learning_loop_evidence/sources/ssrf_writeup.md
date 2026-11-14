# SSRF writeup source
Source: https://portswigger.net/web-security/ssrf

Server-side request forgery allows an attacker to cause a server-side application to make requests to an unintended location. A shopping application may accept a URL parameter such as `stockApi` on `/product/stock`; changing it to `http://localhost/admin` can reach a local administrative endpoint. Metadata services, loopback addresses, redirects, and URL parsing inconsistencies are common attack-surface patterns. Use safe non-routable controls and never access real secrets.
