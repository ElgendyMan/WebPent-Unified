# XSS writeup source
Source: https://portswigger.net/web-security/cross-site-scripting

Cross-site scripting allows an attacker to compromise a user's interaction with a vulnerable application. Reflected XSS can occur when request data is included unsafely in an immediate response, for example `/status?message=All+is+well`. Testing uses a unique marker at every input and checks the response context. Stored and DOM-based XSS use different persistence or client-side paths. Output encoding and appropriate response headers are key defenses.
