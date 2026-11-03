# TrueScan — AI Fake & Scam Detector

One free tool that checks six things:

- **Image** — AI-generated / deepfake photo detection (Gemini vision)
- **Video** — deepfake check from sampled frames (Gemini vision)
- **Link & Message** — phishing engine: look-alike domains, punycode, shorteners,
  IP links, brand impersonation and scam pressure language (100% on-device)
- **QR Code** — decodes a QR on-device (jsQR) and runs its contents through the
  phishing engine without opening it
- **PDF** — static scan for JavaScript, /Launch, embedded files, auto-actions
  and bad links (100% on-device)
- **Repo** — GitHub repo tester: file list, install scripts, workflows, README
  download links and release assets scanned for planted malware

## Stack
Static frontend + two Vercel functions (`api/analyze.js`, `api/repo.js`).
Only env var: `GEMINI_API_KEY` (Google AI Studio). Optional `GITHUB_TOKEN`
raises the repo-test rate limit.

Built by Asad Imran.
