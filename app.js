// TrueScan — frontend. Link engine + PDF scanner are pure logic (tested offline).
"use strict";

/* ================= Link / phishing engine (pure) ================= */
const BRANDS = [
  "google", "gmail", "youtube", "facebook", "instagram", "whatsapp", "tiktok",
  "amazon", "ebay", "paypal", "apple", "microsoft", "netflix", "binance",
  "daraz", "easypaisa", "jazzcash", "meezanbank", "hbl", "ubl", "mcb",
  "bankalfalah", "alliedbank", "nadra", "fbr", "pta", "sbp", "telegram",
  "twitter", "linkedin", "snapchat", "spotify", "aliexpress", "temu", "shein"
];
const OFFICIAL = {
  google: ["google.com", "google.com.pk"], gmail: ["gmail.com", "mail.google.com"],
  youtube: ["youtube.com"], facebook: ["facebook.com", "fb.com"],
  instagram: ["instagram.com"], whatsapp: ["whatsapp.com", "wa.me"],
  tiktok: ["tiktok.com"], amazon: ["amazon.com", "amazon.co.uk", "amazon.ae"],
  ebay: ["ebay.com"], paypal: ["paypal.com"], apple: ["apple.com", "icloud.com"],
  microsoft: ["microsoft.com", "live.com", "outlook.com"], netflix: ["netflix.com"],
  binance: ["binance.com"], daraz: ["daraz.pk", "daraz.com"],
  easypaisa: ["easypaisa.com.pk"], jazzcash: ["jazzcash.com.pk"],
  meezanbank: ["meezanbank.com"], hbl: ["hbl.com"], ubl: ["ubl.com.pk"],
  mcb: ["mcb.com.pk"], bankalfalah: ["bankalfalah.com"], alliedbank: ["abl.com"],
  nadra: ["nadra.gov.pk"], fbr: ["fbr.gov.pk"], pta: ["pta.gov.pk"],
  sbp: ["sbp.org.pk"], telegram: ["telegram.org", "t.me"],
  twitter: ["twitter.com", "x.com"], linkedin: ["linkedin.com"],
  snapchat: ["snapchat.com"], spotify: ["spotify.com"],
  aliexpress: ["aliexpress.com"], temu: ["temu.com"], shein: ["shein.com"]
};
const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "rb.gy", "cutt.ly", "shorturl.at", "tiny.cc", "is.gd", "buff.ly", "rebrand.ly", "s.id", "v.gd", "qr.ae"];
const SUSPICIOUS_TLDS = ["zip", "mov", "xyz", "top", "click", "buzz", "work", "live", "online", "site", "fun", "icu", "rest", "cfd", "sbs", "monster", "quest", "best", "shop", "store", "uno", "lat", "xyz"];

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) => [i, ...Array(n).fill(0)]);
  for (let j = 1; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) for (let j = 1; j <= n; j++)
    dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return dp[m][n];
}

function analyzeUrl(raw) {
  const findings = [];
  let score = 0;
  const add = (pts, level, text) => { score += pts; findings.push({ level, text }); };
  let url;
  try { url = new URL(raw.trim()); }
  catch { try { url = new URL("https://" + raw.trim()); } catch { return null; } }
  const host = url.hostname.toLowerCase();
  const full = url.href;
  const labels = host.split(".");
  const tld = labels[labels.length - 1];
  const registrable = labels.slice(-2).join(".");
  const sld = labels.length >= 2 ? labels[labels.length - 2] : host;

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) add(35, "bad", "The link uses a raw IP address instead of a website name — real companies never do this.");
  if (full.includes("@") && url.username) add(30, "bad", "The link contains an '@' trick — everything before it is fake decoration; the real destination is hidden after it.");
  if (host.startsWith("xn--") || /xn--/.test(host)) add(25, "bad", "Punycode domain (xn--…) — a classic trick to draw look-alike letters that mimic a real brand.");
  if (url.protocol === "http:") add(12, "mid", "Not HTTPS — the connection is not encrypted. Real login and payment pages always use HTTPS.");
  if (SHORTENERS.includes(host) || SHORTENERS.includes(registrable)) add(25, "mid", "A link shortener hides the real destination — scammers use these so you can't see where you'll land.");
  if (SUSPICIOUS_TLDS.includes(tld)) add(15, "mid", `The domain ending ".${tld}" is very cheap and heavily abused by scam sites.`);
  if (labels.length >= 4) add(12, "mid", "Many subdomains stacked together — often used to make a fake address look official.");
  if (full.length > 90) add(8, "mid", "An unusually long link — legitimate pages rarely need addresses this long.");
  if (/%[0-9a-f]{2}/i.test(url.pathname) && url.pathname.length > 25) add(8, "mid", "Encoded characters hide parts of the address — a common obfuscation trick.");
  if (/[а-яА-Я]/.test(host)) add(35, "bad", "The domain contains Cyrillic look-alike letters — it only pretends to be a Latin-letter brand name.");

  // brand impersonation (incl. number-for-letter tricks like faceb00k)
  const sldNorm = sld.replace(/0/g, "o").replace(/1/g, "l").replace(/3/g, "e").replace(/4/g, "a").replace(/5/g, "s").replace(/7/g, "t").replace(/[^a-z]/g, "");
  for (const brand of BRANDS) {
    const officials = OFFICIAL[brand] || [];
    if (officials.includes(host) || officials.includes(registrable)) {
      add(0, "good", `This is the official ${brand} domain (${registrable}) — the address itself is genuine.`);
      continue;
    }
    if (host.includes(brand)) {
      add(38, "bad", `The address contains the name "${brand}" but is NOT the official ${brand} site — this is the #1 phishing pattern.`);
    } else if (sldNorm !== sld.replace(/[^a-z]/g, "") && (sldNorm.includes(brand) || levenshtein(sldNorm, brand) <= 1)) {
      add(36, "bad", `The domain "${sld}" swaps letters for numbers to imitate "${brand}" — a deliberate look-alike trick.`);
    } else if (levenshtein(sld, brand) === 1 && sld.length >= 4) {
      add(34, "bad", `The domain "${sld}" is one letter different from "${brand}" — a deliberate look-alike (typosquatting).`);
    } else if (levenshtein(sld.replace(/[^a-z]/g, ""), brand) === 2 && sld.length >= 6 && Math.abs(sld.length - brand.length) <= 2) {
      add(18, "mid", `The domain "${sld}" is suspiciously similar to "${brand}".`);
    }
  }

  const bait = ["verify", "login", "signin", "secure", "account", "update", "confirm", "suspended", "unlock", "reward", "prize", "winner", "free", "claim", "bonus", "wallet", "kyc", "otp"];
  const pathTxt = (url.pathname + url.search).toLowerCase();
  const hits = bait.filter(w => pathTxt.includes(w));
  if (hits.length >= 2) add(14, "mid", `The link pushes account-action words (${hits.slice(0, 3).join(", ")}…) — phishing pages create urgency like this.`);

  score = Math.max(0, Math.min(100, score));
  return { url: full, host, score, findings };
}

const PRESSURE = ["urgent", "immediately", "within 24 hours", "account will be blocked", "account will be closed", "suspended", "verify now", "click now", "last chance", "you have won", "you won", "lottery", "prize", "claim now", "send money", "processing fee", "advance fee", "otp", "pin code", "password", "congratulations"];

function analyzeMessage(text) {
  const findings = [];
  let score = 0;
  const m = text.match(/https?:\/\/[^\s<>"')]+|www\.[^\s<>"')]+|[a-z0-9-]+\.[a-z]{2,}(?:\/[^\s<>"')]*)?/i);
  let urlRes = null;
  if (m) {
    urlRes = analyzeUrl(m[0]);
    if (urlRes) { score = urlRes.score; findings.push(...urlRes.findings); }
  }
  const low = text.toLowerCase();
  const hits = PRESSURE.filter(p => low.includes(p));
  if (hits.length) {
    const pts = Math.min(30, hits.length * 9);
    score += pts;
    findings.push({ level: hits.length >= 3 ? "bad" : "mid", text: `Pressure / bait language found: "${hits.slice(0, 4).join('", "')}" — real banks and companies never threaten or rush you like this.` });
  }
  if (/\b(ask|send|share|enter).{0,20}\b(otp|pin|password|cvv)\b/i.test(text) || /\b(otp|pin|password|cvv)\b.{0,20}\b(send|share|tell|enter)\b/i.test(text)) {
    score += 30;
    findings.push({ level: "bad", text: "It asks for an OTP / PIN / password — NO real bank or wallet ever asks for these. This alone marks it as a scam." });
  }
  if (!m) findings.push({ level: "mid", text: "No link found in the message — the verdict is based on its wording alone." });
  score = Math.max(0, Math.min(100, score));
  return { score, findings, urlRes };
}

function riskVerdict(score) {
  if (score >= 55) return { tone: "danger", label: "🚨 High risk — likely a scam", score };
  if (score >= 25) return { tone: "warn", label: "⚠️ Suspicious — be careful", score };
  return { tone: "safe", label: "✅ Looks safe", score };
}

/* ================= PDF scanner (pure) ================= */
const PDF_CHECKS = [
  { re: /\/JavaScript/g, pts: 30, level: "bad", text: "Contains JavaScript — PDFs almost never need scripts; malware PDFs use them to attack your reader." },
  { re: /\/JS\s*[(/]/g, pts: 25, level: "bad", text: "Has an embedded script action (/JS) — a classic malicious-PDF technique." },
  { re: /\/Launch/g, pts: 30, level: "bad", text: "Contains a /Launch action — it can run programs on your computer when opened." },
  { re: /\/EmbeddedFile/g, pts: 22, level: "bad", text: "Has embedded files hidden inside — a common way to smuggle malware past email filters." },
  { re: /\/OpenAction/g, pts: 12, level: "mid", text: "Has an /OpenAction — something runs automatically the moment the file opens." },
  { re: /\/AA\s*<</g, pts: 12, level: "mid", text: "Has automatic actions (/AA) that trigger without you clicking anything." },
  { re: /\/XFA/g, pts: 10, level: "mid", text: "Uses XFA forms — an old, often-abused PDF technology." },
  { re: /\/RichMedia/g, pts: 10, level: "mid", text: "Contains rich-media (Flash-era) content — outdated and risky." },
  { re: /\/ObjStm/g, pts: 4, level: "mid", text: "Uses compressed object streams — normal in modern PDFs, but also used to hide code from scanners." }
];
function scanPdfText(text) {
  const findings = [];
  let score = 0;
  for (const c of PDF_CHECKS) {
    const n = (text.match(c.re) || []).length;
    if (n > 0) { score += c.pts; findings.push({ level: c.level, text: `${c.text} (found ${n}×)` }); }
  }
  const urls = [...new Set([...text.matchAll(/https?:\/\/[^\s<>"')\]]+/g)].map(m => m[0]))].slice(0, 12);
  const badUrls = [];
  for (const u of urls) {
    const r = analyzeUrl(u);
    if (r && r.score >= 25) { badUrls.push(u); score += 15; }
  }
  if (badUrls.length) findings.push({ level: "bad", text: `Contains links our phishing engine flags: ${badUrls.slice(0, 3).join(" , ")}` });
  else if (urls.length) findings.push({ level: "good", text: `${urls.length} web link(s) inside, none flagged by the phishing engine.` });
  if (!findings.length) findings.push({ level: "good", text: "No scripts, auto-run actions, embedded files or bad links found in the file structure." });
  score = Math.max(0, Math.min(100, score));
  return { score, findings, urlCount: urls.length };
}

// === UI below ===
const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
const loadingEl = $("#loading"), loadingText = $("#loadingText");
function showLoading(t) { loadingText.textContent = t || "TrueScan is analysing…"; loadingEl.classList.remove("hidden"); }
function hideLoading() { loadingEl.classList.add("hidden"); }
function esc(s) { return String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }

function renderVerdict(el, v) {
  el.innerHTML = `<div class="verdict-card ${v.tone}">
    <div class="verdict-top"><span class="verdict-label">${esc(v.label)}</span>${v.score != null ? `<span class="verdict-score">Risk score: ${v.score}/100</span>` : ""}</div>
    ${v.why ? `<p class="verdict-why">${esc(v.why)}</p>` : ""}
    ${v.extra || ""}
    ${v.findings && v.findings.length ? `<ul class="findings">${v.findings.map(f => `<li class="${f.level}">${f.level === "bad" ? "🔴" : f.level === "mid" ? "🟡" : "🟢"} ${esc(f.text)}</li>`).join("")}</ul>` : ""}
  </div>`;
}
function renderError(el, msg) { el.innerHTML = `<div class="error">${esc(msg)}</div>`; }

/* Tabs */
$$(".tool-tab").forEach(tab => tab.addEventListener("click", () => {
  $$(".tool-tab").forEach(t => t.classList.toggle("active", t === tab));
  $$(".tool-pane").forEach(p => p.classList.toggle("hidden", p.id !== "pane-" + tab.dataset.tool));
}));

/* Drop zones: drag highlight */
$$(".drop").forEach(d => {
  ["dragover", "dragenter"].forEach(e => d.addEventListener(e, ev => { ev.preventDefault(); d.classList.add("drag"); }));
  ["dragleave", "drop"].forEach(e => d.addEventListener(e, ev => { ev.preventDefault(); d.classList.remove("drag"); }));
  d.addEventListener("drop", ev => {
    const input = d.querySelector("input[type=file]");
    const f = ev.dataTransfer.files && ev.dataTransfer.files[0];
    if (f && input) { const dt = new DataTransfer(); dt.items.add(f); input.files = dt.files; input.dispatchEvent(new Event("change")); }
  });
});

function fileMeta(f) { return `${f.name} · ${(f.size / 1024).toFixed(0)} KB · ${f.type || "unknown type"}`; }
function readAsDataURL(f) { return new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(r.result); r.onerror = rej; r.readAsDataURL(f); }); }
function readAsText(f) { return new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(r.result); r.onerror = rej; r.readAsText(f, "latin1"); }); }

async function apiAnalyze(payload) {
  const res = await fetch("/api/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "The analysis service is busy. Try again in a moment.");
  return data;
}
function mediaVerdict(data) {
  if (data.verdict === "ai") return { tone: "danger", label: "🚨 Likely AI-generated / fake", score: data.confidence, why: data.summary, findings: (data.signs || []).map(s => ({ level: "bad", text: s })) };
  if (data.verdict === "real") return { tone: "safe", label: "✅ Likely real", score: 100 - (data.confidence || 50), why: data.summary, findings: (data.signs || []).map(s => ({ level: "good", text: s })) };
  return { tone: "warn", label: "⚠️ Uncertain — inspect carefully", score: data.confidence, why: data.summary, findings: (data.signs || []).map(s => ({ level: "mid", text: s })) };
}

/* ---------- Image ---------- */
let imageData = null;
$("#imageFile").addEventListener("change", async (e) => {
  const f = e.target.files[0]; if (!f) return;
  imageData = await readAsDataURL(f);
  const img = new Image();
  img.onload = () => {
    $("#imagePreview").innerHTML = `<img src="${imageData}" alt="Your image"><div class="meta">${esc(fileMeta(f))} · ${img.naturalWidth}×${img.naturalHeight}px</div>`;
    $("#imagePreview").classList.remove("hidden");
    $("#imageCheckBtn").classList.remove("hidden");
    $("#imageResult").innerHTML = "";
  };
  img.src = imageData;
});
$("#imageCheckBtn").addEventListener("click", async () => {
  if (!imageData) return;
  const btn = $("#imageCheckBtn"); btn.disabled = true; showLoading("TrueScan AI is examining the image…");
  try {
    const data = await apiAnalyze({ kind: "image", mime: imageData.split(";")[0].split(":")[1] || "image/jpeg", data: imageData.split(",")[1] });
    renderVerdict($("#imageResult"), mediaVerdict(data));
  } catch (err) { renderError($("#imageResult"), err.message); }
  finally { hideLoading(); btn.disabled = false; }
});

/* ---------- Video ---------- */
let videoFrames = null;
$("#videoFile").addEventListener("change", async (e) => {
  const f = e.target.files[0]; if (!f) return;
  const url = URL.createObjectURL(f);
  $("#videoPreview").innerHTML = `<video src="${url}" controls muted></video><div class="meta">${esc(fileMeta(f))} — extracting frames…</div>`;
  $("#videoPreview").classList.remove("hidden");
  $("#videoResult").innerHTML = ""; videoFrames = null;
  $("#videoCheckBtn").classList.add("hidden");
  try {
    videoFrames = await extractFrames(url);
    if (videoFrames && videoFrames.length) {
      $("#videoPreview").insertAdjacentHTML("beforeend", `<div class="frames">${videoFrames.map(fr => `<img src="data:image/jpeg;base64,${fr}" alt="Video frame">`).join("")}</div>`);
      $("#videoPreview .meta").textContent = `${fileMeta(f)} — ${videoFrames.length} frames ready`;
      $("#videoCheckBtn").classList.remove("hidden");
    } else renderError($("#videoResult"), "Could not read frames from this video. Try a short MP4 clip.");
  } catch { renderError($("#videoResult"), "Could not read this video file in your browser."); }
});
function extractFrames(url) {
  return new Promise((resolve) => {
    const v = document.createElement("video");
    v.muted = true; v.playsInline = true; v.src = url; v.crossOrigin = "anonymous";
    const frames = [];
    v.addEventListener("loadedmetadata", async () => {
      const dur = v.duration || 0;
      if (!dur || !isFinite(dur)) return resolve(null);
      const canvas = document.createElement("canvas");
      const scale = Math.min(1, 640 / (v.videoWidth || 640));
      canvas.width = Math.round((v.videoWidth || 640) * scale);
      canvas.height = Math.round((v.videoHeight || 360) * scale);
      const ctx = canvas.getContext("2d");
      for (const t of [0.15, 0.4, 0.65, 0.9]) {
        await new Promise(r => { v.addEventListener("seeked", r, { once: true }); v.currentTime = Math.max(0.05, dur * t); setTimeout(r, 2500); });
        try { ctx.drawImage(v, 0, 0, canvas.width, canvas.height); frames.push(canvas.toDataURL("image/jpeg", 0.72).split(",")[1]); } catch { /* tainted */ }
      }
      resolve(frames.length ? frames : null);
    });
    v.addEventListener("error", () => resolve(null));
    setTimeout(() => resolve(frames.length ? frames : null), 20000);
  });
}
$("#videoCheckBtn").addEventListener("click", async () => {
  if (!videoFrames) return;
  const btn = $("#videoCheckBtn"); btn.disabled = true; showLoading("TrueScan AI is examining the video frames…");
  try {
    const data = await apiAnalyze({ kind: "video", frames: videoFrames });
    renderVerdict($("#videoResult"), mediaVerdict(data));
  } catch (err) { renderError($("#videoResult"), err.message); }
  finally { hideLoading(); btn.disabled = false; }
});

/* ---------- Link & message ---------- */
$("#linkCheckBtn").addEventListener("click", () => {
  const val = $("#linkInput").value.trim();
  const el = $("#linkResult");
  if (!val) return renderError(el, "Paste a link or a message first.");
  const isPlainUrl = /^https?:\/\/\S+$/.test(val) || /^[\w-]+(\.[\w-]+)+(\/\S*)?$/.test(val);
  if (isPlainUrl) {
    const r = analyzeUrl(val);
    if (!r) return renderError(el, "That doesn't look like a valid link.");
    const v = riskVerdict(r.score);
    v.why = r.score >= 55 ? `Do NOT open or trust ${r.host}. Share this warning with whoever sent it to you.` : r.score >= 25 ? `Be careful with ${r.host} — it shows phishing signs. Never enter passwords or OTPs there.` : `The address ${r.host} shows no phishing signs. Stay alert anyway: check the page itself before entering any details.`;
    v.findings = r.findings;
    renderVerdict(el, v);
  } else {
    const r = analyzeMessage(val);
    const v = riskVerdict(r.score);
    v.why = r.score >= 55 ? "This message has the classic marks of a scam. Do not click its links, do not reply, and never share an OTP or PIN." : r.score >= 25 ? "This message shows scam-like pressure tactics. Verify through the company's official app or number before doing anything." : "No strong scam signs in this message's wording or links. If it asks for money or codes, treat it as a scam regardless.";
    v.findings = r.findings;
    renderVerdict(el, v);
  }
});

/* ---------- QR ---------- */
$("#qrFile").addEventListener("change", async (e) => {
  const f = e.target.files[0]; if (!f) return;
  const el = $("#qrResult"); el.innerHTML = "";
  const dataUrl = await readAsDataURL(f);
  $("#qrPreview").innerHTML = `<img src="${dataUrl}" alt="QR image"><div class="meta">${esc(fileMeta(f))}</div>`;
  $("#qrPreview").classList.remove("hidden");
  const img = new Image();
  img.onload = () => {
    const canvas = document.createElement("canvas");
    canvas.width = img.naturalWidth; canvas.height = img.naturalHeight;
    const ctx = canvas.getContext("2d");
    ctx.drawImage(img, 0, 0);
    let code = null;
    try { const px = ctx.getImageData(0, 0, canvas.width, canvas.height); code = window.jsQR ? jsQR(px.data, px.width, px.height) : null; } catch { /* ignore */ }
    if (!code || !code.data) return renderError(el, "No QR code could be read from this image. Try a clearer, closer photo of the QR.");
    const content = code.data;
    const extra = `<div class="decoded"><span class="k">What's inside this QR</span>${esc(content)}</div>`;
    if (/^https?:\/\//i.test(content) || /^[\w-]+(\.[\w-]+)+/.test(content)) {
      const r = analyzeUrl(content);
      if (r) { const v = riskVerdict(r.score); v.why = r.score >= 25 ? "This QR leads somewhere suspicious — do NOT scan it with your banking or wallet app." : "The address inside this QR shows no phishing signs. Still check the name shown by your payment app before paying."; v.findings = r.findings; v.extra = extra; return renderVerdict(el, v); }
    }
    if (/^(WIFI|BEGIN:VCARD|SMSTO|tel:|mailto:)/i.test(content)) {
      return renderVerdict(el, { tone: "warn", label: "ℹ️ Not a web link", score: null, why: "This QR holds contact / Wi-Fi / message data rather than a website. Only accept it from people you trust.", findings: [], extra });
    }
    renderVerdict(el, { tone: "warn", label: "ℹ️ Plain text inside", score: null, why: "This QR just contains text — no link to check. Read it above and judge it like any message.", findings: [], extra });
  };
  img.src = dataUrl;
});

/* ---------- PDF ---------- */
$("#pdfFile").addEventListener("change", async (e) => {
  const f = e.target.files[0]; if (!f) return;
  const el = $("#pdfResult"); showLoading("Scanning the PDF on your device…");
  try {
    const text = await readAsText(f);
    if (!text.startsWith("%PDF")) { hideLoading(); return renderError(el, "This file doesn't start with a PDF header — it may be a different file renamed to .pdf. Treat it as dangerous."); }
    const r = scanPdfText(text);
    const v = riskVerdict(r.score);
    v.why = r.score >= 55 ? "Do NOT open this PDF on an important device. It carries active attack features." : r.score >= 25 ? "This PDF has features worth a second thought. Open it only in an up-to-date reader, never enable its content prompts." : "This PDF's structure looks clean — no scripts, auto-run actions or bad links found.";
    v.findings = r.findings;
    v.extra = `<div class="decoded"><span class="k">File</span>${esc(fileMeta(f))} · ${r.urlCount} link(s) inside</div>`;
    renderVerdict(el, v);
  } catch { renderError(el, "Could not read this PDF file."); }
  finally { hideLoading(); }
});

/* ---------- Repo ---------- */
$("#repoCheckBtn").addEventListener("click", async () => {
  const val = $("#repoInput").value.trim();
  const el = $("#repoResult");
  if (!val) return renderError(el, "Paste a GitHub repo link first — e.g. https://github.com/owner/repository");
  const btn = $("#repoCheckBtn"); btn.disabled = true; showLoading("TrueScan is inspecting the repo's files and scripts…");
  try {
    const res = await fetch("/api/repo", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ repo: val }) });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || "The repo test failed. Try again in a moment.");
    const v = riskVerdict(data.score);
    v.why = data.score >= 55 ? `Do NOT download or run anything from ${data.meta.fullName}. It carries planted-malware signs.` : data.score >= 25 ? `${data.meta.fullName} shows things worth checking below before you run anything from it.` : `${data.meta.fullName} shows no planted-malware signs in its files, scripts or releases.`;
    v.findings = data.findings;
    v.extra = `<div class="decoded"><span class="k">Repository</span>${esc(data.meta.fullName)} · ⭐ ${data.meta.stars} · created ${esc(data.meta.created)} · ${data.meta.fileCount} files scanned</div>`;
    renderVerdict(el, v);
  } catch (err) { renderError(el, err.message); }
  finally { hideLoading(); btn.disabled = false; }
});

/* Splash */
window.addEventListener("load", () => {
  const splash = $("#splash");
  if (!splash) return;
  setTimeout(() => { splash.classList.add("hide"); setTimeout(() => splash.remove(), 500); }, 900);
});
