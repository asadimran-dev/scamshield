// TrueScan — GitHub repo safety test. Uses the public GitHub API (no key needed;
// optional GITHUB_TOKEN env raises rate limits). Inspects file list, install
// scripts, workflows, README download links and release assets for planted malware.
const GH = "https://api.github.com";

const EXEC_EXT = ["exe", "dll", "scr", "com", "msi", "bat", "cmd", "ps1", "vbs", "vbe", "jar", "apk", "dmg", "pkg", "deb", "rpm", "run", "bin"];
const SCRIPT_EXT = ["sh", "bat", "cmd", "ps1", "py", "js", "vbs"];
const SUSPICIOUS_WORDS = ["crack", "keygen", "activator", "patcher", "free-download", "freedownload", "cheat", "hacktool", "hack-tool", "robux", "vbucks", "aimbot", "modmenu", "bypass", "nulled", "premium-free"];
const CODE_PATTERNS = [
  { re: /(curl|wget)\s[^\n]{0,120}(\|\s*(sudo\s+)?(sh|bash|zsh)|\.exe|\.ps1|\.bat)/i, pts: 34, text: "downloads and runs a program from the internet (curl/wget pipe) — the classic malware install move" },
  { re: /powershell[^\n]{0,80}(-enc|encodedcommand|frombase64string)/i, pts: 34, text: "runs hidden/encoded PowerShell — used to execute malware invisibly" },
  { re: /(certutil\s+-urlcache|bitsadmin\s+\/transfer)/i, pts: 30, text: "uses Windows certutil/bitsadmin to secretly download files" },
  { re: /base64\s+(-d|--decode)|FromBase64String/i, pts: 20, text: "decodes Base64 content — a common way to hide malicious code in plain sight" },
  { re: /https?:\/\/\d{1,3}(\.\d{1,3}){3}[^\s"')]{0,80}/g, pts: 22, text: "contacts a raw IP address instead of a named server — typical of botnet/malware servers" },
  { re: /(discord\.com\/api\/webhooks|api\.telegram\.org\/bot)/i, pts: 30, text: "sends data to a Discord/Telegram bot — the standard channel for stolen passwords and tokens" },
  { re: /(pastebin\.com\/raw|hastebin|ghostbin|anonfiles|transfer\.sh)/i, pts: 16, text: "pulls code from a paste/file-drop site — real projects host their own code" },
  { re: /(eval\s*\(|exec\s*\(\s*(base64|__import__)|os\.system\s*\(\s*["']\s*(curl|wget|powershell))/i, pts: 24, text: "executes dynamically-obtained code (eval/exec) — behaviour of droppers, not normal installers" },
  { re: /(AppData|Startup|currentversion\\\\run|schtasks\s+\/create|crontab)/i, pts: 18, text: "touches startup/persistence locations — tries to survive reboots like malware does" }
];

function ghHeaders() {
  const h = { "Accept": "application/vnd.github+json", "User-Agent": "TrueScan-RepoTester" };
  if (process.env.GITHUB_TOKEN) h.Authorization = "Bearer " + process.env.GITHUB_TOKEN;
  return h;
}
async function ghJson(path) {
  const r = await fetch(GH + path, { headers: ghHeaders() });
  if (r.status === 404) throw new Error("Repo not found — check the link, and note private repos can't be tested.");
  if (r.status === 403) throw new Error("GitHub's free rate limit is reached right now. Try again in a few minutes.");
  if (!r.ok) throw new Error("GitHub didn't answer properly. Try again in a moment.");
  return r.json();
}
async function ghText(url) {
  try { const r = await fetch(url, { headers: { "User-Agent": "TrueScan-RepoTester" } }); if (!r.ok) return ""; const t = await r.text(); return t.slice(0, 200000); } catch { return ""; }
}
function parseRepo(input) {
  const s = String(input || "").trim().replace(/\.git$/, "");
  const m = s.match(/github\.com\/([\w.-]+)\/([\w.-]+)/i) || s.match(/^([\w.-]+)\/([\w.-]+)$/);
  if (!m) return null;
  return { owner: m[1], repo: m[2] };
}

module.exports = async (req, res) => {
  if (req.method !== "POST") { res.status(405).json({ error: "Method not allowed" }); return; }
  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {});
    const pr = parseRepo(body.repo);
    if (!pr) { res.status(400).json({ error: "That doesn't look like a GitHub repo link. Use https://github.com/owner/repository" }); return; }
    const { owner, repo } = pr;

    const meta = await ghJson(`/repos/${owner}/${repo}`);
    const findings = [];
    let score = 0;
    const add = (pts, level, text) => { score += pts; findings.push({ level, text }); };

    const ageDays = Math.max(0, Math.round((Date.now() - new Date(meta.created_at).getTime()) / 86400000));
    if (ageDays < 30) add(18, "mid", `This repo is only ${ageDays} day(s) old — malware repos are usually brand-new and disappear fast.`);
    else findings.push({ level: "good", text: `Repo age: created ${String(meta.created_at).slice(0, 10)} (${ageDays} days ago).` });
    if ((meta.stargazers_count || 0) === 0 && ageDays < 90) add(6, "mid", "Zero stars and very new — nobody has vouched for this project yet.");

    const tree = await ghJson(`/repos/${owner}/${repo}/git/trees/${encodeURIComponent(meta.default_branch || "main")}?recursive=1`);
    const files = (tree.tree || []).filter(t => t.type === "blob").map(t => t.path);
    const lower = files.map(f => f.toLowerCase());

    // --- file-list checks ---
    const execs = files.filter(f => EXEC_EXT.includes(f.split(".").pop().toLowerCase()) && !f.includes("node_modules/"));
    if (execs.length) add(Math.min(30, 12 + execs.length * 6), "bad", `Executable files committed in the repo: ${execs.slice(0, 4).join(", ")}${execs.length > 4 ? "…" : ""} — real open-source projects ship source code; pre-built programs in the tree are a top malware sign.`);
    const doubleExt = files.filter(f => /\.(pdf|docx?|xlsx?|jpg|png|zip)\.(exe|scr|com|bat|cmd)$/i.test(f));
    if (doubleExt.length) add(38, "bad", `Double-extension trick file(s): ${doubleExt.slice(0, 3).join(", ")} — disguised to look like a document, actually a program. NEVER open these.`);
    const sus = files.filter(f => SUSPICIOUS_WORDS.some(w => f.toLowerCase().includes(w)));
    if (sus.length) add(20, "bad", `File names promise cracks/keygens/cheats: ${sus.slice(0, 3).join(", ")} — this category is infested with malware.`);
    const secrets = files.filter(f => /(^|\/)(\.env|credentials\.(json|txt)|id_rsa|wallet\.dat|cookies\.txt)$/i.test(f));
    if (secrets.length) add(10, "mid", `Sensitive files committed: ${secrets.slice(0, 3).join(", ")} — sloppy or planted repos often leak (or steal) credentials like this.`);
    const archives = files.filter(f => /\.(zip|rar|7z)$/i.test(f) && !f.includes("node_modules/"));
    if (archives.length && execs.length === 0) add(8, "mid", `Archive files in the repo (${archives.slice(0, 3).join(", ")}) — their contents can't be inspected here; scan them before extracting.`);

    // --- content checks on key files ---
    const toFetch = [];
    const pkg = files.find(f => f.toLowerCase() === "package.json");
    if (pkg) toFetch.push(pkg);
    for (const f of files) if (/^\.github\/workflows\/.*\.ya?ml$/i.test(f)) toFetch.push(f);
    for (const f of files) if (/^(install|setup|bootstrap|deploy)\.(sh|bat|cmd|ps1|py)$/i.test(f)) toFetch.push(f);
    const setupPy = files.find(f => f.toLowerCase() === "setup.py");
    if (setupPy) toFetch.push(setupPy);
    const readme = files.find(f => /^readme\.(md|txt|rst)$/i.test(f));

    for (const f of [...new Set(toFetch)].slice(0, 8)) {
      const content = await ghText(`https://raw.githubusercontent.com/${owner}/${repo}/${meta.default_branch || "main"}/${f}`);
      if (!content) continue;
      for (const p of CODE_PATTERNS) {
        const hits = content.match(p.re);
        if (hits) add(p.pts, "bad", `In ${f}: ${p.text}.`);
      }
      if (f === "package.json") {
        try {
          const j = JSON.parse(content);
          const scripts = Object.values(j.scripts || {}).join(" ");
          if (/(curl|wget|powershell|certutil|http:\/\/)/i.test(scripts)) add(26, "bad", "package.json install scripts (preinstall/postinstall) download or run external code — npm would execute this automatically on install.");
        } catch { /* not json */ }
      }
    }

    // README download links leaving GitHub
    if (readme) {
      const content = await ghText(`https://raw.githubusercontent.com/${owner}/${repo}/${meta.default_branch || "main"}/${readme}`);
      const links = [...content.matchAll(/https?:\/\/[^\s<>"')\]]+/g)].map(m => m[0]);
      const dl = links.filter(u => /\.(exe|msi|zip|rar|dmg|apk)([?#]|$)/i.test(u) && !/github\.com|githubusercontent\.com/i.test(u));
      if (dl.length) add(22, "bad", `The README sends you OFF GitHub to download program files (${dl[0].slice(0, 70)}…) — the classic fake-download page pattern.`);
    }

    // Releases
    try {
      const releases = await ghJson(`/repos/${owner}/${repo}/releases?per_page=5`);
      const assets = (releases || []).flatMap(r => r.assets || []);
      const exeAssets = assets.filter(a => EXEC_EXT.includes(String(a.name).split(".").pop().toLowerCase()));
      if (exeAssets.length && ageDays < 180) add(14, "mid", `Release downloads include programs (${exeAssets.slice(0, 3).map(a => a.name).join(", ")}) from a young repo — only run them if you fully trust the source.`);
      else if (exeAssets.length) findings.push({ level: "good", text: `Releases ship program files (${exeAssets.length}) — normal for an established project of this age.` });
    } catch { /* releases optional */ }

    if (!findings.some(f => f.level !== "good")) findings.push({ level: "good", text: "File list, install scripts, workflows and releases all look ordinary for an open-source project." });
    score = Math.max(0, Math.min(100, score));
    res.status(200).json({
      score, findings,
      meta: { fullName: meta.full_name, stars: meta.stargazers_count || 0, created: String(meta.created_at).slice(0, 10), fileCount: files.length }
    });
  } catch (e) {
    res.status(400).json({ error: e.message || "The repo test failed." });
  }
};
