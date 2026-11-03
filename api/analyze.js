// ScamShield — AI media analysis via Gemini vision. Key lives only in Vercel env.
// Tries a small fallback chain; on total failure the last Gemini error is
// included in the error text so problems can be diagnosed from the UI.
const PROMPT_IMAGE = `You are a media-forensics expert. Examine this image and decide whether it is AI-generated or manipulated (deepfake / face-swap) or a genuine camera photo.
Look for: warped hands/fingers/teeth/ears, inconsistent lighting and shadows, plastic or overly smooth skin, garbled text or logos, asymmetric jewellery/glasses, unnatural hair edges, blending seams around faces, impossible reflections.
Reply with ONLY a JSON object, no markdown:
{"verdict":"ai" | "real" | "uncertain","confidence":0-100,"summary":"one or two short sentences a normal person understands","signs":["short sign 1","short sign 2"]}
"confidence" = how strongly the evidence supports your verdict. If evidence is weak or mixed, choose "uncertain".`;

const PROMPT_VIDEO = `You are a media-forensics expert. These are frames sampled from ONE video. Decide whether the video is AI-generated or a deepfake/face-swap, or genuine camera footage.
Look for: face features that morph between frames, flickering edges, warped hands/teeth, inconsistent lighting, plastic skin, garbled text, blending seams.
Reply with ONLY a JSON object, no markdown:
{"verdict":"ai" | "real" | "uncertain","confidence":0-100,"summary":"one or two short sentences a normal person understands","signs":["short sign 1","short sign 2"]}
"confidence" = how strongly the evidence supports your verdict. If evidence is weak or mixed, choose "uncertain".`;

const ATTEMPTS = [
  { model: "gemini-3.5-flash-lite", thinking: true },
  { model: "gemini-3.5-flash-lite", thinking: false },
  { model: "gemini-flash-lite-latest", thinking: false },
  { model: "gemini-2.5-flash", thinking: false }
];

async function callGemini(key, attempt, parts) {
  const gen = { temperature: 0.1, maxOutputTokens: 700 };
  if (attempt.thinking) gen.thinkingConfig = { thinkingBudget: 0 };
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 40000);
  try {
    const g = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${attempt.model}:generateContent?key=${key}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      signal: ctrl.signal,
      body: JSON.stringify({ contents: [{ parts }], generationConfig: gen })
    });
    if (!g.ok) {
      const t = (await g.text().catch(() => "")).slice(0, 220).replace(/\s+/g, " ");
      throw new Error(`${attempt.model} -> HTTP ${g.status} ${t}`);
    }
    return await g.json();
  } finally { clearTimeout(timer); }
}

module.exports = async (req, res) => {
  if (req.method !== "POST") { res.status(405).json({ error: "Method not allowed" }); return; }
  const key = process.env.GEMINI_API_KEY;
  if (!key) { res.status(500).json({ error: "The AI service is not configured yet." }); return; }
  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {});
    const parts = [];
    if (body.kind === "image") {
      if (!body.data) { res.status(400).json({ error: "No image received." }); return; }
      parts.push({ text: PROMPT_IMAGE });
      parts.push({ inline_data: { mime_type: body.mime || "image/jpeg", data: body.data } });
    } else if (body.kind === "video") {
      const frames = Array.isArray(body.frames) ? body.frames.slice(0, 5) : [];
      if (!frames.length) { res.status(400).json({ error: "No video frames received." }); return; }
      parts.push({ text: PROMPT_VIDEO });
      for (const f of frames) parts.push({ inline_data: { mime_type: "image/jpeg", data: f } });
    } else { res.status(400).json({ error: "Unknown check type." }); return; }

    let lastErr = "unknown";
    for (const attempt of ATTEMPTS) {
      try {
        const data = await callGemini(key, attempt, parts);
        const text = (data.candidates && data.candidates[0] && data.candidates[0].content && data.candidates[0].content.parts || []).map(p => p.text || "").join("");
        const m = text.match(/\{[\s\S]*\}/);
        if (!m) { lastErr = attempt.model + " -> unreadable answer"; continue; }
        const out = JSON.parse(m[0]);
        if (!["ai", "real", "uncertain"].includes(out.verdict)) out.verdict = "uncertain";
        out.confidence = Math.max(0, Math.min(100, Math.round(Number(out.confidence) || 50)));
        out.signs = Array.isArray(out.signs) ? out.signs.slice(0, 6).map(String) : [];
        out.summary = String(out.summary || "");
        res.status(200).json(out);
        return;
      } catch (e) { lastErr = String(e.message || e); }
    }
    res.status(502).json({ error: "The AI service is busy. Try again in a moment. [" + lastErr + "]" });
  } catch (e) {
    res.status(500).json({ error: "Something went wrong during analysis. Try again." });
  }
};
