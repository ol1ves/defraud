import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { noul, TypeSafeClient } from "@typesafe-ai/sdk";

const PORT = Number(process.env.PORT || 3000);
const PUBLIC_DIR = fileURLToPath(new URL("../public", import.meta.url));

if (!process.env.TYPESAFE_API_KEY) {
  console.error("Missing TYPESAFE_API_KEY. Set it in .env or the environment.");
  process.exit(1);
}

const client = new TypeSafeClient();

// Weights for the composed risk score. They sum to 1.
const WEIGHTS = {
  unusual_payment: 0.22,
  sensitive_info: 0.2,
  remote_access: 0.16,
  threat_consequence: 0.12,
  authority_claim: 0.12,
  urgency_pressure: 0.1,
  secrecy_isolation: 0.08,
};

const QUESTIONS = {
  authority_claim: noul(
    "Does the `caller` claim to represent a trusted organization such as a bank, government agency, or well-known company?",
  ),
  urgency_pressure: noul(
    "Does the `caller` pressure for immediate action, a tight deadline, or claim something bad happens without fast action?",
  ),
  threat_consequence: noul(
    "Does the `caller` threaten consequences such as arrest, account closure, legal action, or loss of money?",
  ),
  sensitive_info: noul(
    "Does the `caller` ask the `callee` for sensitive information such as passwords, verification codes, social security numbers, card numbers, or account numbers?",
  ),
  unusual_payment: noul(
    "Does the `caller` ask for payment by gift cards, cryptocurrency, wire transfer, or another unusual or hard-to-trace method?",
  ),
  remote_access: noul(
    "Does the `caller` ask the `callee` to install software or grant remote access to a device?",
  ),
  secrecy_isolation: noul(
    "Does the `caller` tell the `callee` to keep the call secret from family, friends, or their bank?",
  ),
  is_scam: noul("Is this phone call a scam or fraud attempt against the `callee`?"),
};

const SIGNAL_KEYS = Object.keys(WEIGHTS);

function composeRisk(signals) {
  let score = 0;
  for (const key of SIGNAL_KEYS) {
    score += WEIGHTS[key] * (signals[key] ?? 0);
  }
  return score;
}

async function analyze(lines) {
  const state = { lines };
  const { answers, model } = await client.systemOne({ state, questions: QUESTIONS });
  const signals = {};
  for (const key of SIGNAL_KEYS) {
    signals[key] = answers[key].noul;
  }
  return {
    model,
    riskScore: composeRisk(signals),
    verdict: answers.is_scam.noul,
    signals,
  };
}

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
};

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
}

function readBody(req, limit = 1_000_000) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => {
      data += chunk;
      if (data.length > limit) {
        reject(new Error("request body too large"));
        req.destroy();
      }
    });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

function validateLines(lines) {
  if (!Array.isArray(lines) || lines.length === 0) {
    return "Body needs a non-empty lines array.";
  }
  for (const line of lines) {
    const ok =
      line &&
      typeof line === "object" &&
      (line.speaker === "caller" || line.speaker === "callee") &&
      typeof line.text === "string" &&
      line.text.trim().length > 0;
    if (!ok) {
      return "Each line needs speaker caller or callee and non-empty text.";
    }
  }
  return null;
}

async function handleAnalyze(req, res) {
  let body;
  try {
    body = JSON.parse((await readBody(req)) || "{}");
  } catch {
    return sendJson(res, 400, { error: "Invalid JSON body." });
  }

  const problem = validateLines(body.lines);
  if (problem) {
    return sendJson(res, 400, { error: problem });
  }

  try {
    const lines = body.lines.map((l) => ({ speaker: l.speaker, text: l.text }));
    const result = await analyze(lines);
    sendJson(res, 200, result);
  } catch (err) {
    console.error("analyze failed:", err);
    const status =
      Number.isInteger(err?.status) && err.status >= 400 && err.status < 600
        ? err.status
        : 502;
    sendJson(res, status, {
      error: "Jev API error.",
      detail: err?.message || String(err),
    });
  }
}

async function serveStatic(pathname, res) {
  const rel = pathname === "/" ? "index.html" : pathname.slice(1);
  const filePath = normalize(join(PUBLIC_DIR, rel));
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403, { "Content-Type": "text/plain" });
    res.end("Forbidden");
    return;
  }
  try {
    const data = await readFile(filePath);
    res.writeHead(200, {
      "Content-Type": MIME[extname(filePath)] || "application/octet-stream",
    });
    res.end(data);
  } catch {
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("Not found");
  }
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  try {
    if (req.method === "POST" && url.pathname === "/api/analyze") {
      await handleAnalyze(req, res);
      return;
    }
    if (req.method === "GET") {
      await serveStatic(url.pathname, res);
      return;
    }
    sendJson(res, 405, { error: "Method not allowed." });
  } catch (err) {
    console.error("request failed:", err);
    sendJson(res, 500, { error: "Internal server error." });
  }
});

server.listen(PORT, () => {
  console.log(`Fraud Detector running at http://localhost:${PORT}`);
});
