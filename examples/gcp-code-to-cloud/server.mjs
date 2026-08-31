import http from "node:http";

const port = Number(process.env.PORT || 8080);
const project = process.env.GOOGLE_CLOUD_PROJECT;
const location = process.env.VERTEX_LOCATION || "us-central1";
const model = process.env.VERTEX_MODEL_ID || "gemini-2.0-flash-001";

function send(response, status, body) {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(body));
}

async function metadataAccessToken() {
  const response = await fetch(
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    { headers: { "Metadata-Flavor": "Google" }, signal: AbortSignal.timeout(5_000) },
  );
  if (!response.ok) throw new Error(`metadata token request failed: ${response.status}`);
  return (await response.json()).access_token;
}

async function generate(prompt) {
  if (!project) throw new Error("GOOGLE_CLOUD_PROJECT is not configured");
  const token = await metadataAccessToken();
  const endpoint = [
    `https://${location}-aiplatform.googleapis.com/v1/projects`,
    encodeURIComponent(project),
    "locations",
    encodeURIComponent(location),
    "publishers/google/models",
    `${encodeURIComponent(model)}:generateContent`,
  ].join("/");
  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      contents: [{ role: "user", parts: [{ text: prompt }] }],
      generationConfig: { maxOutputTokens: 128, temperature: 0.2 },
    }),
    signal: AbortSignal.timeout(30_000),
  });
  const body = await response.json();
  if (!response.ok) throw new Error(`Vertex AI request failed: ${response.status}`);
  return body;
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url || "/", `http://${request.headers.host || "localhost"}`);
  if (request.method === "GET" && url.pathname === "/healthz") {
    return send(response, 200, { status: "ok", provider: "vertex-ai", model });
  }
  if (request.method === "POST" && url.pathname === "/generate") {
    const prompt = (url.searchParams.get("prompt") || "Explain code-to-cloud correlation in one sentence.").slice(0, 1_000);
    try {
      return send(response, 200, await generate(prompt));
    } catch (error) {
      console.error(error);
      return send(response, 502, { error: "generation_failed" });
    }
  }
  return send(response, 404, { error: "not_found" });
});

server.listen(port, "0.0.0.0", () => {
  console.log(JSON.stringify({ event: "listening", port, model }));
});
