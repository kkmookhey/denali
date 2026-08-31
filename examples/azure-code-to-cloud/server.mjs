import http from "node:http";

const port = Number(process.env.PORT || 8080);
const endpoint = process.env.AZURE_OPENAI_ENDPOINT;
const deployment = process.env.AZURE_OPENAI_DEPLOYMENT_ID || "gpt-4o-mini";

function send(response, status, body) {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(body));
}

async function managedIdentityToken() {
  const identityEndpoint = process.env.IDENTITY_ENDPOINT;
  const identityHeader = process.env.IDENTITY_HEADER;
  if (!identityEndpoint || !identityHeader) {
    throw new Error("Azure managed identity endpoint is unavailable");
  }
  const url = new URL(identityEndpoint);
  url.searchParams.set("resource", "https://cognitiveservices.azure.com");
  url.searchParams.set("api-version", "2019-08-01");
  const response = await fetch(url, {
    headers: { "X-IDENTITY-HEADER": identityHeader },
    signal: AbortSignal.timeout(5_000),
  });
  if (!response.ok) throw new Error(`managed identity token failed: ${response.status}`);
  return (await response.json()).access_token;
}

async function generate(prompt) {
  if (!endpoint) throw new Error("AZURE_OPENAI_ENDPOINT is not configured");
  const token = await managedIdentityToken();
  const url = new URL(
    `/openai/deployments/${encodeURIComponent(deployment)}/chat/completions`,
    endpoint,
  );
  url.searchParams.set("api-version", "2024-10-21");
  const response = await fetch(url, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      messages: [{ role: "user", content: prompt }],
      max_tokens: 128,
      temperature: 0.2,
    }),
    signal: AbortSignal.timeout(30_000),
  });
  const body = await response.json();
  if (!response.ok) throw new Error(`Azure OpenAI request failed: ${response.status}`);
  return body;
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url || "/", `http://${request.headers.host || "localhost"}`);
  if (request.method === "GET" && url.pathname === "/healthz") {
    return send(response, 200, { status: "ok", provider: "azure-openai", deployment });
  }
  if (request.method === "POST" && url.pathname === "/generate") {
    const prompt = (
      url.searchParams.get("prompt")
      || "Explain code-to-cloud correlation in one sentence."
    ).slice(0, 1_000);
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
  console.log(JSON.stringify({ event: "listening", port, deployment }));
});
