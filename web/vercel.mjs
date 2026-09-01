const modalOrigin = process.env.MODAL_API_ORIGIN?.replace(/\/$/, "");
if (!modalOrigin) {
  throw new Error("MODAL_API_ORIGIN must be configured in the Vercel project");
}

export const config = {
  framework: "vite",
  installCommand: "npm ci",
  buildCommand: "npm run build",
  outputDirectory: "dist",
  rewrites: [
    { source: "/api/:path*", destination: `${modalOrigin}/:path*` },
    { source: "/:path*", destination: "/index.html" },
  ],
  headers: [
    {
      source: "/api/:path*",
      headers: [{ key: "Cache-Control", value: "private, no-store" }],
    },
  ],
};
