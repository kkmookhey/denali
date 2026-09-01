import { deploymentEnv, routes } from "@vercel/config/v1";

const modalOrigin = deploymentEnv("MODAL_API_ORIGIN");

export const config = {
  framework: "vite",
  installCommand: "npm ci",
  buildCommand: "npm run build",
  outputDirectory: "dist",
  rewrites: [
    routes.rewrite("/api/:path*", `${modalOrigin}/:path*`),
    routes.rewrite("/:path*", "/index.html"),
  ],
  headers: [
    {
      source: "/api/:path*",
      headers: [{ key: "Cache-Control", value: "private, no-store" }],
    },
  ],
};
