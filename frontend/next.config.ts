import type { NextConfig } from "next";
import path from "node:path";

// The browser talks to /backend/...; Next.js forwards it to the API. This keeps the API on
// loopback or a private network and avoids opening CORS to the world.
const apiUrl = process.env.SENTINEL_API_URL ?? "http://127.0.0.1:8000";

const nextConfig: NextConfig = {
  // A self-contained server for the Docker image (copies only what the server needs).
  output: "standalone",
  turbopack: { root: path.resolve(__dirname) },
  async rewrites() {
    return [{ source: "/backend/:path*", destination: `${apiUrl}/:path*` }];
  },
};

export default nextConfig;
