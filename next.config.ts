import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactCompiler: true,
  serverExternalPackages: ["better-sqlite3"],
  experimental: {
    // Allow self-signed certs for UniFi controller API
    serverActions: {
      bodySizeLimit: "2mb",
    },
  },
};

export default nextConfig;
