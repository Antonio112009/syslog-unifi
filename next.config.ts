import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactCompiler: true,
  serverExternalPackages: ["better-sqlite3"],
  allowedDevOrigins: ["192.168.1.77"],
  experimental: {
    // Allow self-signed certs for UniFi controller API
    serverActions: {
      bodySizeLimit: "2mb",
    },
  },
};

export default nextConfig;
