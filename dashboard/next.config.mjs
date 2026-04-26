/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",

  // Proxy all /api/* calls from the browser to the AgentGuard backend.
  // In Docker: BACKEND_URL = http://agentguard:8000  (internal network name)
  // In dev:    BACKEND_URL = http://localhost:8000
  // The browser never talks to the backend directly → no CORS issues.
  async rewrites() {
    const backend = process.env.BACKEND_URL ?? "http://localhost:8000";
    return [
      { source: "/api/:path*", destination: `${backend}/:path*` },
    ];
  },
};

export default nextConfig;
