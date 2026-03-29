import { NextRequest, NextResponse } from "next/server";

const AUTH_PASSWORD = process.env.SYSLOG_AUTH_PASSWORD || "";
const COOKIE_NAME = "syslog-auth";

export function middleware(request: NextRequest) {
  if (!AUTH_PASSWORD) return NextResponse.next();

  const { pathname } = request.nextUrl;

  // Allow login page and auth API
  if (pathname === "/login" || pathname.startsWith("/api/auth")) {
    return NextResponse.next();
  }

  // Allow static assets
  if (pathname.startsWith("/_next") || pathname === "/favicon.ico") {
    return NextResponse.next();
  }

  const cookie = request.cookies.get(COOKIE_NAME);
  if (cookie?.value === hashPassword(AUTH_PASSWORD)) {
    return NextResponse.next();
  }

  // Redirect to login for pages, 401 for API
  if (pathname.startsWith("/api/")) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const loginUrl = new URL("/login", request.url);
  return NextResponse.redirect(loginUrl);
}

function hashPassword(password: string): string {
  // Simple hash for cookie comparison — not for storage
  let hash = 0;
  for (let i = 0; i < password.length; i++) {
    const char = password.charCodeAt(i);
    hash = ((hash << 5) - hash + char) | 0;
  }
  return hash.toString(36);
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
