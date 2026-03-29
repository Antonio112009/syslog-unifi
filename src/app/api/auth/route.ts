import { NextRequest, NextResponse } from "next/server";

const AUTH_PASSWORD = process.env.SYSLOG_AUTH_PASSWORD || "";
const COOKIE_NAME = "syslog-auth";

function hashPassword(password: string): string {
  let hash = 0;
  for (let i = 0; i < password.length; i++) {
    const char = password.charCodeAt(i);
    hash = ((hash << 5) - hash + char) | 0;
  }
  return hash.toString(36);
}

export async function POST(request: NextRequest) {
  const body = await request.json();
  const { password } = body;

  if (!AUTH_PASSWORD || password !== AUTH_PASSWORD) {
    return NextResponse.json({ error: "Invalid password" }, { status: 401 });
  }

  const response = NextResponse.json({ ok: true });
  response.cookies.set(COOKIE_NAME, hashPassword(AUTH_PASSWORD), {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    maxAge: 60 * 60 * 24 * 7, // 7 days
  });
  return response;
}

export async function DELETE() {
  const response = NextResponse.json({ ok: true });
  response.cookies.delete(COOKIE_NAME);
  return response;
}
