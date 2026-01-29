import { cookies } from "next/headers";
import { NextResponse } from "next/server";

const COOKIE_NAME = "xlog_auth";

export async function GET() {
  const cookieStore = await cookies();
  const authenticated = Boolean(cookieStore.get(COOKIE_NAME)?.value);
  return NextResponse.json({ authenticated });
}
