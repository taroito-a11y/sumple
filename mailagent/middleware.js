export const config = {
  matcher: "/(.*)",
};

function unauthorized() {
  return new Response("Authentication required.", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="Protected Area", charset="UTF-8"',
      "Cache-Control": "no-store",
    },
  });
}

export default function middleware(request) {
  const username = (process.env.BASIC_AUTH_USER || "").trim();
  const password = (process.env.BASIC_AUTH_PASSWORD || "").trim();

  if (!username || !password) {
    return new Response(
      "Basic auth is not configured. Set BASIC_AUTH_USER and BASIC_AUTH_PASSWORD.",
      { status: 500, headers: { "Cache-Control": "no-store" } },
    );
  }

  const authorization = request.headers.get("authorization");
  if (!authorization || !authorization.startsWith("Basic ")) {
    return unauthorized();
  }

  let decoded = "";
  try {
    decoded = atob(authorization.slice(6));
  } catch {
    return unauthorized();
  }
  const separatorIndex = decoded.indexOf(":");
  if (separatorIndex < 0) {
    return unauthorized();
  }

  const inputUser = decoded.slice(0, separatorIndex).trim();
  const inputPassword = decoded.slice(separatorIndex + 1).trim();
  if (inputUser !== username || inputPassword !== password) {
    return unauthorized();
  }

  return fetch(request);
}
