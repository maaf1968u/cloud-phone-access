import { timingSafeEqual } from "crypto";
import type { NextFunction, Request, Response } from "express";

const REALM = "Cloud Phone Admin";
const WEBHOOK_PATH = "/api/cryptopay/webhook";

function safeEqual(actual: string, expected: string): boolean {
  const actualBuffer = Buffer.from(actual);
  const expectedBuffer = Buffer.from(expected);

  if (actualBuffer.length !== expectedBuffer.length) {
    return false;
  }

  return timingSafeEqual(actualBuffer, expectedBuffer);
}

function validateApiKey(req: Request): boolean {
  const expectedApiKey = process.env.ADMIN_API_KEY;
  if (!expectedApiKey) {
    return false;
  }

  const headerApiKey = req.get("x-admin-api-key");
  if (headerApiKey && safeEqual(headerApiKey, expectedApiKey)) {
    return true;
  }

  const authorization = req.get("authorization") || "";
  const [scheme, token] = authorization.split(" ");
  return scheme?.toLowerCase() === "bearer" && Boolean(token) && safeEqual(token, expectedApiKey);
}

function validateBasicAuth(req: Request): boolean {
  const expectedUsername = process.env.ADMIN_USERNAME;
  const expectedPassword = process.env.ADMIN_PASSWORD;
  if (!expectedUsername || !expectedPassword) {
    return false;
  }

  const authorization = req.get("authorization") || "";
  const [scheme, credentials] = authorization.split(" ");
  if (scheme?.toLowerCase() !== "basic" || !credentials) {
    return false;
  }

  const decoded = Buffer.from(credentials, "base64").toString("utf-8");
  const separatorIndex = decoded.indexOf(":");
  if (separatorIndex === -1) {
    return false;
  }

  const username = decoded.slice(0, separatorIndex);
  const password = decoded.slice(separatorIndex + 1);

  return safeEqual(username, expectedUsername) && safeEqual(password, expectedPassword);
}

function hasAdminCredentialsConfigured(): boolean {
  return Boolean(
    process.env.ADMIN_API_KEY ||
      (process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD),
  );
}

export function requireAdminAuth(req: Request, res: Response, next: NextFunction) {
  if (req.path === WEBHOOK_PATH) {
    return next();
  }

  if (!hasAdminCredentialsConfigured()) {
    return res.status(503).json({
      message: "Admin authentication is not configured",
    });
  }

  if (validateApiKey(req) || validateBasicAuth(req)) {
    return next();
  }

  res.setHeader("WWW-Authenticate", `Basic realm="${REALM}", charset="UTF-8"`);
  return res.status(401).json({ message: "Unauthorized" });
}
