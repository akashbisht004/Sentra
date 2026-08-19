import { randomBytes,createHash } from "crypto";

export function generateRefreshToken(): string {
    return randomBytes(32).toString("hex");
}

export function hashRefreshToken(token: string): string{
    return createHash("sha256").update(token).digest("hex");
}