import { randomBytes } from "crypto";

export function generateRefreshToken(): string {
    const refreshToken = randomBytes(32).toString("hex");
    return refreshToken;

}