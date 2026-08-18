import { SignJWT, jwtVerify } from "jose";
import { AuthError } from "../errors/auth-error.js";

export async function createToken(userId: string, secret: string, tokenExpiry: string): Promise<string> {

    const key = new TextEncoder().encode(secret);

    const jwt = new SignJWT({ sub: userId });
    jwt.setExpirationTime(tokenExpiry);
    jwt.setIssuedAt();
    jwt.setProtectedHeader({ alg: "HS256" });

    const token = await jwt.sign(key);

    return token;
}

export async function verifyToken(token: string, secret: string): Promise<string> {

    const key = new TextEncoder().encode(secret);
    let payload;

    try {
        payload = (await jwtVerify(token, key)).payload;
    } catch (error) {
        throw new AuthError("Invalid token", "AUTHENTICATION_FAILED");
    }

    const sub = payload.sub;
    if (typeof sub !== "string") {
        throw new AuthError("Invalid token", "AUTHENTICATION_FAILED");
    }

    return sub;

}   