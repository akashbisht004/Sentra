import { AuthError } from "../errors/auth-error.js";
import { generateRefreshToken, hashRefreshToken } from "../jwt/refresh-token.js";
import { createToken, verifyToken } from "../jwt/token.js";
import type { UserAdapter, User, RefreshTokenAdapter } from "../types/adapter.js";
import type { AuthResult, LoginData, SignUpData } from "../types/auth.js";
import bcrypt from "bcrypt";
import type { RefreshSession } from "../types/session.js";
import { randomBytes } from "node:crypto";
import { durationToDate } from "../utils/duration.js";

class Auth {
    private adapter: UserAdapter;
    private secret: string;
    private expiry: string;
    private refreshTokenAdapter: RefreshTokenAdapter;
    private refreshTokenExpiry: string;

    constructor(adapter: UserAdapter, refreshTokenAdapter: RefreshTokenAdapter, secret: string, expiry: string, refreshTokenExpiry: string) {
        this.adapter = adapter;
        this.secret = secret;
        this.expiry = expiry;
        this.refreshTokenAdapter = refreshTokenAdapter;
        this.refreshTokenExpiry = refreshTokenExpiry;
    }

    async signUp(data: SignUpData): Promise<User> {
        const user = await this.adapter.findUserByEmail(data.email);

        if (user != null) {
            throw new AuthError("User already exists with same mail", "USER_ALREADY_EXISTS");
        }

        const passwordHash = await bcrypt.hash(data.password, 10);

        const newUser = await this.adapter.createUser({
            email: data.email,
            passwordHash
        });

        return {
            id: newUser.id,
            email: newUser.email
        };
    }

    async login(data: LoginData): Promise<AuthResult> {
        const user = await this.adapter.findUserByEmail(data.email);
        if (user == null) throw new AuthError("Invalid credentials", "INVALID_CREDENTIALS");

        const valid = await bcrypt.compare(data.password, user.passwordHash);

        if (!valid) throw new AuthError("Invalid credentials", "INVALID_CREDENTIALS");

        const refreshToken = generateRefreshToken();
        const refreshTokenHash = hashRefreshToken(refreshToken);
        const sessionId = randomBytes(16).toString("hex");
        const refreshSession: RefreshSession = {
            sessionId,
            userId: user.id,
            refreshTokenHash,
            expiresAt: durationToDate(this.refreshTokenExpiry),
            revokedAt: null
        };
        await this.refreshTokenAdapter.createSession(refreshSession);

        const token = await createToken(user.id, this.secret, this.expiry)

        return {
            user: {
                id: user.id,
                email: user.email,
            },
            token,
            refreshToken
        };

    }

    async authenticate(token: string): Promise<User> {
        const userId = await verifyToken(token, this.secret);
        const user = await this.adapter.findUserById(userId);
        if (user == null) throw new AuthError("Authorization failed", "AUTHENTICATION_FAILED");

        return {
            id: user.id,
            email: user.email
        };
    }

    async refresh(refreshToken: string): Promise<AuthResult> {

        const refreshTokenHash = hashRefreshToken(refreshToken);
        const session = await this.refreshTokenAdapter.findSessionByTokenHash(refreshTokenHash);

        if (session == null) {
            throw new AuthError("Invalid refresh token", "AUTHENTICATION_FAILED");
        }
        if (session.revokedAt !== null) {
            throw new AuthError("Refresh token has been revoked", "AUTHENTICATION_FAILED");
        }
        if (session.expiresAt.getTime() <= Date.now()) {
            throw new AuthError("Refresh token has been expired", "AUTHENTICATION_FAILED");
        }
        const user = await this.adapter.findUserById(session.userId);
        if (user == null) {
            throw new AuthError("User no longer exists", "AUTHENTICATION_FAILED");
        }
        const newRefreshToken = generateRefreshToken();

        const newRefreshTokenHash = hashRefreshToken(newRefreshToken);

        const newSessionId = randomBytes(16).toString("hex");

        const newSession: RefreshSession = {
            sessionId: newSessionId,
            userId: user.id,
            refreshTokenHash: newRefreshTokenHash,
            expiresAt: durationToDate(this.refreshTokenExpiry),
            revokedAt: null
        };

        await this.refreshTokenAdapter.revokeSession(session.sessionId);

        await this.refreshTokenAdapter.createSession(newSession);

        const token = await createToken(
            user.id,
            this.secret,
            this.expiry
        );

        return {
            user: {
                id: user.id,
                email: user.email
            },
            token,
            refreshToken: newRefreshToken
        };
    }

}
export { Auth };

