import { AuthError, createAuth } from "../src/index.js";
import { UserRecord, CreateUser } from "../src/types/adapter.js";
import { RefreshSession } from "../src/types/session.js";
import { expect, it, describe } from "vitest";
import bcrypt from "bcrypt";
import { hashRefreshToken } from "../src/jwt/refresh-token.js";

const pass = bcrypt.hashSync("akash", 10);
const pass2 = bcrypt.hashSync("rahul", 10);

const db: UserRecord[] = [
    {
        id: "1",
        email: "akash@gmail.com",
        passwordHash: pass
    },
    {
        id: "2",
        email: "rahul@gmail.com",
        passwordHash: pass2
    }
];

const adapter = {
    db: [...db],
    sessions: [] as RefreshSession[],

    findUserByEmail(email: string): Promise<UserRecord | null> {
        return Promise.resolve(
            this.db.find(user => user.email === email) ?? null
        );
    },

    createUser(data: CreateUser): Promise<UserRecord> {
        const user = {
            id: Math.random().toString(),
            ...data
        };

        this.db.push(user);

        return Promise.resolve(user);
    },

    findUserById(userId: string): Promise<UserRecord | null> {
        return Promise.resolve(
            this.db.find(user => user.id === userId) ?? null
        );
    },

    findSessionByTokenHash(
        refreshTokenHash: string
    ): Promise<RefreshSession | null> {
        return Promise.resolve(
            this.sessions.find(
                session => session.refreshTokenHash === refreshTokenHash
            ) ?? null
        );
    },

    createSession(
        session: RefreshSession
    ): Promise<RefreshSession> {
        this.sessions.push(session);
        return Promise.resolve(session);
    },

    revokeSession(sessionId: string): Promise<void> {
        const session = this.sessions.find(
            session => session.sessionId === sessionId
        );

        if (session) {
            session.revokedAt = new Date();
        }

        return Promise.resolve();
    },

    getSessions(): RefreshSession[] {
        return this.sessions;
    }
};


const auth = createAuth({
    adapter,
    refreshTokenAdapter: adapter,
    secret: "hello"
});


describe("Login", () => {

    it("Successful login", async () => {
        const res = await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        expect(res.user.email).toBe("akash@gmail.com");
        expect(res.user.id).toBeDefined();
        expect(res.token).toBeTypeOf("string");
        expect(res.refreshToken).toBeTypeOf("string");
    });


    it("Nonexistent user", async () => {
        try {
            await auth.login({
                email: "aakash@gmail.com",
                password: "akash"
            });

            expect.fail("expected autherror to throw");

        } catch (error) {
            expect(error).toBeInstanceOf(AuthError);
            expect((error as AuthError).code)
                .toBe("INVALID_CREDENTIALS");
        }
    });


    it("wrong password", async () => {
        try {
            await auth.login({
                email: "akash@gmail.com",
                password: "wrong-password"
            });

            expect.fail("expected autherror to throw");

        } catch (error) {
            expect(error).toBeInstanceOf(AuthError);
            expect((error as AuthError).code)
                .toBe("INVALID_CREDENTIALS");
        }
    });


    it("should not expose the password hash to the caller", async () => {
        const res = await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        expect(res.user).not.toHaveProperty("passwordHash");
    });


    it("Successful login for another user", async () => {
        const res = await auth.login({
            email: "rahul@gmail.com",
            password: "rahul"
        });

        expect(res.user.email).toBe("rahul@gmail.com");
        expect(res.user.id).toBeDefined();
        expect(res.token).toBeTypeOf("string");
        expect(res.refreshToken).toBeTypeOf("string");
    });


    it("should create a refresh session", async () => {
        const before = adapter.getSessions().length;

        await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        const after = adapter.getSessions().length;

        expect(after).toBe(before + 1);
    });


    it("should create a session for the logged-in user", async () => {
        const result = await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        const sessions = adapter.getSessions();
        const session = sessions[sessions.length - 1];

        expect(session.userId).toBe(result.user.id);
    });


    it("should not store the raw refresh token", async () => {
        const result = await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        const sessions = adapter.getSessions();
        const session = sessions[sessions.length - 1];

        expect(session.refreshTokenHash)
            .not.toBe(result.refreshToken);
    });


    it("should store a valid bcrypt refresh token hash", async () => {
        const result = await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        const sessions = adapter.getSessions();
        const session = sessions[sessions.length - 1];

        expect(session.refreshTokenHash).toBe(hashRefreshToken(result.refreshToken));
    });


    it("should create a non-revoked session", async () => {
        await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        const sessions = adapter.getSessions();
        const session = sessions[sessions.length - 1];

        expect(session.revokedAt).toBeNull();
    });


    it("should set refresh token expiration in the future", async () => {
        await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        const sessions = adapter.getSessions();
        const session = sessions[sessions.length - 1];

        expect(session.expiresAt.getTime())
            .toBeGreaterThan(Date.now());
    });

});