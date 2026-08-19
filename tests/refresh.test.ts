import { createAuth, AuthError } from "../src/index.js";
import { MemoryAdapter } from "../examples/memory-adapter.js";
import { describe, it, expect } from "vitest";
import bcrypt from "bcrypt";

describe("Refresh", () => {

    it("should refresh a valid refresh token", async () => {
        const adapter = new MemoryAdapter();

        await adapter.createUser({
            email: "akash@gmail.com",
            passwordHash: await bcrypt.hash("akash", 10)
        });

        const auth = createAuth({
            adapter,
            refreshTokenAdapter: adapter,
            secret: "my-secret"
        });

        const loginResult = await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        const result = await auth.refresh(
            loginResult.refreshToken
        );

        expect(result.user.email).toBe("akash@gmail.com");
        expect(result.user.id).toBe(loginResult.user.id);
        expect(result.token).toBeTypeOf("string");
        expect(result.refreshToken).not.toBe(loginResult.refreshToken
        );

        expect(result.refreshToken).toBeTypeOf("string");
    });

    it("should reject an invalid refresh token", async () => {
        const adapter = new MemoryAdapter();

        await adapter.createUser({
            email: "akash@gmail.com",
            passwordHash: await bcrypt.hash("akash", 10)
        });

        const auth = createAuth({
            adapter,
            refreshTokenAdapter: adapter,
            secret: "my-secret"
        });

        try {
            await auth.refresh("invalid-refresh-token");

            expect.fail("Expected authentication error");
        } catch (error) {
            expect(error).toBeInstanceOf(AuthError);
            expect((error as AuthError).code)
                .toBe("AUTHENTICATION_FAILED");
        }
    });
    it("should reject a revoked refresh token", async () => {
        const adapter = new MemoryAdapter();

        await adapter.createUser({
            email: "akash@gmail.com",
            passwordHash: await bcrypt.hash("akash", 10)
        });

        const auth = createAuth({
            adapter,
            refreshTokenAdapter: adapter,
            secret: "my-secret"
        });

        const loginResult = await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        const sessions = adapter.getSessions();

        const session = sessions[0];

        await adapter.revokeSession(session.sessionId);

        try {
            await auth.refresh(loginResult.refreshToken);

            expect.fail("Expected authentication error");
        } catch (error) {
            expect(error).toBeInstanceOf(AuthError);
            expect((error as AuthError).code)
                .toBe("AUTHENTICATION_FAILED");
        }
    });
    it("should reject an expired refresh token", async () => {
        const adapter = new MemoryAdapter();

        await adapter.createUser({
            email: "akash@gmail.com",
            passwordHash: await bcrypt.hash("akash", 10)
        });

        const auth = createAuth({
            adapter,
            refreshTokenAdapter: adapter,
            secret: "my-secret"
        });

        const loginResult = await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        const sessions = adapter.getSessions();

        sessions[0].expiresAt = new Date(Date.now() - 1000);

        try {
            await auth.refresh(loginResult.refreshToken);

            expect.fail("Expected authentication error");
        } catch (error) {
            expect(error).toBeInstanceOf(AuthError);
            expect((error as AuthError).code)
                .toBe("AUTHENTICATION_FAILED");
        }
    });
    it("should reject refresh when the user no longer exists", async () => {
        const adapter = new MemoryAdapter();

        const user = await adapter.createUser({
            email: "akash@gmail.com",
            passwordHash: await bcrypt.hash("akash", 10)
        });

        const auth = createAuth({
            adapter,
            refreshTokenAdapter: adapter,
            secret: "my-secret"
        });

        const loginResult = await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        adapter.deleteUser(user.id);

        try {
            await auth.refresh(loginResult.refreshToken);

            expect.fail("Expected authentication error");
        } catch (error) {
            expect(error).toBeInstanceOf(AuthError);
            expect((error as AuthError).code)
                .toBe("AUTHENTICATION_FAILED");
        }
    });
    it("should invalidate the old refresh token after rotation", async () => {
        const adapter = new MemoryAdapter();

        await adapter.createUser({
            email: "akash@gmail.com",
            passwordHash: await bcrypt.hash("akash", 10)
        });

        const auth = createAuth({
            adapter,
            refreshTokenAdapter: adapter,
            secret: "my-secret"
        });

        const firstLogin = await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        const firstRefresh = await auth.refresh(
            firstLogin.refreshToken
        );

        await expect(
            auth.refresh(firstLogin.refreshToken)
        ).rejects.toMatchObject({
            code: "AUTHENTICATION_FAILED"
        });

        expect(firstRefresh.refreshToken)
            .not.toBe(firstLogin.refreshToken);
    });

    it("should allow the newly rotated refresh token to be used", async () => {
        const adapter = new MemoryAdapter();

        await adapter.createUser({
            email: "akash@gmail.com",
            passwordHash: await bcrypt.hash("akash", 10)
        });

        const auth = createAuth({
            adapter,
            refreshTokenAdapter: adapter,
            secret: "my-secret"
        });

        const firstLogin = await auth.login({
            email: "akash@gmail.com",
            password: "akash"
        });

        const secondResult = await auth.refresh(
            firstLogin.refreshToken
        );

        const thirdResult = await auth.refresh(
            secondResult.refreshToken
        );

        expect(thirdResult.user.id)
            .toBe(firstLogin.user.id);

        expect(thirdResult.token)
            .toBeTypeOf("string");

        expect(thirdResult.refreshToken)
            .toBeTypeOf("string");

        expect(thirdResult.refreshToken)
            .not.toBe(secondResult.refreshToken);
    });
});