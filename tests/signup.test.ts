import { createAuth, AuthError } from "../src/index.js";
import { describe, it, expect, beforeEach, vi } from "vitest";
import bcrypt from "bcrypt";
import { MemoryAdapter } from "../examples/memory-adapter.js";

describe("Signup", () => {
    let adapter: MemoryAdapter;
    let auth: ReturnType<typeof createAuth>;

    beforeEach(() => {
        adapter = new MemoryAdapter();

        auth = createAuth({
            adapter,
            refreshTokenAdapter: adapter,
            secret: "hello"
        });
    });

    it("should create a new user", async () => {
        await auth.signUp({
            email: "akash@gmail.com",
            password: "333"
        });

        expect(adapter.getUsers()).toHaveLength(1);
    });

    it("should return the created user", async () => {
        const user = await auth.signUp({
            email: "akash@gmail.com",
            password: "333"
        });

        expect(user.email).toBe("akash@gmail.com");
        expect(user.id).toBeDefined();
    });

    it("should store the correct email", async () => {
        await auth.signUp({
            email: "akash@gmail.com",
            password: "333"
        });

        expect(adapter.getUsers()[0].email).toBe("akash@gmail.com");
    });

    it("should hash the password", async () => {
        await auth.signUp({
            email: "akash@gmail.com",
            password: "333"
        });

        expect(adapter.getUsers()[0].passwordHash).not.toBe("333");
    });

    it("should create a valid bcrypt password hash", async () => {
        await auth.signUp({
            email: "akash@gmail.com",
            password: "333"
        });

        const isValid = await bcrypt.compare(
            "333",
            adapter.getUsers()[0].passwordHash
        );

        expect(isValid).toBe(true);
    });

    it("should not expose the password hash to the caller", async () => {
        const user = await auth.signUp({
            email: "akash@gmail.com",
            password: "333"
        });

        expect(user).not.toHaveProperty("passwordHash");
    });

    it("should reject an existing email", async () => {
        await auth.signUp({
            email: "akash@gmail.com",
            password: "333"
        });

        try {
            await auth.signUp({
                email: "akash@gmail.com",
                password: "another-password"
            });

            expect.fail("Expected signup to throw");
        } catch (error) {
            expect(error).toBeInstanceOf(AuthError);
            expect((error as AuthError).code).toBe(
                "USER_ALREADY_EXISTS"
            );
        }
    });

    it("should not create a duplicate user", async () => {
        await auth.signUp({
            email: "akash@gmail.com",
            password: "333"
        });

        try {
            await auth.signUp({
                email: "akash@gmail.com",
                password: "another-password"
            });
        } catch {
            // Expected
        }

        expect(adapter.getUsers()).toHaveLength(1);
    });

    it("should allow different users to signup", async () => {
        await auth.signUp({
            email: "akash@gmail.com",
            password: "333"
        });

        await auth.signUp({
            email: "rahul@gmail.com",
            password: "444"
        });

        expect(adapter.getUsers()).toHaveLength(2);
    });

    it("should call beforeSignUp hook", async () => {
        const beforeSignUp = vi.fn().mockResolvedValue(undefined);

        auth = createAuth({
            adapter,
            refreshTokenAdapter: adapter,
            secret: "my-secret",
            hooks: {
                beforeSignUp
            }
        });

        await auth.signUp({
            email: "akash@gmail.com",
            password: "akash"
        });

        expect(beforeSignUp).toHaveBeenCalledOnce();

        expect(beforeSignUp).toHaveBeenCalledWith({
            email: "akash@gmail.com"
        });
    });

    it("should stop signup when beforeSignUp throws", async () => {
        const beforeSignUp = vi
            .fn()
            .mockRejectedValue(
                new AuthError(
                    "Registration is disabled",
                    "AUTHENTICATION_FAILED"
                )
            );

        auth = createAuth({
            adapter,
            refreshTokenAdapter: adapter,
            secret: "my-secret",
            hooks: {
                beforeSignUp
            }
        });

        await expect(
            auth.signUp({
                email: "akash@gmail.com",
                password: "akash"
            })
        ).rejects.toMatchObject({
            code: "AUTHENTICATION_FAILED"
        });

        expect(
            await adapter.findUserByEmail("akash@gmail.com")
        ).toBeNull();
    });

    it("should call afterSignUp hook after successful signup", async () => {
        const afterSignUp = vi.fn().mockResolvedValue(undefined);

        auth = createAuth({
            adapter,
            refreshTokenAdapter: adapter,
            secret: "my-secret",
            hooks: {
                afterSignUp
            }
        });

        const user = await auth.signUp({
            email: "akash@gmail.com",
            password: "akash"
        });

        expect(afterSignUp).toHaveBeenCalledOnce();
        expect(afterSignUp).toHaveBeenCalledWith(user);
    });

    it("should not expose password data to afterSignUp", async () => {
        const afterSignUp = vi.fn().mockResolvedValue(undefined);

        auth = createAuth({
            adapter,
            refreshTokenAdapter: adapter,
            secret: "my-secret",
            hooks: {
                afterSignUp
            }
        });

        await auth.signUp({
            email: "akash@gmail.com",
            password: "akash"
        });

        const hookUser = afterSignUp.mock.calls[0][0];

        expect(hookUser).not.toHaveProperty("password");
        expect(hookUser).not.toHaveProperty("passwordHash");
    });

    it("should still return successful signup if afterSignUp throws", async () => {
        const afterSignUp = vi
            .fn()
            .mockRejectedValue(new Error("Analytics failed"));

        auth = createAuth({
            adapter,
            refreshTokenAdapter: adapter,
            secret: "my-secret",
            hooks: {
                afterSignUp
            }
        });

        const user = await auth.signUp({
            email: "akash@gmail.com",
            password: "akash"
        });

        expect(user.email).toBe("akash@gmail.com");
        expect(user.id).toBeDefined();

        expect(adapter.getUsers()).toHaveLength(1);
    });
});