import { describe, it, expect } from "vitest";
import bcrypt from "bcrypt";

import { createAuth, AuthError } from "../src/index.js";
import { createToken } from "../src/jwt/token.js";

import type { UserRecord, CreateUser } from "../src/types/adapter.js";

const secret = "hello";

const pass = bcrypt.hashSync("akash", 10);
const pass2 = bcrypt.hashSync("rahul", 10);

let db: UserRecord[] = [
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

    findUserByEmail(email: string): Promise<UserRecord | null> {
        return Promise.resolve(
            db.find(user => user.email === email) ?? null
        );
    },

    createUser(data: CreateUser): Promise<UserRecord> {

        const user = {
            id: Math.random().toString(),
            ...data
        };

        db.push(user);

        return Promise.resolve(user);
    },

    findUserById(userId: string): Promise<UserRecord | null> {
        return Promise.resolve(
            db.find(user => user.id === userId) ?? null
        );
    }
};


const auth = createAuth({
    adapter,
    secret
});


describe("Authenticate", () => {

    it("should return the correct user for a valid token", async () => {

        const token = await createToken(
            "1",
            secret,
            "7d"
        );

        const user = await auth.authenticate(token);

        expect(user.id).toBe("1");
        expect(user.email).toBe("akash@gmail.com");
    });


    it("should authenticate another user correctly", async () => {

        const token = await createToken(
            "2",
            secret,
            "7d"
        );

        const user = await auth.authenticate(token);

        expect(user.id).toBe("2");
        expect(user.email).toBe("rahul@gmail.com");
    });


    it("should reject an invalid token", async () => {

        await expect(
            auth.authenticate("invalid-token")
        ).rejects.toThrow();
    });

    it("should reject a tampered token", async () => {

        const token = await createToken(
            "1",
            secret,
            "7d"
        );

        const parts = token.split(".");

        parts[1] = parts[1] + "tampered";

        const tamperedToken = parts.join(".");

        await expect(
            auth.authenticate(tamperedToken)
        ).rejects.toThrow();
    });


    it("should reject an expired token", async () => {

        const token = await createToken(
            "1",
            secret,
            "0s"
        );

        await expect(
            auth.authenticate(token)
        ).rejects.toThrow();
    });


    it("should reject a token when the user no longer exists", async () => {

        const token = await createToken(
            "1",
            secret,
            "7d"
        );

        db = db.filter(user => user.id !== "1");

        await expect(
            auth.authenticate(token)
        ).rejects.toBeInstanceOf(AuthError);

        try {

            await auth.authenticate(token);

        } catch (error) {

            expect((error as AuthError).code)
                .toBe("AUTHENTICATION_FAILED");
        }
    });


    it("should not expose the password hash", async () => {

        const token = await createToken(
            "2",
            secret,
            "7d"
        );

        const user = await auth.authenticate(token);

        expect(user).not.toHaveProperty("passwordHash");
    });

});