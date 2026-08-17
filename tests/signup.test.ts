import { createAuth } from "../src/index";
import { CreateUser, UserRecord } from "../src/types/adapter";
import { describe, it, expect, beforeEach } from "vitest";
import bcrypt from "bcrypt";

let db: UserRecord[] = [];

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
    secret: "hello"
});


beforeEach(() => {
    db = [];
});


describe("Signup", () => {

    it("should create a new user", async () => {
        await auth.signUp({
            email: "akash@gmail.com",
            password: "333"
        });

        expect(db).toHaveLength(1);
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

        expect(db[0].email).toBe("akash@gmail.com");
    });


    it("should hash the password", async () => {
        await auth.signUp({
            email: "akash@gmail.com",
            password: "333"
        });

        expect(db[0].passwordHash).not.toBe("333");
    });


    it("should create a valid bcrypt password hash", async () => {
        await auth.signUp({
            email: "akash@gmail.com",
            password: "333"
        });

        const isValid = await bcrypt.compare(
            "333",
            db[0].passwordHash
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

        await expect(
            auth.signUp({
                email: "akash@gmail.com",
                password: "another-password"
            })
        ).rejects.toThrow("User already exists");
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
        } catch {}

        expect(db).toHaveLength(1);
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

        expect(db).toHaveLength(2);
    });

});