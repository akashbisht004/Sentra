import { AuthError, createAuth } from "../src/index";
import { UserRecord,CreateUser } from "../src/types/adapter";
import { expect,it,describe } from "vitest";
import bcrypt from "bcrypt";

const pass = bcrypt.hashSync("akash", 10);
const pass2= bcrypt.hashSync("rahul",10);
let db: UserRecord[] = [{ id: "1", email: "akash@gmail.com", passwordHash: pass },{
    id:"2",
    email:"rahul@gmail.com",
    passwordHash: pass2
}];

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

describe("Login",()=>{
    it("Successful login",async ()=>{
        let user=await auth.login({email:"akash@gmail.com",password:"akash"});
        expect(user.email).toBe("akash@gmail.com");
        expect(user.id).toBeDefined();
    });

    it("Nonexistent user",async ()=>{
        try{
            await auth.login({email: "aakash@gmail.com",password: "akash"});
            expect.fail("expected autherror to throw");
        }catch(error){
            expect(error).toBeInstanceOf(AuthError);
            expect((error as AuthError).code).toBe("INVALID_CREDENTIALS");
        }
    });

    it("wrong password",async ()=>{
        try{
            await auth.login({email: "akash@gmail.com",password: "wrong-password"});
            expect.fail("expected autherror to throw");
        }catch(error){
            expect(error).toBeInstanceOf(AuthError);
            expect((error as AuthError).code).toBe("INVALID_CREDENTIALS");
        }
    });

    it("should not expose the password hash to the caller", async () => {
            const user = await auth.login({
                email: "akash@gmail.com",
                password: "akash"
            });
    
            expect(user).not.toHaveProperty("passwordHash");
        });

    it("Successful login for another user",async ()=>{
        let user=await auth.login({email:"rahul@gmail.com",password:"rahul"});
        expect(user.email).toBe("rahul@gmail.com");
        expect(user.id).toBeDefined();
    });

})

