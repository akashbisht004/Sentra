import type {UserAdapter, UserRecord, CreateUser} from "../src/types/adapter.js";

export class MemoryAdapter implements UserAdapter{
    private db: UserRecord[]=[];

    async findUserByEmail(email: string): Promise<UserRecord | null> {
        return this.db.find((user) => user.email === email) ?? null;
    }

    async findUserById(userId: string): Promise<UserRecord | null> {
        return this.db.find((user)=> user.id===userId)?? null;
    }

    async createUser(data: CreateUser): Promise<UserRecord> {
        const user: UserRecord={id:Math.random().toString(), email:data.email, passwordHash:data.passwordHash};
        this.db.push(user);
        return user;
    }

}