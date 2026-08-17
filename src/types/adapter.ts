
export interface User{
    id: string;
    email: string;
}

export interface UserRecord extends User {
    passwordHash: string;
}
export interface CreateUser{
    email: string;
    passwordHash: string;
}

export interface UserAdapter {
    findUserByEmail(email: string): Promise<UserRecord | null>;
    createUser(data: CreateUser): Promise<UserRecord>;
    findUserById(userId: string): Promise<UserRecord | null>;
}

