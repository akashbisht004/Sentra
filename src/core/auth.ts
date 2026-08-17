import { UserAdapter, User, SignUpData } from "../types/adapter.js";
import bcrypt from "bcrypt";

class Auth {
  private adapter: UserAdapter;
  private secret: string;

  constructor(adapter: UserAdapter, secret: string) {
    this.adapter = adapter;
    this.secret = secret;
  }

  async signUp(data: SignUpData): Promise<User> {
        const user = await this.adapter.findUserByEmail(data.email);

        if (user != null) {
            throw new Error("User already exists");
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
}
export  {Auth};

