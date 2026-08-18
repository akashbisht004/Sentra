import {createAuth} from "../src/index.js";
import { MemoryAdapter } from "./memory-adapter.js";

const adapter = new MemoryAdapter();

const auth = createAuth({
    adapter,
    secret: "my-secret"
});
// signup
const res = await auth.signUp({
    email: "akash@gmail.com",
    password: "123"
});
// login
const { user, token } = await auth.login({
    email: "akash@gmail.com",
    password: "123"
});
// authentication
const authenticatedUser = await auth.authenticate(token);