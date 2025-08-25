import { Elysia } from "elysia";
import { AuthService } from "../auth/auth-service";
import {
    TLoginBody,
    TRegisterBody,
    TRenewTokenQuery,
} from "../types/auth";

/**
 * Basic non-SSO (email/password) auth endpoints.
 * Routes:
 *   POST /api/auth/register
 *   POST /api/auth/login
 *   GET  /api/auth/renew
 *   POST /api/auth/logout
 */
const auth = new Elysia({ prefix: "/auth" })
    .post(
        "/register",
        async ({ body, cookie: { session_token }, ip, set }) => {
            const res = await AuthService.register({
                ...body,
                ip,
                trusted: Boolean((body as any)?.trusted),
            });
            if (!res.success || !res.token || !res.expires) {
                set.status = 401;
                return { ok: false };
            }
            session_token.set({
                value: res.token,
                httpOnly: true,
                sameSite: "lax",
                expires: res.expires,
                path: "/",
            });
            return { ok: true };
        },
        { body: TRegisterBody }
    )
    .post(
        "/login",
        async ({ body, cookie: { session_token }, ip, set }) => {
            const res = await AuthService.authenticate({
                ...body,
                ip,
                trusted: Boolean((body as any)?.trusted),
            });
            if (!res.success || !res.token || !res.expires) {
                set.status = 401;
                return { ok: false };
            }
            session_token.set({
                value: res.token,
                httpOnly: true,
                sameSite: "lax",
                expires: res.expires,
                path: "/",
            });
            return { ok: true };
        },
        { body: TLoginBody }
    )
    .get(
        "/renew",
        async ({ cookie: { session_token }, query, set }) => {
            const token = session_token.value;
            if (!token) {
                set.status = 401;
                return { ok: false };
            }
            const res = await AuthService.renewToken(
                token,
                Boolean((query as any)?.trusted)
            );
            if (!res.success || !res.token || !res.expires) {
                set.status = 401;
                return { ok: false };
            }
            session_token.set({
                value: res.token,
                httpOnly: true,
                sameSite: "lax",
                expires: res.expires,
                path: "/",
            });
            return { ok: true };
        },
        { query: TRenewTokenQuery }
    )
    .post("/logout", async ({ cookie: { session_token } }) => {
        session_token.remove();
        return { ok: true };
    });

export default auth;
