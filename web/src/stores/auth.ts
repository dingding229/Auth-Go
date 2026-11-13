import { defineStore } from "pinia";
import { get, post } from "../lib/http";
import {
  adminSession,
  clearAdmin,
  clearPortal,
  portalSession,
  setAdmin,
  setPortal,
} from "../lib/session";
import { api } from "../lib/http";
import type { Row } from "../lib/json";
export const useAuth = defineStore("auth", () => {
  async function login(data: Row) {
    clearAdmin();
    const value = await post("/auth/login", data);
    setAdmin(
      String(value.access_token),
      String(value.refresh_token),
      value.admin,
    );
  }
  async function me() {
    const value = await get("/auth/me", undefined, { quiet: true });
    adminSession.user = value;
    return value;
  }
  async function logout() {
    try {
      await post("/auth/logout");
    } finally {
      clearAdmin();
    }
  }
  async function portalLogin(data: Row) {
    clearPortal();
    const value = await api("portal", "/login", { method: "POST", data });
    setPortal(String(value.portal_token));
  }
  async function portalUserLogin(data: Row) {
    clearPortal();
    const v = await api("portal", "/user/login", { method: "POST", data });
    setPortal(String(v.portal_token), "user");
  }
  return {
    portalUserLogin,
    admin: adminSession,
    portal: portalSession,
    login,
    me,
    logout,
    portalLogin,
    clearAdmin,
    clearPortal,
  };
});
