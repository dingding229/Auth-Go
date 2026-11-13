import { defineStore } from "pinia";

export const useUIStore = defineStore("ui", {
  state: () => ({ siteName: "Auth Go", pageTitle: "" }),
});
