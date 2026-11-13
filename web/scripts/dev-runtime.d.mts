import type { HtmlTagDescriptor, Plugin } from "vite";
export interface DevUIRoute {
  path: string;
  scope: string;
}
export const devApiTarget: string;
export function devAdminCandidate(requestUrl: string | undefined, routes: readonly DevUIRoute[]): string | null;
export function confirmedDevAdminPath(candidate: string | null, envelope: unknown): string | null;
export function devRuntimeTags(requestUrl: string | undefined, routes: readonly DevUIRoute[], request?: typeof globalThis.fetch): Promise<HtmlTagDescriptor[]>;
export function devRuntimePlugin(): Plugin;
