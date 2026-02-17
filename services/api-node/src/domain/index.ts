import { DomainEngine } from "./engine.js";

export const engine = new DomainEngine();

export function resetEngineForTests(): void {
  engine.resetStateForTests();
}
