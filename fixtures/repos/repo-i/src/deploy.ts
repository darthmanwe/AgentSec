import { execSync } from "child_process";

export function deploy(target: string): string {
  // Command injection: the argument is interpolated into a shell string.
  return execSync(`./deploy.sh ${target}`).toString();
}
