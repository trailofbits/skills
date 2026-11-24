// Worker failures become `null` in the workflow, as they do under Claude Code's
// native Workflow tool. Every other code is a configuration or capability problem
// and fails the whole run: a misconfigured role must not read as twenty null results.
export const WORKER_FAILURES = new Set(['EXIT', 'LAUNCH', 'TIMEOUT', 'OUTPUT_LIMIT', 'PROTOCOL', 'WORKER', 'SCHEMA']);

export class RunnerError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = 'RunnerError';
    this.code = code;
    Object.assign(this, details);
  }
}

export const isWorkerFailure = error => WORKER_FAILURES.has(error?.code);
