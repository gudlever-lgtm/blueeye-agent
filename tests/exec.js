import { spawn } from 'node:child_process';

// Kører en systemkommando via spawn. Samler stdout/stderr og resolver
// med { code, stdout, stderr }. Respekterer en valgfri AbortSignal.
export function runCommand(cmd, args, { signal } = {}) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason || new Error('Command aborted'));
      return;
    }

    let child;
    try {
      child = spawn(cmd, args);
    } catch (err) {
      reject(err);
      return;
    }

    let stdout = '';
    let stderr = '';

    const onAbort = () => {
      child.kill('SIGKILL');
      reject(signal.reason || new Error('Command aborted'));
    };
    signal?.addEventListener('abort', onAbort, { once: true });

    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });

    child.on('error', (err) => {
      signal?.removeEventListener('abort', onAbort);
      reject(err);
    });

    child.on('close', (code) => {
      signal?.removeEventListener('abort', onAbort);
      resolve({ code, stdout, stderr });
    });
  });
}

// Fejler kommandoen fordi binæren ikke findes?
export function isMissingBinary(err) {
  return err && err.code === 'ENOENT';
}
