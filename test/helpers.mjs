// Shared helpers for the tests. No dependencies: node:test + the built package.

/** A fake `fetch` that records calls and answers with the given responses, in order (the last one repeats). */
export function mockFetch(...answers) {
  const calls = [];
  const queue = answers.length ? answers : [{ status: 200, body: okBody() }];
  const fn = async (url, init) => {
    const call = { url, init, headers: init.headers, body: init.body ? JSON.parse(init.body) : undefined };
    calls.push(call);
    const answer = queue[Math.min(calls.length - 1, queue.length - 1)];
    if (typeof answer === 'function') return answer(call, init);
    if (answer instanceof Error) throw answer;
    const text = typeof answer.body === 'string' ? answer.body : JSON.stringify(answer.body);
    return new Response(text, { status: answer.status ?? 200, headers: { 'Content-Type': 'application/json' } });
  };
  fn.calls = calls;
  return fn;
}

export function okBody(id = 'msg_test_1', extra = {}) {
  return {
    success: true,
    messageId: id,
    queued: false,
    data: { messageId: id, branded: false, queued: false, remaining: { clean: 99, total: 'unlimited' } },
    ...extra,
  };
}

/** A random 32-byte secret in base64, like the ones Supabase and Clerk generate. */
export function randomSecretB64(bytes = 32) {
  const raw = crypto.getRandomValues(new Uint8Array(bytes));
  return btoa(String.fromCharCode(...raw));
}

export function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}
