"use strict";

// Asks this Rootwell to make a request (CSR) whose new key it keeps. It sends
// only the names and organization details a person typed, after checking
// their shape; it reads no file, and the key is made on the server and never
// comes back. Request's own script, which reads key files, makes no request
// and calls only this.
(function () {
  const name = /^(\*\.)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;
  const address = /^[0-9a-f.:]{2,45}$/;
  const algorithms = ["ec-p256", "rsa-2048"];
  const details = ["organization", "locality", "province", "country"];

  function send(path, body) {
    return fetch(path, {
      method: body ? "POST" : "GET", credentials: "same-origin", cache: "no-store", redirect: "error",
      headers: body ? { "Content-Type": "application/json", "X-Rootwell-Request": "1" } : { "X-Rootwell-Request": "1" },
      body: body ? JSON.stringify(body) : undefined,
    });
  }

  async function answer(response) {
    const text = await response.text();
    if (text.length > 4 * 1024 * 1024) throw new Error("large");
    return JSON.parse(text);
  }

  // keep makes the request. It answers { request } when it is made, or
  // { status, refusal } when Rootwell said no.
  async function keep(input) {
    const ok = input && algorithms.includes(input.algorithm) && Array.isArray(input.dns_names) && Array.isArray(input.ip_addresses) &&
      input.dns_names.length <= 32 && input.ip_addresses.length <= 8 && input.dns_names.length + input.ip_addresses.length > 0 &&
      input.dns_names.every((n) => typeof n === "string" && n.length <= 253 && name.test(n)) &&
      input.ip_addresses.every((a) => typeof a === "string" && address.test(a)) &&
      details.every((d) => typeof input[d] === "string" && input[d].length <= 128);
    if (!ok) throw new Error("input");
    const body = { algorithm: input.algorithm, dns_names: input.dns_names.slice(), ip_addresses: input.ip_addresses.slice() };
    for (const d of details) if (input[d]) body[d] = input[d];
    // The list's count goes with the request. When the list changed in
    // between, it is read once more.
    for (let attempt = 0; attempt < 2; attempt++) {
      const list = await send("/api/inventory");
      if (!list.ok) return { status: list.status };
      const listed = await answer(list);
      if (!Number.isSafeInteger(listed.generation)) throw new Error("answer");
      const made = await send("/api/requests/create", { ...body, expected_generation: listed.generation });
      const refusal = made.headers.get("X-Rootwell-Refusal") || "";
      if (made.status === 409 && !refusal && attempt === 0) continue;
      if (!made.ok) return { status: made.status, refusal };
      const result = await answer(made);
      const request = result && result.request;
      if (!request || typeof request.csr !== "string" || !Array.isArray(request.dns_names) || !Array.isArray(request.ip_addresses)) throw new Error("answer");
      return { request };
    }
    return { status: 409, refusal: "" };
  }

  Object.defineProperty(globalThis, "rootwellKeepRequest", { value: keep, configurable: false, writable: false });
})();
