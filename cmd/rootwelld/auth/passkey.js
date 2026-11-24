"use strict";

// Passkeys in the browser: Rootwell's options become a WebAuthn request, and
// the authenticator's answer becomes the base64url fields the server reads.
// The device asks for the person's fingerprint, face or PIN itself.
(function () {
  function fromB64(text) {
    const plain = String(text).replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(plain + "===".slice((plain.length + 3) % 4));
    return Uint8Array.from(binary, (c) => c.charCodeAt(0));
  }

  function toB64(buffer) {
    let binary = "";
    for (const b of new Uint8Array(buffer)) binary += String.fromCharCode(b);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  globalThis.rootwellPasskey = {
    supported() {
      return typeof globalThis.PublicKeyCredential === "function" && !!(globalThis.navigator && globalThis.navigator.credentials);
    },

    // sign asks a passkey to sign the server's challenge.
    async sign(options) {
      const credential = await globalThis.navigator.credentials.get({ publicKey: {
        challenge: fromB64(options.challenge), rpId: options.rp_id, timeout: options.timeout, userVerification: "required",
        allowCredentials: options.allow.map((id) => ({ type: "public-key", id: fromB64(id) })),
      } });
      if (!credential || !credential.response) throw new Error("no passkey");
      return {
        id: toB64(credential.rawId), client_data: toB64(credential.response.clientDataJSON),
        authenticator_data: toB64(credential.response.authenticatorData), signature: toB64(credential.response.signature),
      };
    },

    // create makes a new passkey for this account on this name.
    async create(options, name) {
      const credential = await globalThis.navigator.credentials.create({ publicKey: {
        challenge: fromB64(options.challenge), rp: { id: options.rp_id, name: "Rootwell" },
        user: { id: fromB64(options.user_id), name: options.user_name, displayName: options.user_name },
        pubKeyCredParams: [-7, -8, -257].map((alg) => ({ type: "public-key", alg })),
        authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
        attestation: "none", timeout: options.timeout,
        excludeCredentials: options.exclude.map((id) => ({ type: "public-key", id: fromB64(id) })),
      } });
      if (!credential || !credential.response) throw new Error("no passkey");
      return { client_data: toB64(credential.response.clientDataJSON), attestation: toB64(credential.response.attestationObject), name };
    },
  };
})();
