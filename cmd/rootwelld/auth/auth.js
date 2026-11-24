"use strict";

// Sign-in, setup and the Account page. Every request is JSON to the same
// origin with the page header; the server's answers are read by status, and
// only the few shapes it sends on success are accepted.
(() => {
  const mode = document.body.dataset.mode;
  const $ = (id) => document.getElementById(id);
  const status = $("status");
  const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

  function say(text) { status.textContent = text || ""; }

  // send posts body and returns the status and, for JSON answers, the value.
  // One deadline covers the whole exchange.
  async function send(path, body, method = "POST") {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    try {
      const response = await fetch(path, {
        method, credentials: "same-origin", cache: "no-store", redirect: "error", signal: controller.signal,
        headers: body === undefined ? { "X-Rootwell-Request": "1" } : { "Content-Type": "application/json", "X-Rootwell-Request": "1" },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      const text = await response.text();
      if (text.length > 16384) throw new Error("large answer");
      let value = null;
      if (response.ok && (response.headers.get("content-type") || "").split(";")[0].trim() === "application/json") value = JSON.parse(text);
      return { status: response.status, ok: response.ok, text, value };
    } finally {
      clearTimeout(timer);
    }
  }

  // A change that needs a fresh phone code asks for one once, then repeats.
  async function sendFresh(path, body) {
    let answer = await send(path, body);
    if (answer.status === 428 && globalThis.rootwellFresh && await globalThis.rootwellFresh()) answer = await send(path, body);
    return answer;
  }

  const tooMany = "Too many wrong tries. Wait a little, then try again.";
  const failed = "That did not go through. Try again.";

  function showPhone(value) {
    if (!value || typeof value.key !== "string" || !/^[A-Z2-7]{32}$/.test(value.key) || !globalThis.rootwellQR($("phone-qr"), value.qr)) return false;
    $("phone-key").textContent = globalThis.rootwellGroups(value.key);
    $("phone-step").hidden = false;
    $("phone-code").value = "";
    $("phone-code").focus();
    return true;
  }

  function showCodes(value, name) {
    const codes = value && value.recovery_codes;
    if (!Array.isArray(codes) || codes.length !== 10 || !codes.every((c) => typeof c === "string" && /^[a-z2-7]{4}(-[a-z2-7]{4}){3}$/.test(c))) return false;
    $("codes").replaceChildren(...codes.map((code) => {
      const item = document.createElement("li");
      item.className = "mono";
      item.textContent = code;
      return item;
    }));
    const text = "Rootwell recovery codes for " + name + "\nEach one signs in once, in place of a phone code.\n\n" + codes.join("\n") + "\n";
    $("codes-copy").onclick = async () => {
      try {
        await navigator.clipboard.writeText(text);
        $("codes-copy").textContent = "Copied";
      } catch {
        say("Copying is blocked here. Download them instead.");
      }
    };
    $("codes-download").onclick = () => {
      const link = document.createElement("a");
      link.href = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
      link.download = "rootwell-recovery-codes.txt";
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(link.href), 1000);
    };
    $("codes-step").hidden = false;
    return true;
  }

  function guard(form, run) {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const buttons = form.querySelectorAll("button");
      if (form.dataset.busy) return;
      form.dataset.busy = "1";
      buttons.forEach((b) => { b.disabled = true; });
      say("");
      try {
        await run();
      } catch {
        say(failed);
      } finally {
        delete form.dataset.busy;
        buttons.forEach((b) => { b.disabled = false; });
      }
    });
  }

  // ── Sign in ─────────────────────────────────────────────────────────────
  if (mode === "login") {
    const passwordForm = $("password-form");
    const codeForm = $("code-form");
    const passkeyButton = $("passkey-sign-in");
    // A passkey may stand in for the phone code when the account has one and
    // this browser can use it.
    const offerPasskey = async () => {
      passkeyButton.hidden = true;
      if (!globalThis.rootwellPasskey || !globalThis.rootwellPasskey.supported()) return;
      const answer = await send("/api/session", undefined, "GET").catch(() => null);
      passkeyButton.hidden = !(answer && answer.ok && answer.value && answer.value.passkeys === true);
    };
    const showCode = () => {
      passwordForm.hidden = true;
      codeForm.hidden = false;
      $("code").value = "";
      $("code").focus();
      void offerPasskey();
    };
    const showPassword = () => {
      codeForm.hidden = true;
      passwordForm.hidden = false;
      $("code").value = "";
      $("name").focus();
    };
    void send("/api/session", undefined, "GET").then((answer) => {
      if (answer.ok && answer.value && answer.value.stage === "code") showCode();
      if (answer.ok && answer.value && answer.value.stage === "ready") window.location.assign("/certificates");
    }).catch(() => {});
    guard(passwordForm, async () => {
      const name = $("name").value.trim();
      const password = $("password").value;
      $("password").value = "";
      if (!NAME.test(name) || !password) return say("That name and password do not match.");
      const answer = await send("/api/session", { name, password });
      if (answer.status === 204) return showCode();
      say(answer.status === 429 ? tooMany : answer.status === 401 ? "That name and password do not match." :
        answer.status === 503 ? "Rootwell is busy. Try again." : failed);
    });
    guard(codeForm, async () => {
      const code = $("code").value.trim();
      $("code").value = "";
      if (!code) return say("Enter the code your phone shows.");
      const answer = await send("/api/session/code", { code });
      if (answer.status === 204) return window.location.assign("/certificates");
      if (answer.status === 409 || (answer.status === 401 && /sign in again/i.test(answer.text))) {
        showPassword();
        return say(/too many/i.test(answer.text) ? "Too many wrong codes. Sign in again." : "Sign in again.");
      }
      say(answer.status === 429 ? tooMany : answer.status === 401 ? "That code does not match." : failed);
      $("code").focus();
    });
    passkeyButton.addEventListener("click", async () => {
      if (passkeyButton.disabled) return;
      say("");
      passkeyButton.disabled = true;
      try {
        const options = await send("/api/passkey/options", {});
        if (options.status !== 200 || !options.value) {
          return say(options.status === 409 ? "Passkeys work on a name, such as localhost, not on an IP address." : failed);
        }
        let signed;
        try {
          signed = await globalThis.rootwellPasskey.sign(options.value);
        } catch {
          return say("The passkey was not used. Try again, or enter a code.");
        }
        const answer = await send("/api/passkey", signed);
        if (answer.status === 204) return window.location.assign("/certificates");
        if (answer.status === 401 && /sign in again/i.test(answer.text)) {
          showPassword();
          return say("Too many wrong answers. Sign in again.");
        }
        say(answer.status === 429 ? tooMany : answer.status === 401 ? "That passkey was not accepted." : "Ask the passkey once more.");
      } catch {
        say(failed);
      } finally {
        passkeyButton.disabled = false;
      }
    });
    $("start-over").addEventListener("click", async () => {
      await send("/api/session", undefined, "DELETE").catch(() => {});
      say("");
      showPassword();
    });
  }

  // ── Setup ───────────────────────────────────────────────────────────────
  if (mode === "setup") {
    let name = "";
    guard($("setup-form"), async () => {
      const code = $("setup-code").value.trim();
      name = $("name").value.trim();
      const password = $("password").value;
      const again = $("confirm").value;
      if (!code) return say("Enter the setup code from the server.");
      if (!NAME.test(name)) return say("Choose a name of letters and digits; dots, dashes and underscores may follow.");
      if ([...password].length < 15) return say("Choose a password of at least 15 characters.");
      if (password !== again) return say("The two passwords differ.");
      const answer = await send("/api/setup", { code, name, password });
      if (answer.status === 200 && answer.value && typeof answer.value.name === "string") {
        $("password").value = "";
        $("confirm").value = "";
        $("setup-code").value = "";
        name = answer.value.name;
        $("setup-step").hidden = true;
        if (!showPhone(answer.value)) say(failed);
        return;
      }
      say(answer.status === 429 ? tooMany :
        answer.status === 401 ? "That setup code does not work for this name. Make a new one on the server with rootwelld setup-code." :
        answer.status === 400 ? "Choose a password of at least 15 characters that is not a common one." : failed);
    });
    guard($("phone-form"), async () => {
      const code = $("phone-code").value.trim();
      $("phone-code").value = "";
      if (!/^\d{6}$/.test(code)) return say("Enter the six digits your phone shows.");
      const answer = await send("/api/setup/confirm", { code });
      if (answer.status === 200) {
        $("phone-step").hidden = true;
        if (!showCodes(answer.value, name)) say(failed);
        return;
      }
      if (answer.status === 409 || (answer.status === 401 && /start the setup again/i.test(answer.text))) {
        $("phone-step").hidden = true;
        $("setup-step").hidden = false;
        return say(answer.status === 409 ? "That setup code no longer works. Make a new one on the server with rootwelld setup-code." :
          "Too many wrong codes, or the time ran out. Start again.");
      }
      say(answer.status === 429 ? tooMany : "That code does not match. Check the phone's clock, then enter the code it shows now.");
      $("phone-code").focus();
    });
  }

  // ── Account ─────────────────────────────────────────────────────────────
  if (mode === "account") {
    let name = "";
    const left = (n) => { $("codes-left").textContent = n === 1 ? "1 is left." : n + " are left."; };
    void send("/api/session", undefined, "GET").then((answer) => {
      if (!answer.ok || !answer.value || answer.value.stage !== "ready") return window.location.assign("/login");
      name = String(answer.value.name || "");
      $("account-name").textContent = name;
      left(Number(answer.value.recovery_left) || 0);
    }).catch(() => {});
    guard($("password-form"), async () => {
      const password = $("password").value;
      const next = $("next").value;
      const again = $("confirm").value;
      if (next !== again) return say("The two new passwords differ.");
      if ([...next].length < 15) return say("Choose a new password of at least 15 characters.");
      const answer = await sendFresh("/api/password", { password, next });
      if (answer.status === 204) return window.location.assign("/login");
      if (answer.status === 428) return say("Nothing changed. That needs a code from your phone.");
      say(answer.status === 429 ? tooMany : answer.status === 401 ? "The current password does not match." :
        answer.status === 400 ? "Choose a different password: at least 15 characters, not a common one, and not the one you have now." : failed);
    });
    window.addEventListener("pagehide", () => { for (const id of ["password", "next", "confirm", "phone-code"]) $(id).value = ""; });
    $("phone-start").addEventListener("click", async () => {
      say("");
      const answer = await sendFresh("/api/phone", {}).catch(() => null);
      if (answer && answer.status === 200 && showPhone(answer.value)) return;
      say(answer && answer.status === 428 ? "Nothing changed. That needs a code from your phone." : failed);
    });
    guard($("phone-form"), async () => {
      const code = $("phone-code").value.trim();
      $("phone-code").value = "";
      if (!/^\d{6}$/.test(code)) return say("Enter the six digits the new phone shows.");
      const answer = await sendFresh("/api/phone/confirm", { code });
      if (answer.status === 204) {
        $("phone-step").hidden = true;
        return say("Rootwell now uses the new phone. Other browsers are signed out.");
      }
      if (answer.status === 401 && /signed out/i.test(answer.text)) return window.location.assign("/login");
      say(answer.status === 409 ? "Start again with Move to a new phone." : "That code does not match. Check the phone's clock, then enter the code it shows now.");
    });
    const passkeyList = $("passkeys");
    const drawPasskeys = (value) => {
      const list = value && Array.isArray(value.passkeys) ? value.passkeys : [];
      if (!list.length) {
        const empty = document.createElement("li");
        empty.className = "meta";
        empty.textContent = "No passkey yet.";
        return passkeyList.replaceChildren(empty);
      }
      passkeyList.replaceChildren(...list.map((p) => {
        const item = document.createElement("li");
        item.className = "between";
        const label = document.createElement("span");
        label.textContent = String(p.name) + " · added " + String(p.added).slice(0, 10) + (p.last_used ? " · last used " + String(p.last_used).slice(0, 10) : "");
        const remove = document.createElement("button");
        remove.className = "btn btn-ghost btn-sm";
        remove.type = "button";
        remove.textContent = "Remove";
        remove.addEventListener("click", async () => {
          say("");
          const answer = await sendFresh("/api/passkeys/remove", { id: p.id }).catch(() => null);
          if (answer && answer.status === 200) {
            drawPasskeys(answer.value);
            return say("The passkey is removed. Other browsers are signed out.");
          }
          say(answer && answer.status === 428 ? "Nothing changed. That needs a code from your phone." : failed);
        });
        item.append(label, remove);
        return item;
      }));
    };
    void send("/api/passkeys", undefined, "GET").then((answer) => { if (answer.ok) drawPasskeys(answer.value); }).catch(() => {});
    $("passkey-add").hidden = !(globalThis.rootwellPasskey && globalThis.rootwellPasskey.supported());
    $("passkey-add").addEventListener("click", async () => {
      say("");
      const options = await sendFresh("/api/passkeys/options", {}).catch(() => null);
      if (!options || options.status !== 200 || !options.value) {
        return say(options && options.status === 409 ? "Passkeys work on a name, such as localhost, not on an IP address." :
          options && options.status === 428 ? "Nothing changed. That needs a code from your phone." : failed);
      }
      let made;
      try {
        made = await globalThis.rootwellPasskey.create(options.value, $("passkey-name").value.trim());
      } catch {
        return say("No passkey was added.");
      }
      const answer = await send("/api/passkeys", made);
      if (answer.status === 201) {
        $("passkey-name").value = "";
        drawPasskeys(answer.value);
        return say("The passkey is added. Other browsers are signed out.");
      }
      say(answer.status === 409 ? "This passkey is added already, or the account has ten." :
        answer.status === 400 ? "That passkey could not be added. It must ask for your PIN, fingerprint or face." : failed);
    });
    $("codes-new").addEventListener("click", async () => {
      say("");
      const answer = await sendFresh("/api/recovery-codes", {}).catch(() => null);
      if (answer && answer.status === 200 && showCodes(answer.value, name)) return left(10);
      say(answer && answer.status === 428 ? "Nothing changed. That needs a code from your phone." : failed);
    });
  }
  // ── Installation ────────────────────────────────────────────────────────
  if (mode === "installation") {
    void send("/api/installation", undefined, "GET").then((answer) => {
      if (!answer.ok || !answer.value) return say(failed);
      const v = answer.value;
      $("names").textContent = (Array.isArray(v.names) ? v.names : []).join(", ");
      $("fingerprint").textContent = String(v.fingerprint || "");
      $("serving").textContent = "The server certificate renews itself; this one lasts until " + String(v.serving_until || "").slice(0, 10) + ".";
      $("contents").textContent = Number(v.certificates) === 1 ? "1 certificate is saved." : Number(v.certificates) + " certificates are saved.";
    }).catch(() => say(failed));
    // The backup is a file, not JSON: it is fetched and handed to the browser
    // as a download, after a fresh code when Rootwell asks for one.
    const fetchBackup = () => fetch("/api/backup", {
      method: "POST", credentials: "same-origin", cache: "no-store", redirect: "error",
      headers: { "Content-Type": "application/json", "X-Rootwell-Request": "1" }, body: "{}",
    });
    $("backup-download").addEventListener("click", async () => {
      const button = $("backup-download");
      if (button.disabled) return;
      button.disabled = true;
      say("");
      try {
        let response = await fetchBackup();
        if (response.status === 428 && globalThis.rootwellFresh && await globalThis.rootwellFresh()) response = await fetchBackup();
        if (response.status === 428) return say("Nothing was downloaded. A backup needs a code from your phone.");
        if (response.status !== 200) return say(response.status === 507 ? "This vault is too large to download here; copy it on the server with Rootwell stopped." : failed);
        const name = (/filename="([^"]+)"/.exec(response.headers.get("content-disposition") || "") || [])[1] || "rootwell-backup.db";
        const link = document.createElement("a");
        link.href = URL.createObjectURL(await response.blob());
        link.download = name;
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(link.href), 1000);
        say("Downloaded " + name + ". Keep it apart from the instance key's recovery code.");
      } catch {
        say(failed);
      } finally {
        button.disabled = false;
      }
    });
  }
})();
