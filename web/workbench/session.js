"use strict";

// Sign out, from the rail of every workspace page. This script reads no file
// and holds no secret: it asks the server to end the session, and leaves the
// page only when the server confirms it, so a failure never looks like a
// sign-out.
(function () {
  document.addEventListener("DOMContentLoaded", function () {
    const button = document.getElementById("rail-sign-out");
    if (!button) return;
    const label = button.querySelector("span");
    button.hidden = false;
    button.addEventListener("click", async function () {
      if (button.disabled) return;
      button.disabled = true;
      try {
        const response = await window.fetch("/api/session", {
          method: "DELETE", headers: { "X-Rootwell-Request": "1" },
          credentials: "same-origin", cache: "no-store", redirect: "error",
        });
        if (response.status === 204) {
          window.location.assign("/login");
          return;
        }
      } catch {
        // Reported below.
      }
      if (label) label.textContent = "Sign out failed; try again";
      button.disabled = false;
    });
  });
})();
