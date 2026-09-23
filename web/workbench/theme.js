"use strict";

(function () {
  const key = "rootwell-workbench-theme";
  const root = document.documentElement;

  function storedTheme() {
    try {
      const value = window.localStorage.getItem(key);
      return value === "light" || value === "dark" ? value : null;
    } catch {
      return null;
    }
  }

  function currentTheme() {
    const stored = storedTheme();
    if (stored) return stored;
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  const initial = storedTheme();
  if (initial) root.dataset.theme = initial;

  document.addEventListener("DOMContentLoaded", function () {
    const button = document.getElementById("theme-toggle");
    if (!button) return;

    function updateLabel() {
      const next = currentTheme() === "dark" ? "Light" : "Dark";
      button.textContent = next;
      button.setAttribute("aria-label", "Switch to the " + next.toLowerCase() + " colour scheme");
    }

    button.hidden = false;
    updateLabel();
    button.addEventListener("click", function () {
      const next = currentTheme() === "dark" ? "light" : "dark";
      root.dataset.theme = next;
      try {
        window.localStorage.setItem(key, next);
      } catch {
        // The visual change still applies when storage is unavailable.
      }
      updateLabel();
    });
  });
})();
