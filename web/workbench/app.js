"use strict";

(function () {
  const tabs = Array.from(document.querySelectorAll("[data-tool]"));
  const panels = {
    inspect: document.getElementById("inspect-panel"),
    verify: document.getElementById("verify-panel")
  };
  const path = document.getElementById("page-path");

  function selectTool(name) {
    tabs.forEach(function (tab) {
      const selected = tab.dataset.tool === name;
      tab.setAttribute("aria-selected", selected ? "true" : "false");
    });
    Object.keys(panels).forEach(function (panelName) {
      panels[panelName].hidden = panelName !== name;
    });
    path.textContent = name === "verify" ? "Verify" : "Inspect";
  }

  tabs.forEach(function (tab) {
    tab.addEventListener("click", function () {
      selectTool(tab.dataset.tool);
    });
  });

  function formatSize(size) {
    if (size < 1024) return size + " B";
    if (size < 1024 * 1024) return (size / 1024).toFixed(1) + " KiB";
    return (size / (1024 * 1024)).toFixed(1) + " MiB";
  }

  function showSelection(input, output) {
    const file = input.files && input.files.length === 1 ? input.files[0] : null;
    output.textContent = file ? file.name + " · " + formatSize(file.size) : "No file selected";
  }

  [
    ["inspect-file", "inspect-file-state"],
    ["verify-leaf", "verify-leaf-state"],
    ["verify-roots", "verify-roots-state"],
    ["verify-intermediates", "verify-intermediates-state"]
  ].forEach(function (binding) {
    const input = document.getElementById(binding[0]);
    const output = document.getElementById(binding[1]);
    input.addEventListener("change", function () {
      showSelection(input, output);
    });
  });

  document.querySelectorAll("[data-drop-target]").forEach(function (zone) {
    const input = document.getElementById(zone.dataset.dropTarget);
    const output = document.getElementById(input.id + "-state");

    ["dragenter", "dragover"].forEach(function (eventName) {
      zone.addEventListener(eventName, function (event) {
        event.preventDefault();
        zone.classList.add("is-dragging");
      });
    });
    ["dragleave", "drop"].forEach(function (eventName) {
      zone.addEventListener(eventName, function (event) {
        event.preventDefault();
        zone.classList.remove("is-dragging");
      });
    });
    zone.addEventListener("drop", function (event) {
      if (!event.dataTransfer || event.dataTransfer.files.length !== 1) {
        output.textContent = "Choose exactly one file";
        return;
      }
      const file = event.dataTransfer.files[0];
      output.textContent = file.name + " · " + formatSize(file.size) + " · preview only";
    });
  });

  document.querySelectorAll("[data-show-sample]").forEach(function (button) {
    button.addEventListener("click", function () {
      const result = document.getElementById(button.dataset.showSample);
      const opening = result.hidden;
      result.hidden = !opening;
      button.textContent = opening ? "Hide sample result" : "Show sample result";
      if (opening) result.scrollIntoView({ block: "nearest" });
    });
  });
})();
