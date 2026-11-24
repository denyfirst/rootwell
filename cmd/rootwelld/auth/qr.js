"use strict";

// Draws the QR code the server sends, as rows of "0" and "1", into an <svg>:
// one path for the dark modules and a quiet zone of four. Nothing is fetched
// and no style is written, so the strict page policy holds.
(function () {
  const SVG = "http://www.w3.org/2000/svg";

  function valid(rows) {
    if (!Array.isArray(rows) || rows.length < 21 || rows.length > 57) return false;
    return rows.every((row) => typeof row === "string" && row.length === rows.length && /^[01]+$/.test(row));
  }

  globalThis.rootwellQR = function (svg, rows) {
    if (!valid(rows)) return false;
    const size = rows.length;
    let d = "";
    rows.forEach((row, y) => {
      for (let x = 0; x < size; x++) {
        if (row[x] !== "1") continue;
        let run = 1;
        while (x + run < size && row[x + run] === "1") run++;
        d += "M" + x + " " + y + "h" + run + "v1h-" + run + "z";
        x += run - 1;
      }
    });
    const path = document.createElementNS(SVG, "path");
    path.setAttribute("d", d);
    svg.setAttribute("viewBox", "-4 -4 " + (size + 8) + " " + (size + 8));
    svg.setAttribute("shape-rendering", "crispEdges");
    svg.replaceChildren(path);
    return true;
  };

  // The key, for typing by hand: groups of four.
  globalThis.rootwellGroups = function (key) {
    return String(key).replace(/(.{4})(?=.)/g, "$1 ");
  };
})();
