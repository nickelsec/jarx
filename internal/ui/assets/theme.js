// Sets the theme before the page paints, so it never flashes the wrong
// one. Dark unless this browser picked light.
(function () {
  "use strict";
  var theme = "dark";
  try { theme = localStorage.getItem("jarx-theme") === "light" ? "light" : "dark"; } catch (e) { /* storage off */ }
  document.documentElement.setAttribute("data-theme", theme);
})();
