// jarx dashboard. Every page works without this file; it only adds
// conveniences. It's the only script the CSP allows.
(function () {
  "use strict";

  var facets = function () { return document.querySelectorAll("details.facet"); };
  var closeFacets = function () { facets().forEach(function (d) { d.open = false; }); };

  // One facet menu open at a time. "toggle" doesn't bubble, so listen on
  // the way down: it keeps working after a swap.
  document.addEventListener("toggle", function (e) {
    var d = e.target;
    if (!d.classList || !d.classList.contains("facet") || !d.open) return;
    facets().forEach(function (o) { if (o !== d) o.open = false; });
  }, true);

  // In-place navigation. Every link and GET form inside the dashboard
  // (pages, projects, filters, page numbers, search) fetches the new view
  // and swaps the page's main part instead of reloading, and the sidebar
  // marks where you are. The URL still changes, so back, forward and reload
  // work. Without fetch, everything reloads as before.
  var canSwap = !!(window.fetch && window.DOMParser && window.history && history.pushState && window.AbortController);
  var inflight = null;

  var fetchDoc = function (url) {
    if (inflight) inflight.abort();
    inflight = new AbortController();
    return fetch(url, { credentials: "same-origin", signal: inflight.signal })
      .then(function (r) { return r.ok ? r.text() : Promise.reject(r.status); })
      .then(function (html) { return new DOMParser().parseFromString(html, "text/html"); });
  };

  var busy = function (on) {
    var t = document.getElementById("findings");
    if (t) t.classList.toggle("busy", on);
  };

  // syncSide copies which sidebar link is current from the new page, and
  // opens View all when that link is behind it.
  var syncSide = function (doc) {
    var now = document.querySelector("aside.side");
    var next = doc.querySelector("aside.side");
    if (!now || !next) return;
    now.querySelectorAll("[aria-current]").forEach(function (el) { el.removeAttribute("aria-current"); });
    next.querySelectorAll("a[aria-current]").forEach(function (el) {
      now.querySelectorAll("a[href]").forEach(function (m) {
        if (m.getAttribute("href") !== el.getAttribute("href")) return;
        m.setAttribute("aria-current", el.getAttribute("aria-current"));
        var more = m.closest("details.more");
        if (more) more.open = true;
      });
    });
  };

  var navigate = function (url, push, toTop) {
    busy(true);
    fetchDoc(url).then(function (doc) {
      var now = document.querySelector("main.main");
      var next = doc.querySelector("main.main");
      if (!now || !next) { location.href = url; return; }
      var focusID = document.activeElement && document.activeElement.id;
      now.replaceChildren.apply(now, Array.prototype.map.call(next.childNodes, function (n) { return document.importNode(n, true); }));
      document.title = doc.title;
      syncSide(doc);
      initPage();
      if (push) history.pushState(null, "", url); else history.replaceState(null, "", url);
      if (focusID) {
        var el = document.getElementById(focusID);
        if (el) { el.focus(); if (el.setSelectionRange && el.value) el.setSelectionRange(el.value.length, el.value.length); }
      }
      if (toTop) window.scrollTo(0, 0);
    }).catch(function (err) {
      if (err && err.name === "AbortError") return;
      location.href = url;
    });
  };

  // inApp is a URL the dashboard serves as a page: same origin, not a file.
  var inApp = function (u) { return u.origin === location.origin && u.pathname.indexOf("/static/") !== 0; };

  var formURL = function (form) {
    var params = new URLSearchParams(new FormData(form));
    if (params.has("q") && !params.get("q").trim()) params.delete("q");
    var qs = params.toString();
    return (form.getAttribute("action") || location.pathname) + (qs ? "?" + qs : "");
  };

  var submitInPlace = function (form) {
    var url = formURL(form);
    var u = new URL(url, location.href);
    if (!canSwap || !inApp(u)) { form.submit(); return; }
    closeFacets();
    navigate(url, true, u.pathname !== location.pathname);
  };

  document.addEventListener("click", function (e) {
    // A click outside an open menu closes it.
    facets().forEach(function (d) { if (d.open && !d.contains(e.target)) d.open = false; });

    // A finding's row opens its modal. A click on the backdrop, which is
    // the dialog itself outside its box, closes it; so do X and Escape.
    var opener = e.target.closest && e.target.closest("[data-open]");
    if (opener) {
      var dlg = document.getElementById(opener.getAttribute("data-open"));
      if (dlg && dlg.showModal) { dlg.showModal(); dlg.focus(); return; }
    }
    if (e.target.tagName === "DIALOG" && e.target.open) { e.target.close(); return; }

    if (!canSwap || e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    var a = e.target.closest && e.target.closest("a[href]");
    if (!a || a.target || a.hasAttribute("download")) return;
    var u = new URL(a.href, location.href);
    if (!inApp(u)) return;
    e.preventDefault();
    closeFacets();
    navigate(u.pathname + u.search, true, !!a.closest(".pager") || u.pathname !== location.pathname);
  });

  document.addEventListener("submit", function (e) {
    var form = e.target;
    if (!canSwap || (form.method || "get").toLowerCase() !== "get") return;
    if (!inApp(new URL(formURL(form), location.href))) return;
    e.preventDefault();
    submitInPlace(form);
  });

  window.addEventListener("popstate", function () {
    if (canSwap) navigate(location.pathname + location.search, false, false);
  });

  // Rows per page applies as soon as it changes.
  document.addEventListener("change", function (e) {
    var s = e.target;
    if (s.hasAttribute && s.hasAttribute("data-autosubmit") && s.form) submitInPlace(s.form);
  });

  // Live search: as you type, swap in the matching table and filter menus,
  // leaving the search box alone so typing isn't interrupted.
  var timer = 0;
  document.addEventListener("input", function (e) {
    var search = e.target;
    if (!canSwap || !search.hasAttribute || !search.hasAttribute("data-search") || !search.form) return;
    clearTimeout(timer);
    timer = setTimeout(function () {
      var url = formURL(search.form);
      busy(true);
      fetchDoc(url).then(function (doc) {
        ["#findings", "[data-facets]"].forEach(function (sel) {
          var now = document.querySelector(sel);
          var next = doc.querySelector(sel);
          if (now && next) now.replaceWith(document.importNode(next, true));
        });
        history.replaceState(null, "", url);
      }).catch(function () { busy(false); });
    }, 200);
  });

  document.addEventListener("keydown", function (e) {
    // Escape closes an open menu.
    if (e.key === "Escape") { closeFacets(); return; }
    // "/" focuses search.
    if (e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey) return;
    var t = e.target;
    if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable)) return;
    var search = document.querySelector("[data-search]");
    if (!search) return;
    e.preventDefault();
    search.focus();
    search.select();
  });

  // Copy path: the file's path to the clipboard, so it can be opened
  // locally. 127.0.0.1 counts as a secure origin, so the clipboard works.
  document.addEventListener("click", function (e) {
    var b = e.target.closest && e.target.closest("[data-copy]");
    if (!b) return;
    var text = b.getAttribute("data-copy");
    var label = b.querySelector("span");
    var done = function () {
      b.classList.add("done");
      if (label) label.textContent = "Copied";
      setTimeout(function () { b.classList.remove("done"); if (label) label.textContent = "Copy path"; }, 1500);
    };
    // The older way, for when the clipboard API isn't allowed. The text
    // area goes inside the open dialog, the one place that takes focus.
    var fallback = function () {
      var t = document.createElement("textarea");
      t.value = text;
      t.setAttribute("readonly", "");
      t.className = "sr";
      (b.closest("dialog") || document.body).appendChild(t);
      t.select();
      var ok = false;
      try { ok = document.execCommand("copy"); } catch (err) { ok = false; }
      t.remove();
      if (ok) done();
    };
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, fallback);
    else fallback();
  });

  // A link to one finding opens it by itself, on load and after a swap.
  var autoOpen = function () {
    var d = document.querySelector("dialog[data-autoopen]");
    if (d && d.showModal && !d.open) { d.showModal(); d.focus(); }
  };
  autoOpen();
  new MutationObserver(function () { autoOpen(); }).observe(document.querySelector("main") || document.body, { childList: true });

  // Light or dark. theme.js set it before paint; this flips and remembers.
  var toggle = document.querySelector("[data-theme-toggle]");
  if (toggle) {
    var root = document.documentElement;
    var label = function () {
      toggle.setAttribute("aria-label", root.getAttribute("data-theme") === "light" ? "Switch to dark mode" : "Switch to light mode");
    };
    label();
    toggle.addEventListener("click", function () {
      var next = root.getAttribute("data-theme") === "light" ? "dark" : "light";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem("jarx-theme", next); } catch (err) { /* storage off */ }
      label();
    });
  }

  // "All" checks or unchecks every artifact on the LLM review page. It runs
  // on load and after every swap, once per checkbox.
  var initPage = function () {
  document.querySelectorAll("[data-check-all]:not([data-ready])").forEach(function (all) {
    all.setAttribute("data-ready", "");
    var form = all.closest("form");
    var boxes = form ? form.querySelectorAll('input[name="a"]') : [];
    var sync = function () {
      var on = 0;
      boxes.forEach(function (b) { if (b.checked) on++; });
      all.checked = on === boxes.length && on > 0;
      all.indeterminate = on > 0 && on < boxes.length;
    };
    all.addEventListener("change", function () {
      boxes.forEach(function (b) { b.checked = all.checked; });
    });
    boxes.forEach(function (b) { b.addEventListener("change", sync); });
    sync();
  });
  };
  initPage();
})();
