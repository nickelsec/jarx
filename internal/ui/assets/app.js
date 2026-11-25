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

  // dropMsg takes a notice's msg out of the address bar once it shows, so
  // a reload or a copied link doesn't show it again.
  var dropMsg = function () {
    var u = new URL(location.href);
    if (!u.searchParams.has("msg")) return;
    u.searchParams.delete("msg");
    history.replaceState(null, "", u.pathname + u.search);
  };
  dropMsg();

  // A swap that takes a moment shows a skeleton of a page instead of the
  // old one sitting still. Quick ones never show it.
  var skelTimer = 0;
  var skeleton = function () {
    var main = document.querySelector("main.main");
    if (!main || main.querySelector(".skeleton")) return;
    var sk = document.createElement("div");
    sk.className = "skeleton";
    sk.setAttribute("aria-hidden", "true");
    var add = function (parent, cls) { var e = document.createElement("div"); e.className = cls; parent.appendChild(e); return e; };
    add(sk, "sk sk-title");
    add(sk, "sk sk-sub");
    var cards = add(sk, "sk-cards");
    for (var i = 0; i < 3; i++) add(cards, "sk sk-card");
    var rows = add(sk, "sk-rows");
    for (var j = 0; j < 7; j++) add(rows, "sk sk-row");
    main.prepend(sk);
    main.classList.add("loading");
  };
  var loading = function () {
    clearTimeout(skelTimer);
    skelTimer = setTimeout(skeleton, 150);
  };
  var loaded = function () {
    clearTimeout(skelTimer);
    var main = document.querySelector("main.main");
    if (!main) return;
    main.classList.remove("loading");
    var sk = main.querySelector(".skeleton");
    if (sk) sk.remove();
  };

  // swapDoc puts a fetched page in place of this one.
  var swapDoc = function (doc, url, push, toTop) {
    loaded();
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
    // A link to a part of a page (like #scan-history) lands on it.
    var hash = url.indexOf("#") >= 0 ? url.slice(url.indexOf("#") + 1) : "";
    var target = hash && document.getElementById(hash);
    if (target) target.scrollIntoView({ block: "start" });
    else if (toTop) window.scrollTo(0, 0);
    dropMsg();
  };

  var navigate = function (url, push, toTop) {
    busy(true);
    loading();
    fetchDoc(url).then(function (doc) { swapDoc(doc, url, push, toTop); }).catch(function (err) {
      if (err && err.name === "AbortError") return;
      location.href = url;
    });
  };

  // postInPlace sends a POST form (rescan, add or remove a repo) and swaps
  // in the page it lands on. Its button says what's happening meanwhile.
  // If the fetch fails, the form posts the usual way.
  var postInPlace = function (form, submitter) {
    var btn = form.querySelector('button[type="submit"]');
    var label = btn && btn.querySelector("span");
    if (btn) {
      btn.disabled = true;
      btn.classList.add("busy");
      if (label && form.getAttribute("data-busy")) label.textContent = form.getAttribute("data-busy");
    }
    if (inflight) inflight.abort();
    inflight = new AbortController();
    loading();
    var action = (submitter && submitter.getAttribute("formaction")) || form.getAttribute("action");
    var body = new URLSearchParams(new FormData(form, submitter || undefined));
    if (form.id === "review" && picks) {
      body.delete("a");
      picks.forEach(function (k) { body.append("a", k); });
      try { sessionStorage.removeItem(picksKey); } catch (err) { /* storage off */ }
    }
    fetch(action, { method: "POST", body: body, credentials: "same-origin", signal: inflight.signal })
      .then(function (r) {
        if (!r.ok) return Promise.reject(r.status);
        var u = new URL(r.url);
        return r.text().then(function (html) { swapDoc(new DOMParser().parseFromString(html, "text/html"), u.pathname + u.search, true, false); });
      })
      .catch(function (err) {
        if (err && err.name === "AbortError") return;
        form.submit();
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
      if (dlg && dlg.id === "review-confirm") fillSend(dlg);
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
    navigate(u.pathname + u.search + u.hash, true, !!a.closest(".pager") || u.pathname !== location.pathname);
  });

  document.addEventListener("submit", function (e) {
    var form = e.target;
    var method = (form.method || "get").toLowerCase();
    var target = (e.submitter && e.submitter.getAttribute("formaction")) || form.getAttribute("action") || location.pathname;
    if (canSwap && method === "post" && inApp(new URL(target, location.href))) {
      e.preventDefault();
      postInPlace(form, e.submitter);
      return;
    }
    if (!canSwap || method !== "get") return;
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

  // Toasts: a short note in the top right after an action or a scan. X
  // dismisses one, and each fades on its own after a while.
  var dismiss = function (t) {
    t.classList.add("out");
    setTimeout(function () { t.remove(); }, 250);
  };
  var showToast = function (text, bad) {
    var box = document.querySelector(".toasts");
    if (!box) { box = document.createElement("div"); box.className = "toasts"; document.body.appendChild(box); }
    var t = document.createElement("div");
    t.className = "toast" + (bad ? " bad" : "");
    t.setAttribute("role", "status");
    var ns = "http://www.w3.org/2000/svg";
    var icon = document.createElementNS(ns, "svg");
    icon.setAttribute("viewBox", "0 0 24 24");
    icon.setAttribute("aria-hidden", "true");
    var path = document.createElementNS(ns, "path");
    path.setAttribute("d", bad ? "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 8v4.5M12 16h.01" : "M5 12.5l4.5 4.5L19 7.5");
    icon.appendChild(path);
    var span = document.createElement("span");
    span.className = "toast-text";
    span.textContent = text;
    var x = document.createElement("button");
    x.type = "button";
    x.className = "toast-x";
    x.setAttribute("aria-label", "Dismiss");
    var xi = document.createElementNS(ns, "svg");
    xi.setAttribute("viewBox", "0 0 24 24");
    xi.setAttribute("aria-hidden", "true");
    var xp = document.createElementNS(ns, "path");
    xp.setAttribute("d", "M6 6l12 12M18 6L6 18");
    xi.appendChild(xp);
    x.appendChild(xi);
    t.appendChild(icon); t.appendChild(span); t.appendChild(x);
    box.appendChild(t);
    setTimeout(function () { dismiss(t); }, 6000);
  };
  document.addEventListener("click", function (e) {
    var x = e.target.closest && e.target.closest(".toast-x");
    if (x) dismiss(x.closest(".toast"));
  });

  // A running rescan: any page that says one is running asks every second
  // or so until it's done, then says so and shows the new results in place.
  // A running review is watched the same way, with its progress bar on
  // the LLM review page.
  var watching = false;
  var watchScan = function () {
    var scan = !!document.querySelector('[data-scan="running"]');
    var rev = !!document.querySelector('[data-review="running"]');
    if (watching || !canSwap || (!scan && !rev)) return;
    watching = true;
    var poll = function () {
      fetch("/rescan/status", { credentials: "same-origin", cache: "no-store" })
        .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
        .then(function (st) {
          var rv = st.review || {};
          if (st.running) showSteps(st);
          if (rv.running) showReview(rv);
          if ((scan && st.running) || (rev && rv.running)) { setTimeout(poll, 700); return; }
          watching = false;
          if (scan) showToast(st.failed ? "Scan failed" : "Scan complete", st.failed);
          if (rev) showToast(rv.note || "Review complete", !!rv.note);
          navigate(location.pathname + location.search, false, false);
        })
        .catch(function () { setTimeout(poll, 3000); });
    };
    setTimeout(poll, 700);
  };

  // showReview moves the LLM review page's progress along.
  var showReview = function (rv) {
    var bar = document.querySelector("[data-review-bar]");
    if (bar) { bar.max = rv.total; bar.value = rv.done; }
    var count = document.querySelector("[data-review-count]");
    if (count) count.textContent = rv.done + " of " + rv.total;
    var wait = document.querySelector("[data-review-wait]");
    if (wait) wait.textContent = rv.waiting ? rv.waiting + " waiting on a rate limit" : "";
  };

  // fillSend says, in the confirmation, how many checked artifacts would go
  // and about how many tokens. Send is off when nothing is checked.
  var fillSend = function (dlg) {
    var n = 0, tokens = 0;
    arts.forEach(function (a) {
      if (picks && picks.has(a.key)) { n++; tokens += a.tokens; }
    });
    var c = dlg.querySelector("[data-send-count]");
    if (c) c.textContent = n;
    var noun = dlg.querySelector("[data-send-noun]");
    if (noun) noun.textContent = n === 1 ? "artifact" : "artifacts";
    var t = dlg.querySelector("[data-send-tokens]");
    if (t) t.textContent = tokens.toLocaleString();
    var send = dlg.querySelector('button[form="review"]');
    if (send) send.disabled = n === 0;
  };

  // showSteps marks the Scan page's steps done, now or to come, from a
  // status answer, with the current step's count.
  var showSteps = function (st) {
    var list = document.querySelectorAll("[data-progress] [data-step]");
    var at = (st.steps || []).indexOf(st.step);
    list.forEach(function (li, i) {
      li.className = "step" + (i < at ? " done" : i === at ? " now" : "");
      var count = li.querySelector(".step-count");
      if (i === at && st.stepTotal > 0) {
        if (!count) { count = document.createElement("span"); count.className = "step-count"; li.appendChild(count); }
        count.textContent = st.stepDone + "/" + st.stepTotal;
      } else if (count) {
        count.remove();
      }
    });
  };

  // The Scan page counts the seconds while a scan runs.
  var elapsedFrom = 0;
  setInterval(function () {
    var el = document.querySelector("[data-elapsed]");
    if (!el) { elapsedFrom = 0; return; }
    if (!elapsedFrom) elapsedFrom = Date.now();
    el.textContent = Math.round((Date.now() - elapsedFrom) / 1000) + "s";
  }, 500);

  // Closing a dialog that a URL opened (the folder browser) takes it out of
  // the URL, so a reload doesn't open it again.
  document.addEventListener("close", function (e) {
    var d = e.target;
    var key = d.getAttribute && d.getAttribute("data-strip");
    if (!key) return;
    var u = new URL(location.href);
    u.searchParams.delete(key);
    history.replaceState(null, "", u.pathname + u.search);
  }, true);

  // The LLM review checklist's picks: every artifact, on every page, as
  // the page lists them in data-arts. They start as the page checks them
  // (new and failed ones) and are kept for the session as you page, so
  // "All" means all of them and Send, Skip and Unskip send every pick.
  var picks = null;
  var arts = [];
  var picksKey = "jarx-llm-picks";
  var initPicks = function () {
    var form = document.getElementById("review");
    if (!form) { picks = null; arts = []; return; }
    arts = (form.getAttribute("data-arts") || "").split(" ").filter(Boolean).map(function (s) {
      var p = s.split(":");
      return { key: p[0], tokens: parseInt(p[1], 10) || 0, state: p[2] };
    });
    var sig = arts.map(function (a) { return a.key.slice(0, 12) + a.state; }).join(",");
    var stored = null;
    try { stored = JSON.parse(sessionStorage.getItem(picksKey) || "null"); } catch (err) { stored = null; }
    var known = {};
    arts.forEach(function (a) { known[a.key] = true; });
    if (stored && stored.sig === sig) {
      picks = new Set(stored.keys.filter(function (k) { return known[k]; }));
    } else {
      picks = new Set(arts.filter(function (a) { return a.state === "new" || a.state === "failed"; }).map(function (a) { return a.key; }));
    }
    picks.sig = sig;
    showPicks();
  };
  // sendable is every artifact that isn't skipped: what "All" checks.
  var sendable = function () { return arts.filter(function (a) { return a.state !== "skipped"; }); };
  var savePicks = function () {
    if (!picks) return;
    try { sessionStorage.setItem(picksKey, JSON.stringify({ sig: picks.sig, keys: Array.from(picks) })); } catch (err) { /* storage off */ }
  };
  var showPicks = function () {
    if (!picks) return;
    document.querySelectorAll('#review input[name="a"]').forEach(function (b) { b.checked = picks.has(b.value); });
    var all = document.querySelector("[data-check-all]");
    var n = sendable().length;
    if (all) {
      all.checked = n > 0 && picks.size >= n;
      all.indeterminate = picks.size > 0 && picks.size < n;
    }
    var label = document.querySelector("[data-picked]");
    if (label) label.textContent = picks.size ? " · " + picks.size + " checked" : "";
  };
  document.addEventListener("change", function (e) {
    var t = e.target;
    if (!picks || !t.closest || !t.closest("#review")) return;
    if (t.hasAttribute("data-check-all")) {
      picks = Object.assign(new Set(t.checked ? sendable().map(function (a) { return a.key; }) : []), { sig: picks.sig });
    } else if (t.name === "a") {
      if (t.checked) picks.add(t.value); else picks.delete(t.value);
    } else {
      return;
    }
    savePicks();
    showPicks();
  });
  // Rerun failed checks just the ones that failed last time, then asks.
  document.addEventListener("click", function (e) {
    if (!picks || !e.target.closest || !e.target.closest("[data-rerun]")) return;
    picks = Object.assign(new Set(arts.filter(function (a) { return a.state === "failed"; }).map(function (a) { return a.key; })), { sig: picks.sig });
    savePicks();
    showPicks();
    var dlg = document.getElementById("review-confirm");
    if (dlg && dlg.showModal) { fillSend(dlg); dlg.showModal(); dlg.focus(); }
  });

  // Each page's own toasts fade, the scan and review watch starts, and the
  // checklist's picks show. It runs on load and after every swap.
  var initPage = function () {
    document.querySelectorAll(".toast:not([data-ready])").forEach(function (t) {
      t.setAttribute("data-ready", "");
      setTimeout(function () { dismiss(t); }, 6000);
    });
    watchScan();
    initPicks();
  };
  initPage();
})();
