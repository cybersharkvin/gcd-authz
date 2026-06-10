/* Tantalus Desktop OS — Window Manager */
(function() {
  var zTop = 10;
  var winSeq = 0;
  var openWindows = {}; // payloadKey -> windowId
  var selected = null;

  /* ---- helpers ---- */
  function nextId() { return 'win-' + (++winSeq); }

  function clamp(v, lo, hi) { return Math.max(lo, Math.min(hi, v)); }

  /* ---- window creation ---- */
  window.WM = {
    open: function(opts) {
      // opts: { key, title, kind, w, h, htmxGet, htmxPost, body }
      var key = opts.key || opts.title;
      if (openWindows[key]) {
        WM.focus(openWindows[key]);
        return openWindows[key];
      }
      var id = nextId();
      var w = opts.w || 720, h = opts.h || 520;
      var count = Object.keys(openWindows).length;
      var offset = (count % 6) * 28;
      var x = clamp((window.innerWidth - w) / 2 + offset, 40, window.innerWidth - 400);
      var y = clamp((window.innerHeight - h) / 2 - 30 + offset, 40, window.innerHeight - 300);
      zTop++;

      var el = document.createElement('div');
      el.className = 'window';
      el.id = id;
      el.style.cssText = 'left:'+x+'px;top:'+y+'px;width:'+w+'px;height:'+h+'px;z-index:'+zTop;

      var titleParts = opts.title.split(/\.(?=[^.]+$)/);
      var titleMain = titleParts[0];
      var titleExt = titleParts[1] ? '.' + titleParts[1] : '';

      el.innerHTML =
        '<div class="window-chrome">' +
          '<div class="window-spacer"></div>' +
          '<div class="window-title">' + esc(titleMain) + '<span class="ext">' + esc(titleExt) + '</span></div>' +
          '<div class="traffic">' +
            '<span class="min" title="Minimize"></span>' +
            '<span class="max" title="Maximize"></span>' +
            '<span class="close" title="Close"></span>' +
          '</div>' +
        '</div>' +
        '<div class="window-body" id="' + id + '-body">' + (opts.body || '') + '</div>';

      document.body.appendChild(el);
      openWindows[key] = id;

      // Wire events
      var chrome = el.querySelector('.window-chrome');
      initDrag(el, chrome);
      el.querySelector('.traffic .close').onclick = function(e) { e.stopPropagation(); WM.close(key); };
      el.querySelector('.traffic .max').onclick = function(e) {
        e.stopPropagation();
        if (el.dataset.maximized === 'true') {
          el.style.cssText = el.dataset.restore;
          el.dataset.maximized = 'false';
        } else {
          el.dataset.restore = el.style.cssText;
          el.style.cssText = 'left:8px;top:40px;width:'+(window.innerWidth-16)+'px;height:'+(window.innerHeight-56)+'px;z-index:'+zTop;
          el.dataset.maximized = 'true';
        }
      };
      el.onmousedown = function() { WM.focus(id); };

      // If htmxGet specified, trigger HTMX load into body
      if (opts.htmxGet) {
        var body = el.querySelector('.window-body');
        body.setAttribute('hx-get', opts.htmxGet);
        body.setAttribute('hx-trigger', 'load');
        body.setAttribute('hx-swap', 'innerHTML');
        if (typeof htmx !== 'undefined') htmx.process(body);
      }

      return id;
    },

    focus: function(id) {
      var el = document.getElementById(id);
      if (!el) return;
      zTop++;
      el.style.zIndex = zTop;
    },

    close: function(key) {
      var id = openWindows[key];
      if (!id) return;
      var el = document.getElementById(id);
      if (el) {
        el.classList.add('closing');
        setTimeout(function() { el.remove(); }, 260);
      }
      delete openWindows[key];
    },

    isOpen: function(key) { return !!openWindows[key]; },
    getBodyId: function(key) { return openWindows[key] ? openWindows[key] + '-body' : null; }
  };

  /* ---- snap preview ---- */
  var snapEl = document.createElement('div');
  snapEl.className = 'snap-preview';
  document.body.appendChild(snapEl);
  var MENU = 40;

  function getSnapZone(x, y) {
    var w = window.innerWidth, h = window.innerHeight;
    if (x < w * 0.15) return { left: '4px', top: MENU + 'px', width: (w / 2 - 8) + 'px', height: (h - MENU - 8) + 'px', zone: 'left' };
    if (x > w * 0.85) return { left: (w / 2 + 4) + 'px', top: MENU + 'px', width: (w / 2 - 8) + 'px', height: (h - MENU - 8) + 'px', zone: 'right' };
    if (y < MENU + 6) return { left: '4px', top: MENU + 'px', width: (w - 8) + 'px', height: (h - MENU - 8) + 'px', zone: 'max' };
    return null;
  }

  function showSnap(s) {
    if (!s) { snapEl.classList.remove('visible'); return; }
    snapEl.style.left = s.left; snapEl.style.top = s.top;
    snapEl.style.width = s.width; snapEl.style.height = s.height;
    snapEl.classList.add('visible');
  }

  /* ---- drag ---- */
  function initDrag(win, chrome) {
    chrome.addEventListener('mousedown', function(e) {
      if (e.target.closest('.traffic')) return;
      e.preventDefault();

      // If snapped/maximized, un-snap on drag start
      if (win.dataset.maximized === 'true' || win.dataset.snapped) {
        var pct = e.clientX / window.innerWidth;
        var ow = parseInt(win.dataset.restoreW) || 720;
        var oh = parseInt(win.dataset.restoreH) || 520;
        win.classList.add('no-transition');
        win.style.width = ow + 'px';
        win.style.height = oh + 'px';
        win.style.left = clamp(e.clientX - ow * pct, 0, window.innerWidth - 200) + 'px';
        win.style.top = clamp(e.clientY - 14, 32, window.innerHeight - 80) + 'px';
        win.dataset.maximized = 'false';
        delete win.dataset.snapped;
        // Force reflow so no-transition takes effect before we remove it
        void win.offsetHeight;
        win.classList.remove('no-transition');
      }

      var startX = e.clientX, startY = e.clientY;
      var ox = win.offsetLeft, oy = win.offsetTop;
      win.classList.add('no-transition');

      function move(ev) {
        win.style.left = clamp(ox + ev.clientX - startX, 0, window.innerWidth - 200) + 'px';
        win.style.top = clamp(oy + ev.clientY - startY, 32, window.innerHeight - 80) + 'px';
        showSnap(getSnapZone(ev.clientX, ev.clientY));
      }
      function up(ev) {
        window.removeEventListener('mousemove', move);
        window.removeEventListener('mouseup', up);
        document.body.style.cursor = '';
        document.body.style.userSelect = '';
        win.classList.remove('no-transition');
        showSnap(null);

        var snap = getSnapZone(ev.clientX, ev.clientY);
        if (snap) {
          // Save restore dimensions
          win.dataset.restoreW = win.offsetWidth;
          win.dataset.restoreH = win.offsetHeight;
          win.dataset.restore = win.style.cssText;
          win.dataset.snapped = snap.zone;
          if (snap.zone === 'max') {
            win.dataset.maximized = 'true';
          }
          win.style.left = snap.left;
          win.style.top = snap.top;
          win.style.width = snap.width;
          win.style.height = snap.height;
        }
      }
      document.body.style.cursor = 'move';
      document.body.style.userSelect = 'none';
      window.addEventListener('mousemove', move);
      window.addEventListener('mouseup', up);
    });

    /* touch drag for mobile */
    chrome.addEventListener('touchstart', function(e) {
      if (e.target.closest('.traffic')) return;
      var t = e.touches[0];
      if (win.dataset.maximized === 'true' || win.dataset.snapped) {
        win.classList.add('no-transition');
        var ow = parseInt(win.dataset.restoreW) || 720;
        var oh = parseInt(win.dataset.restoreH) || 520;
        win.style.width = Math.min(ow, window.innerWidth - 16) + 'px';
        win.style.height = Math.min(oh, window.innerHeight - 60) + 'px';
        win.style.left = clamp(t.clientX - ow * 0.5, 0, window.innerWidth - 200) + 'px';
        win.style.top = clamp(t.clientY - 14, 32, window.innerHeight - 80) + 'px';
        win.dataset.maximized = 'false';
        delete win.dataset.snapped;
        void win.offsetHeight;
        win.classList.remove('no-transition');
      }
      var startX = t.clientX, startY = t.clientY;
      var ox = win.offsetLeft, oy = win.offsetTop;
      win.classList.add('no-transition');
      WM.focus(win.id);

      function tmove(e) {
        e.preventDefault();
        var t = e.touches[0];
        win.style.left = clamp(ox + t.clientX - startX, 0, window.innerWidth - 200) + 'px';
        win.style.top = clamp(oy + t.clientY - startY, 32, window.innerHeight - 80) + 'px';
      }
      function tend() {
        window.removeEventListener('touchmove', tmove);
        window.removeEventListener('touchend', tend);
        win.classList.remove('no-transition');
      }
      window.addEventListener('touchmove', tmove, { passive: false });
      window.addEventListener('touchend', tend);
    }, { passive: true });
  }

  /* ---- ESC to close top window ---- */
  document.addEventListener('keydown', function(e) {
    if (e.key !== 'Escape') return;
    var topZ = 0, topKey = null;
    for (var k in openWindows) {
      var el = document.getElementById(openWindows[k]);
      if (el && parseInt(el.style.zIndex) > topZ) {
        topZ = parseInt(el.style.zIndex);
        topKey = k;
      }
    }
    if (topKey) WM.close(topKey);
  });

  /* ---- desktop icon selection ---- */
  document.addEventListener('click', function(e) {
    if (!e.target.closest('.file-icon')) {
      document.querySelectorAll('.file-icon[data-selected="true"]').forEach(function(el) {
        el.dataset.selected = 'false';
      });
      selected = null;
    }
  });

  window.selectIcon = function(el) {
    document.querySelectorAll('.file-icon[data-selected="true"]').forEach(function(e) {
      e.dataset.selected = 'false';
    });
    el.dataset.selected = 'true';
  };

  /* ---- html escape ---- */
  function esc(s) { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

  /* ---- markdown renderer ---- */
  window.renderMd = function(s) {
    s = s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    s = s.replace(/```(\w*)\n([\s\S]*?)```/g, function(m, lang, code) {
      return "<pre><code>" + code.trim() + "</code></pre>";
    });
    s = s.replace(/`([^`]+)`/g, "<code>$1</code>");
    s = s.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
    s = s.replace(/\*(.+?)\*/g, "<em>$1</em>");
    s = s.replace(/^### (.+)$/gm, "<h3>$1</h3>");
    s = s.replace(/^## (.+)$/gm, "<h2>$1</h2>");
    s = s.replace(/^# (.+)$/gm, "<h1>$1</h1>");
    var blocks = s.split(/\n\n+/);
    var out = "";
    for (var i = 0; i < blocks.length; i++) {
      var b = blocks[i].trim();
      if (!b) continue;
      if (b.indexOf("<pre>") === 0 || b.indexOf("<h") === 0) { out += b; continue; }
      var lines = b.split("\n");
      var isList = true, ordered = false;
      for (var j = 0; j < lines.length; j++) {
        var l = lines[j].trim();
        if (!l) continue;
        if (/^\d+[.)]\s/.test(l)) ordered = true;
        else if (/^[-*]\s/.test(l)) {}
        else { isList = false; break; }
      }
      if (isList && lines.length > 0) {
        var tag = ordered ? "ol" : "ul";
        out += "<" + tag + ">";
        for (var j = 0; j < lines.length; j++) {
          var l = lines[j].trim();
          if (!l) continue;
          out += "<li>" + l.replace(/^(\d+[.)]\s|[-*]\s)/, "") + "</li>";
        }
        out += "</" + tag + ">";
      } else {
        out += "<p>" + b.replace(/\n/g, "<br>") + "</p>";
      }
    }
    return out;
  };

  /* ---- JSON syntax highlight ---- */
  window.highlightJson = function(el) {
    if (!el || !el.textContent.trim()) return;
    var raw = el.textContent;
    el.innerHTML = raw
      .replace(/"([^"\\]*(\\.[^"\\]*)*)"(\s*:)?/g, function(m, key, esc, colon) {
        if (colon) return '<span class="json-key">"' + key + '"</span>:';
        return '<span class="json-string">"' + key + '"</span>';
      })
      .replace(/\b(-?\d+\.?\d*([eE][+-]?\d+)?)\b/g, '<span class="json-number">$1</span>')
      .replace(/\b(true|false)\b/g, '<span class="json-bool">$1</span>')
      .replace(/\bnull\b/g, '<span class="json-null">null</span>');
  };

  /* ---- render markdown on messages ---- */
  window.renderMessages = function(root) {
    var msgs = (root || document).querySelectorAll('.message-assistant:not([data-md]), .msg-bubble.assistant:not([data-md])');
    for (var i = 0; i < msgs.length; i++) {
      var el = msgs[i];
      if (el.querySelector('.blocked-badge')) {
        var badge = el.querySelector('.blocked-badge').outerHTML;
        el.innerHTML = badge + renderMd(el.textContent.trim());
      } else {
        el.innerHTML = renderMd(el.textContent.trim());
      }
      el.setAttribute('data-md', '1');
    }
  };

  /* ---- reasoning toggle ---- */
  window.toggleReasoning = function(trigger) {
    trigger.parentElement.classList.toggle('open');
  };

  /* ---- HTMX hooks ---- */
  document.body.addEventListener('htmx:afterSwap', function() {
    renderMessages();
    var md = document.getElementById('modal-md');
    if (md && !md.getAttribute('data-md')) {
      md.innerHTML = renderMd(md.textContent.trim());
      md.setAttribute('data-md', '1');
    }
  });
  document.body.addEventListener('htmx:oobAfterSwap', function() {
    renderMessages();
    var jv = document.getElementById('json-viewer');
    if (jv) {
      highlightJson(jv);
      try {
        var trace = JSON.parse(jv.textContent);
        if (Array.isArray(trace)) {
          for (var i = trace.length - 1; i >= 0; i--) {
            if (trace[i].tool_call && window._toolVerbMap && window._toolVerbMap[trace[i].tool_call]) {
              window._lastToolVerb = window._toolVerbMap[trace[i].tool_call];
              break;
            }
          }
        }
      } catch(e) {}
    }
  });

  /* ---- clock ---- */
  function updateClock() {
    var el = document.getElementById('menubar-clock');
    if (el) el.textContent = new Date().toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
  }
  /* ---- desktop icon drag ---- */
  function initIconDrag() {
    var icons = document.querySelectorAll('.desktop > .file-icon');
    var THRESHOLD = 5;
    icons.forEach(function(icon) {
      icon.addEventListener('mousedown', function(e) {
        if (e.button !== 0) return;
        var startX = e.clientX, startY = e.clientY;
        var ox = icon.offsetLeft, oy = icon.offsetTop;
        var dragging = false;

        function move(ev) {
          var dx = ev.clientX - startX, dy = ev.clientY - startY;
          if (!dragging && Math.abs(dx) + Math.abs(dy) < THRESHOLD) return;
          if (!dragging) { dragging = true; icon.classList.add('dragging'); }
          var desk = icon.parentElement;
          icon.style.left = clamp(ox + dx, 0, desk.clientWidth - 48) + 'px';
          icon.style.top = clamp(oy + dy, 0, desk.clientHeight - 48) + 'px';
        }
        function up() {
          window.removeEventListener('mousemove', move);
          window.removeEventListener('mouseup', up);
          if (dragging) {
            icon.classList.remove('dragging');
            // Suppress the click/dblclick that follows mouseup after drag
            var suppress = function(e) { e.stopPropagation(); e.preventDefault(); };
            icon.addEventListener('click', suppress, { capture: true, once: true });
            icon.addEventListener('dblclick', suppress, { capture: true, once: true });
          }
        }
        window.addEventListener('mousemove', move);
        window.addEventListener('mouseup', up);
      });

      icon.addEventListener('touchstart', function(e) {
        var t = e.touches[0];
        var startX = t.clientX, startY = t.clientY;
        var ox = icon.offsetLeft, oy = icon.offsetTop;
        var dragging = false;

        function tmove(ev) {
          var t = ev.touches[0];
          var dx = t.clientX - startX, dy = t.clientY - startY;
          if (!dragging && Math.abs(dx) + Math.abs(dy) < THRESHOLD) return;
          if (!dragging) { dragging = true; icon.classList.add('dragging'); }
          ev.preventDefault();
          var desk = icon.parentElement;
          icon.style.left = clamp(ox + dx, 0, desk.clientWidth - 48) + 'px';
          icon.style.top = clamp(oy + dy, 0, desk.clientHeight - 48) + 'px';
        }
        function tend() {
          window.removeEventListener('touchmove', tmove);
          window.removeEventListener('touchend', tend);
          icon.classList.remove('dragging');
        }
        window.addEventListener('touchmove', tmove, { passive: false });
        window.addEventListener('touchend', tend);
      }, { passive: true });
    });
  }
  initIconDrag();

  setInterval(updateClock, 30000);
  setTimeout(updateClock, 100);

})();
