/* SentinelGo project website: progressive enhancement only.
   The page is fully readable without this script. */
(function () {
  'use strict';

  var doc = document.documentElement;
  var motionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
  var reduceMotion = motionQuery.matches;

  function $(sel, root) { return (root || document).querySelector(sel); }
  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
  function store(key, val) {
    try { if (val === undefined) return localStorage.getItem(key); localStorage.setItem(key, val); } catch (e) { return null; }
  }

  /* ---------- Theme toggle ---------- */
  function effectiveTheme() {
    if (doc.dataset.theme) return doc.dataset.theme;
    return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  }
  var toggle = $('.theme-toggle');
  if (toggle) toggle.addEventListener('click', function () {
    var next = effectiveTheme() === 'dark' ? 'light' : 'dark';
    doc.dataset.theme = next;
    store('sg-theme', next);
    if (fleet) fleet.refreshColors();
  });

  /* ---------- Nav state + reading progress ---------- */
  var nav = $('header.nav');
  var bar = $('.progress');
  var ticking = false;
  function onScroll() {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(function () {
      var y = window.scrollY;
      nav.classList.toggle('scrolled', y > 8);
      var max = doc.scrollHeight - window.innerHeight;
      bar.style.transform = 'scaleX(' + (max > 0 ? y / max : 0) + ')';
      updateTimeline();
      ticking = false;
    });
  }
  window.addEventListener('scroll', onScroll, { passive: true });
  window.addEventListener('resize', function () { measureNow(); onScroll(); });

  /* ---------- Mobile section menu ---------- */
  var menuBtn = $('.menu-btn');
  var menu = $('#nav-menu');
  function setMenu(open, refocus) {
    nav.classList.toggle('open', open);
    menuBtn.setAttribute('aria-expanded', String(open));
    menuBtn.setAttribute('aria-label', open ? 'Close section menu' : 'Open section menu');
    if (open) { var first = $('a', menu); if (first) first.focus(); }
    else if (refocus) menuBtn.focus();
  }
  if (menuBtn && menu) {
    menuBtn.addEventListener('click', function () { setMenu(!nav.classList.contains('open')); });
    menu.addEventListener('click', function (e) { if (e.target.closest('a')) setMenu(false); });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && nav.classList.contains('open')) setMenu(false, true); });
    document.addEventListener('click', function (e) { if (nav.classList.contains('open') && !nav.contains(e.target)) setMenu(false); });
    window.matchMedia('(min-width: 1081px)').addEventListener('change', function (m) { if (m.matches) setMenu(false); });
  }

  /* Highlight the nav link of the section in view. */
  var navLinks = $$('.nav-links a');
  if ('IntersectionObserver' in window) {
    var secObs = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (!e.isIntersecting) return;
        navLinks.forEach(function (a) { a.classList.toggle('active', a.getAttribute('href') === '#' + e.target.id); });
      });
    }, { rootMargin: '-45% 0px -50% 0px' });
    navLinks.forEach(function (a) { var s = $(a.getAttribute('href')); if (s) secObs.observe(s); });
  }

  /* ---------- Reveal on scroll ---------- */
  var reveals = $$('.reveal');
  if ('IntersectionObserver' in window && !reduceMotion) {
    // Anything already on screen is shown at once, so it doesn't blink out and back.
    reveals.forEach(function (el) { if (el.getBoundingClientRect().top < window.innerHeight) el.classList.add('in'); });
    var revObs = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (!e.isIntersecting) return;
        var sibs = Array.prototype.filter.call(e.target.parentElement.children, function (c) { return c.classList.contains('reveal'); });
        e.target.style.transitionDelay = Math.min(sibs.indexOf(e.target), 6) * 70 + 'ms';
        e.target.classList.add('in');
        revObs.unobserve(e.target);
      });
    }, { rootMargin: '0px 0px -8% 0px' });
    reveals.forEach(function (el) { if (!el.classList.contains('in')) revObs.observe(el); });
  } else {
    reveals.forEach(function (el) { el.classList.add('in'); });
  }

  /* ---------- Counters ---------- */
  var counters = $$('[data-count]');
  function runCounter(el) {
    var end = parseInt(el.dataset.count, 10);
    if (reduceMotion || end === 0) { el.textContent = String(end); return; }
    var t0 = performance.now(), dur = 1400;
    (function step(t) {
      // Reduced motion switched on mid-count: jump straight to the final value.
      var p = reduceMotion ? 1 : Math.min(1, (t - t0) / dur);
      el.textContent = String(Math.round(end * (1 - Math.pow(1 - p, 3))));
      if (p < 1) requestAnimationFrame(step);
    })(t0);
  }
  if ('IntersectionObserver' in window) {
    var cObs = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) { if (e.isIntersecting) { runCounter(e.target); cObs.unobserve(e.target); } });
    }, { threshold: .6 });
    counters.forEach(function (el) { cObs.observe(el); });
  }

  /* ---------- Tabs (ARIA, keyboard) ---------- */
  function setupTabs(list) {
    var tabs = $$('[role="tab"]', list);
    function select(tab, focus, quiet) {
      tabs.forEach(function (t) {
        var on = t === tab;
        t.setAttribute('aria-selected', String(on));
        t.tabIndex = on ? 0 : -1;
        var p = document.getElementById(t.getAttribute('aria-controls'));
        if (!p) return;
        p.hidden = !on;
        if (on && !quiet && p.classList.contains('panel')) { p.classList.remove('anim'); void p.offsetWidth; p.classList.add('anim'); }
      });
      if (focus) tab.focus();
    }
    var initial = tabs.filter(function (t) { return t.getAttribute('aria-selected') === 'true'; })[0] || tabs[0];
    if (initial) select(initial, false, true);
    tabs.forEach(function (t, i) {
      t.addEventListener('click', function () { select(t); });
      t.addEventListener('keydown', function (e) {
        var k = e.key, n = tabs.length, j = null;
        if (k === 'ArrowRight' || k === 'ArrowDown') j = (i + 1) % n;
        else if (k === 'ArrowLeft' || k === 'ArrowUp') j = (i - 1 + n) % n;
        else if (k === 'Home') j = 0;
        else if (k === 'End') j = n - 1;
        if (j !== null) { e.preventDefault(); select(tabs[j], true); }
      });
    });
  }
  $$('[role="tablist"]').forEach(setupTabs);

  /* ---------- Copy buttons ---------- */
  $$('.copy').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var pre = btn.parentElement.querySelector('pre').cloneNode(true);
      $$('.p', pre).forEach(function (p) { p.remove(); }); // drop shell prompts
      var text = pre.textContent.replace(/\s+$/, '') + '\n';
      var done = function (msg) { btn.textContent = msg; setTimeout(function () { btn.textContent = 'Copy'; }, 1600); };
      if (navigator.clipboard) navigator.clipboard.writeText(text).then(function () { done('Copied'); }, function () { done('Press Ctrl+C'); });
      else done('Press Ctrl+C');
    });
  });

  /* ---------- Card spotlight ---------- */
  document.addEventListener('pointermove', function (e) {
    var card = e.target.closest && e.target.closest('.spot');
    if (!card) return;
    var r = card.getBoundingClientRect();
    card.style.setProperty('--mx', (e.clientX - r.left) + 'px');
    card.style.setProperty('--my', (e.clientY - r.top) + 'px');
  }, { passive: true });

  /* ---------- Latest release (falls back to the static text) ---------- */
  (function () {
    var TTL = 60 * 60 * 1000;
    function apply(tag) { $$('[data-version]').forEach(function (el) { el.textContent = tag; }); }
    var cached = null;
    try { cached = JSON.parse(localStorage.getItem('sg-latest') || 'null'); } catch (e) {}
    if (cached && typeof cached.tag === 'string' && /^v\d+\.\d+\.\d+$/.test(cached.tag)) {
      apply(cached.tag);
      // A timestamp in the future (clock moved back) counts as stale.
      if (typeof cached.t === 'number' && cached.t <= Date.now() && Date.now() - cached.t < TTL) return;
    }
    if (!window.fetch) return;
    fetch('https://api.github.com/repos/BrainStation-23/SentinelGo/releases/latest', { headers: { Accept: 'application/vnd.github+json' } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (j) {
        if (!j || !/^v\d+\.\d+\.\d+$/.test(j.tag_name || '')) return;
        apply(j.tag_name);
        try { localStorage.setItem('sg-latest', JSON.stringify({ tag: j.tag_name, t: Date.now() })); } catch (e) {}
      })
      .catch(function () {});
  })();

  /* ---------- Roadmap: filters, scroll-filled rail, "now" split ---------- */
  var timeline = $('.timeline');
  var fill = timeline && $('.fill', timeline);
  var nowEl = $('#now');
  function measureNow() {
    if (!timeline || !nowEl) return;
    var top = nowEl.offsetTop + nowEl.offsetHeight / 2;
    timeline.style.setProperty('--now', top + 'px');
  }
  function updateTimeline() {
    if (!timeline) return;
    var r = timeline.getBoundingClientRect();
    var line = window.innerHeight * 0.6;
    var p = Math.max(0, Math.min(1, (line - r.top) / r.height));
    fill.style.height = (p * r.height) + 'px';
  }
  var items = $$('.tl-item');
  if ('IntersectionObserver' in window) {
    var tlObs = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) { e.target.classList.toggle('in', e.isIntersecting || e.boundingClientRect.top < 0); });
    }, { rootMargin: '0px 0px -40% 0px' });
    items.forEach(function (el) { tlObs.observe(el); });
  } else {
    items.forEach(function (el) { el.classList.add('in'); });
  }
  $$('.fchip').forEach(function (chip, _, all) {
    chip.addEventListener('click', function () {
      var f = chip.dataset.filter;
      all.forEach(function (c) { c.setAttribute('aria-pressed', String(c === chip)); });
      items.forEach(function (it) {
        var kinds = (it.dataset.kind || '').split(' ');
        it.classList.toggle('hide', !(f === 'all' || kinds.indexOf(f) !== -1));
      });
      // Hide era labels that have no visible items before the next marker.
      $$('.tl > li').forEach(function (li, i, lis) {
        if (!li.classList.contains('tl-era')) return;
        var any = false;
        for (var k = i + 1; k < lis.length && !lis[k].classList.contains('tl-era') && !lis[k].classList.contains('tl-now'); k++) {
          if (!lis[k].classList.contains('hide')) { any = true; break; }
        }
        li.style.display = any ? '' : 'none';
      });
      measureNow();
      updateTimeline();
    });
  });
  measureNow();
  window.addEventListener('load', function () { measureNow(); onScroll(); });

  /* ---------- Hero: animated fleet ---------- */
  var fleet = (function () {
    var canvas = $('#fleet');
    if (!canvas || !canvas.getContext) return null;
    var ctx = canvas.getContext('2d');
    var toasts = $('.toasts');
    var W = 0, H = 0, dpr = 1, cx = 0, cy = 0, R = 0;
    var C = {};
    var nodes = [], packets = [], rings = [];
    var running = false, visible = true, last = 0, nextBeat = 0, nextIncident = 1600, rafId = 0;

    var INCIDENTS = [
      { host: 'win-fin-017', bad: 'Firewall disabled', fix: 'Firewall re-enabled by native task' },
      { host: 'lnx-build-09', bad: 'Critical CVE in an installed package', fix: 'Patched through policy' },
      { host: 'win-ops-221', bad: 'BitLocker off', fix: 'BitLocker on · recovery key in vault' },
      { host: 'mac-sales-12', bad: 'Browser three versions behind', fix: 'Updated from the app catalog' },
      { host: 'win-hr-044', bad: 'EDR service stopped', fix: 'Restarted by linked remediation' },
      { host: 'lnx-ci-03', bad: 'OS patches 45 days old', fix: 'Updates applied on schedule' },
      { host: 'mac-eng-31', bad: 'Unapproved app installed', fix: 'Removed by policy' }
    ];
    var incidentIdx = 0;

    function css(name) { return getComputedStyle(doc).getPropertyValue(name).trim(); }
    function refreshColors() {
      C = { accent: css('--accent'), a2: css('--accent-2'), a3: css('--accent-3'), danger: css('--danger'), warn: css('--warn'),
            ok: css('--ok'), line: css('--border-strong'), text: css('--text'), bg: css('--bg'), light: effectiveTheme() === 'light' };
      if (!running) draw(performance.now());
    }

    function build() {
      nodes = [];
      var orbits = [{ r: .42, n: 10, s: .00010 }, { r: .70, n: 16, s: -.00006 }, { r: 1, n: 22, s: .00004 }];
      orbits.forEach(function (o, oi) {
        for (var i = 0; i < o.n; i++) {
          nodes.push({ orbit: oi, r: o.r, speed: o.s, a: (i / o.n) * Math.PI * 2 + oi * .7 + Math.random() * .15,
                       state: Math.random() < .07 ? 'warn' : 'ok', pulse: 0, x: 0, y: 0, z: 0 });
        }
      });
    }

    function resize() {
      var rect = canvas.getBoundingClientRect();
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      W = rect.width; H = rect.height;
      canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      cx = W * .5; cy = H * .5; R = Math.min(W * .47, H * .78);
      if (!running) draw(performance.now());
    }

    var TILT = .5;
    function place(n) {
      var r = n.r * R;
      n.x = cx + Math.cos(n.a) * r;
      n.y = cy + Math.sin(n.a) * r * TILT;
      n.z = Math.sin(n.a); // -1 back, +1 front
    }

    function spawn(node, dir, color, onArrive) {
      packets.push({ node: node, dir: dir, t: 0, speed: dir === 'up' ? .0011 + Math.random() * .0006 : .0012, color: color, onArrive: onArrive });
    }

    function toast(inc) {
      if (!toasts || reduceMotion) return null;
      var el = document.createElement('div');
      el.className = 'toast';
      el.innerHTML = '<span class="dot"></span><div><b></b><div class="msg"></div></div>';
      el.querySelector('b').textContent = inc.host;
      el.querySelector('.msg').textContent = inc.bad;
      toasts.appendChild(el);
      var all = toasts.children;
      if (all.length > 3) {
        var old = all[0];
        old.classList.add('out');
        setTimeout(function () { old.remove(); }, 380);
      }
      return el;
    }

    function incident() {
      var front = nodes.filter(function (n) { return n.state !== 'bad' && n.z > -.2; });
      if (!front.length) return;
      var n = front[Math.floor(Math.random() * front.length)];
      var inc = INCIDENTS[incidentIdx++ % INCIDENTS.length];
      n.state = 'bad';
      rings.push({ x: n.x, y: n.y, node: n, t: 0, color: C.danger });
      var el = toast(inc);
      function resolve() {
        n.state = 'ok';
        rings.push({ node: n, t: 0, color: C.ok });
        if (el) { el.classList.add('fixed'); el.querySelector('.msg').textContent = inc.fix; }
      }
      // If the animation stopped meanwhile (e.g. reduced motion switched on),
      // no packet would ever arrive, so resolve straight away, and redraw the
      // static frame so the node doesn't stay drawn as failed.
      setTimeout(function () {
        if (running) spawn(n, 'down', C.a3, resolve);
        else { resolve(); if (reduceMotion) staticFrame(); }
      }, 1000);
    }

    function drawShield(x, y, s, alpha) {
      ctx.save();
      ctx.translate(x - 16 * s, y - 16 * s);
      ctx.scale(s, s);
      ctx.globalAlpha = alpha;
      var g = ctx.createLinearGradient(0, 0, 32, 32);
      g.addColorStop(0, C.accent); g.addColorStop(1, C.a2);
      ctx.fillStyle = g;
      ctx.beginPath();
      ctx.moveTo(16, 2); ctx.lineTo(4, 7); ctx.lineTo(4, 15);
      ctx.bezierCurveTo(4, 22.4, 9.1, 28.4, 16, 30);
      ctx.bezierCurveTo(22.9, 28.4, 28, 22.4, 28, 15);
      ctx.lineTo(28, 7); ctx.closePath(); ctx.fill();
      ctx.strokeStyle = C.light ? '#ffffff' : '#060a11';
      ctx.lineWidth = 3; ctx.lineCap = 'round'; ctx.lineJoin = 'round';
      ctx.beginPath(); ctx.moveTo(11, 16); ctx.lineTo(14.5, 19.5); ctx.lineTo(21.5, 12); ctx.stroke();
      ctx.restore();
    }

    function nodeColor(n) { return n.state === 'bad' ? C.danger : n.state === 'warn' ? C.warn : (n.orbit === 1 ? C.a2 : C.accent); }

    function draw(now) {
      if (!W) return;
      ctx.clearRect(0, 0, W, H);

      // Orbit rings
      ctx.lineWidth = 1;
      [.42, .70, 1].forEach(function (r) {
        ctx.beginPath();
        ctx.ellipse(cx, cy, r * R, r * R * TILT, 0, 0, Math.PI * 2);
        ctx.strokeStyle = C.line; ctx.globalAlpha = .55; ctx.stroke();
      });
      ctx.globalAlpha = 1;

      nodes.forEach(place);
      var back = nodes.filter(function (n) { return n.z < 0; });
      var front = nodes.filter(function (n) { return n.z >= 0; });

      function drawNode(n) {
        var depth = (n.z + 1) / 2;
        var size = 2.4 + depth * 2.8;
        var col = nodeColor(n);
        ctx.globalAlpha = .35 + depth * .65;
        ctx.fillStyle = col;
        ctx.shadowColor = col; ctx.shadowBlur = n.state === 'bad' ? 18 : 8 * depth;
        ctx.beginPath(); ctx.arc(n.x, n.y, n.state === 'bad' ? size + 1.5 : size, 0, Math.PI * 2); ctx.fill();
        ctx.shadowBlur = 0;
      }
      back.forEach(drawNode);

      // Core: glow, rotating arcs, shield
      var glow = ctx.createRadialGradient(cx, cy, 0, cx, cy, R * .38);
      glow.addColorStop(0, C.light ? 'rgba(0,137,111,.18)' : 'rgba(0,212,170,.28)');
      glow.addColorStop(1, 'rgba(0,0,0,0)');
      ctx.globalAlpha = 1; ctx.fillStyle = glow;
      ctx.beginPath(); ctx.arc(cx, cy, R * .38, 0, Math.PI * 2); ctx.fill();
      var rot = now * .0004;
      ctx.lineWidth = 2; ctx.lineCap = 'round';
      [[R * .17, rot, C.accent], [R * .22, -rot * .7, C.a2], [R * .27, rot * .5, C.a3]].forEach(function (a) {
        for (var k = 0; k < 3; k++) {
          ctx.beginPath();
          ctx.strokeStyle = a[2]; ctx.globalAlpha = .55;
          ctx.arc(cx, cy, a[0], a[1] + k * 2.1, a[1] + k * 2.1 + .9);
          ctx.stroke();
        }
      });
      ctx.globalAlpha = 1;
      drawShield(cx, cy, R / 110, 1);

      // Packets
      packets.forEach(function (p) {
        var n = p.node;
        for (var k = 4; k >= 0; k--) {
          var t = Math.max(0, p.t - k * .035);
          var f = p.dir === 'up' ? t : 1 - t;
          var x = n.x + (cx - n.x) * f, y = n.y + (cy - n.y) * f;
          ctx.globalAlpha = (1 - k / 5) * .9;
          ctx.fillStyle = p.color;
          ctx.beginPath(); ctx.arc(x, y, k === 0 ? 2.4 : 1.6, 0, Math.PI * 2); ctx.fill();
        }
      });
      ctx.globalAlpha = 1;

      front.forEach(drawNode);
      ctx.globalAlpha = 1;

      // Ripples
      rings.forEach(function (r) {
        var x = r.node ? r.node.x : r.x, y = r.node ? r.node.y : r.y;
        ctx.globalAlpha = Math.max(0, 1 - r.t);
        ctx.strokeStyle = r.color; ctx.lineWidth = 2;
        ctx.beginPath(); ctx.arc(x, y, 4 + r.t * 26, 0, Math.PI * 2); ctx.stroke();
      });
      ctx.globalAlpha = 1;
    }

    function tick(now) {
      if (!running) return;
      var dt = Math.min(50, now - (last || now));
      last = now;
      nodes.forEach(function (n) { n.a += n.speed * dt; });

      nextBeat -= dt;
      while (nextBeat <= 0) {
        var n = nodes[Math.floor(Math.random() * nodes.length)];
        if (n.state !== 'bad') spawn(n, 'up', n.orbit === 1 ? C.a2 : C.accent);
        nextBeat += 70 + Math.random() * 60;
      }
      nextIncident -= dt;
      if (nextIncident <= 0) { incident(); nextIncident = 2800 + Math.random() * 900; }
      // Warn nodes occasionally settle, others occasionally drift to warn.
      if (Math.random() < dt * .00004) { var w = nodes[Math.floor(Math.random() * nodes.length)]; if (w.state !== 'bad') w.state = w.state === 'warn' ? 'ok' : 'warn'; }

      packets = packets.filter(function (p) {
        p.t += p.speed * dt;
        if (p.t >= 1) { if (p.onArrive) p.onArrive(); return false; }
        return true;
      });
      rings = rings.filter(function (r) { r.t += dt / 900; return r.t < 1; });

      draw(now);
      rafId = requestAnimationFrame(tick);
    }

    // Exactly one frame is ever pending: stop() cancels it, so resuming after a
    // hidden tab can't leave a second loop running alongside the new one.
    function start() { if (running || reduceMotion || !visible || document.hidden) return; running = true; last = 0; rafId = requestAnimationFrame(tick); }
    function stop() { running = false; cancelAnimationFrame(rafId); rafId = 0; }

    function staticFrame() {
      // One calm frame with a few packets in flight, for reduced motion.
      nodes.forEach(place);
      // Settle remediations still in flight so their nodes and toasts don't stay failed.
      packets.forEach(function (p) { if (p.onArrive) p.onArrive(); });
      packets = []; rings = [];
      for (var i = 0; i < 14; i++) packets.push({ node: nodes[(i * 7) % nodes.length], dir: 'up', t: (i % 5) / 5 + .1, color: C.accent });
      draw(performance.now());
    }

    build(); refreshColors(); resize();
    window.addEventListener('resize', resize);
    window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', refreshColors);
    document.addEventListener('visibilitychange', function () { if (document.hidden) stop(); else start(); });
    if ('IntersectionObserver' in window) {
      new IntersectionObserver(function (e) { visible = e[0].isIntersecting; if (visible) start(); else stop(); }).observe(canvas);
    }
    // Follow the reduced-motion setting live, not just at page load.
    motionQuery.addEventListener('change', function (m) {
      reduceMotion = m.matches;
      if (reduceMotion) { stop(); staticFrame(); } else { packets = []; start(); }
    });
    if (reduceMotion) staticFrame(); else start();
    return { refreshColors: refreshColors };
  })();

  doc.classList.add('js-ready');
  onScroll();
})();
