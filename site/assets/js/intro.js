/* CyberChainBench — hacker terminal intro + scroll reveal.
   Rewritten: plain-text lines with a class (no nested-tag typewriter), so it
   can never stall mid-tag. Always finishes; click / any key skips. */
(function () {
  'use strict';

  // Run-once guard: this code may be present both inlined and as an external
  // <script src>. Whichever runs first wins; the other becomes a no-op.
  if (window.__ccbIntro) return;
  window.__ccbIntro = true;

  function startReveal() {
    var els = document.querySelectorAll('[data-reveal]');
    if (!('IntersectionObserver' in window) || !els.length) {
      for (var i = 0; i < els.length; i++) els[i].classList.add('revealed');
      return;
    }
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) {
          var el = e.target;
          el.style.transitionDelay = (el.getAttribute('data-reveal-delay') || 0) + 'ms';
          el.classList.add('revealed');
          io.unobserve(el);
        }
      });
    }, { threshold: 0.12, rootMargin: '0px 0px -8% 0px' });
    els.forEach(function (el) { io.observe(el); });
  }

  var overlay = document.getElementById('termOverlay');
  var body = document.getElementById('termBody');
  if (!overlay || !body) { startReveal(); return; }

  var booted = false;
  try { booted = !!sessionStorage.getItem('ccb-booted'); } catch (e) {}
  var reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  if (booted || reduced) {
    document.documentElement.classList.remove('js-anim'); // ensure nothing stays hidden
    if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
    startReveal();
    return;
  }

  // We are going to animate: make sure the gating styles are active even if the
  // inline head guard was blocked (some file:// setups).
  document.documentElement.classList.add('js-anim');
  document.body.classList.add('hero-animate');

  /* Line types:
     type   "type" = typewrite the text · "print" = appear instantly · "bar" = progress bar
     cls    css class applied to the line (color)
     text   the line text (typewriter/print)
     d      pause after the line, ms
     pre    optional html prepended instantly before typed text (e.g. the "$ " prompt) */
  var SCRIPT = [
    { type:'type',  cls:'c',    pre:'<span class="p">$</span> ', text:'whoami',                       d:260 },
    { type:'print', cls:'dim',  text:'anon-agent  (uid=1337  role=ai-pentester)',                     d:240 },
    { type:'type',  cls:'c',    pre:'<span class="p">$</span> ', text:'sudo ./ccb --boot exploit-engine', d:200 },
    { type:'print', cls:'dim',  text:'[sudo] authenticating agent … ', append:'<span class="ok">granted</span>', d:200 },
    { type:'print', cls:'dim',  text:'[ 0.01 ] initializing CyberChainBench v1.0',                    d:90  },
    { type:'print', cls:'dim',  text:'[ 0.04 ] mounting Foundry fork backend … ', append:'<span class="ok">ok</span>', d:90 },
    { type:'print', cls:'dim',  text:'[ 0.09 ] loading dataset … ', append:'<span class="ok">541 exploits</span> <span class="dim">($1.13B stolen, 9 chains)</span>', d:140 },
    { type:'bar',   cls:'dim',  label:'[ 0.12 ] indexing corpus ',                                    d:160 },
    { type:'blank' },
    { type:'type',  cls:'c',    pre:'<span class="p">$</span> ', text:'ccb attack --target 0xDEAD…BEEF --task detect,exploit,patch', d:240 },
    { type:'print', cls:'warn', text:'>> replaying historical block at fork height …',                d:200 },
    { type:'print', cls:'warn', text:'>> tracing vulnerable call path …',                             d:200 },
    { type:'print', cls:'warn', text:'>> crafting proof-of-concept exploit …',                        d:230 },
    { type:'print', cls:'ok',   text:'>> profit extracted · invariant broken · exploit CONFIRMED',    d:240 },
    { type:'blank' },
    { type:'glitch',cls:'grant',text:'[ ACCESS GRANTED ]',                                            d:520 },
    { type:'type',  cls:'ask',  text:'can an AI agent crack the exploit?',                            d:650 }
  ];

  var cursor = document.createElement('span');
  cursor.className = 'term-cursor';

  var li = 0, done = false, activeLine = null;

  function park() { (activeLine || body).appendChild(cursor); }

  function finish() {
    if (done) return;
    done = true;
    overlay.classList.add('gone');
    try { sessionStorage.setItem('ccb-booted', '1'); } catch (e) {}
    setTimeout(function () { document.body.classList.add('hero-revealed'); }, 600);
    setTimeout(function () {
      if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
      startReveal();
    }, 780);
  }

  function next(delay) {
    if (done) return;
    setTimeout(run, delay || 80);
  }

  function run() {
    if (done) return;
    if (li >= SCRIPT.length) { setTimeout(finish, 260); return; }
    var item = SCRIPT[li++];
    var line = document.createElement('div');
    line.className = 'line' + (item.cls ? ' ' + item.cls : '');
    body.appendChild(line);
    activeLine = line;
    park();

    if (item.type === 'blank') { line.innerHTML = '&nbsp;'; next(70); return; }

    if (item.type === 'print') {
      // print text may contain intentional <span> markup; insert as-is
      line.innerHTML = (item.text || '') + (item.append || '');
      next(item.d); return;
    }

    if (item.type === 'bar') {
      var slots = 22, filled = 0;
      function tickBar() {
        if (done) { line.innerHTML = item.label + '[' + rep('=', slots) + '] 100%'; next(0); return; }
        var pct = Math.round(filled / slots * 100);
        line.innerHTML = item.label + '[' + rep('=', filled) + rep(' ', slots - filled) + '] ' + pct + '%';
        park();
        if (filled >= slots) { next(item.d); return; }
        filled++;
        setTimeout(tickBar, 28 + Math.random() * 26);
      }
      tickBar(); return;
    }

    if (item.type === 'glitch') {
      var target = item.text, frames = 8, f = 0;
      function gl() {
        if (done) { line.textContent = target; next(0); return; }
        if (f >= frames) { line.textContent = target; next(item.d); return; }
        line.textContent = scramble(target);
        park();
        f++;
        setTimeout(gl, 55);
      }
      gl(); return;
    }

    // type
    var pre = item.pre || '';
    var txt = item.text || '';
    var typed = 0;
    function typeStep() {
      if (done) { line.innerHTML = pre + esc(txt); next(0); return; }
      line.innerHTML = pre + esc(txt.slice(0, typed));
      park();
      body.scrollTop = body.scrollHeight;
      if (typed >= txt.length) { next(item.d); return; }
      var ch = txt[typed++];
      setTimeout(typeStep, ch === ' ' ? 16 : 22 + Math.random() * 30);
    }
    typeStep();
  }

  function esc(s){ return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
  function rep(c,n){ var s=''; for(var i=0;i<n;i++) s+=c; return s; }
  function scramble(s){
    var glyphs = '!<>-_\\/[]{}=+*^?#01x$';
    var out = '';
    for (var i=0;i<s.length;i++){
      out += (s[i] === ' ') ? ' ' : glyphs[Math.floor(Math.random()*glyphs.length)];
    }
    return out;
  }

  overlay.addEventListener('click', finish);
  document.addEventListener('keydown', finish);

  // Safety net: no matter what, never trap the user.
  setTimeout(function(){ if (!done) finish(); }, 14000);

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { setTimeout(run, 320); });
  } else {
    setTimeout(run, 320);
  }
}());
