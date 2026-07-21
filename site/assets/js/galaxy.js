/* CyberChainBench — animated background.
   Star field receding into depth + an infinite hexagon "block" tunnel.
   Palette tuned to the site: blue #7c9bff / teal #3fe0ad on near-black. */
(function () {
  'use strict';

  // Run-once guard: this code may be present both inlined and as an external
  // <script src>. Whichever runs first wins; the other becomes a no-op.
  if (window.__ccbGalaxy) return;
  window.__ccbGalaxy = true;

  if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

  var canvas = document.createElement('canvas');
  canvas.id = 'galaxy-bg';
  canvas.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;z-index:-1;pointer-events:none;';
  document.body.insertBefore(canvas, document.body.firstChild);

  var ctx = canvas.getContext('2d');
  var W = 0, H = 0, cx = 0, cy = 0, DPR = Math.min(window.devicePixelRatio || 1, 2);

  function resize() {
    W = window.innerWidth; H = window.innerHeight;
    canvas.width = W * DPR; canvas.height = H * DPR;
    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
    cx = W / 2; cy = H / 2;
  }
  resize();
  window.addEventListener('resize', resize);

  // ── Stars ──────────────────────────────────────────────────
  var STAR_COUNT  = 220;
  var Z_STAR_NEAR = 0.5;
  var Z_STAR_FAR  = 12.0;
  var STAR_SPEED  = 0.0032;

  var stars = (function () {
    var out = [], i;
    for (i = 0; i < STAR_COUNT; i++) {
      var big = Math.random() < 0.08;
      var cr  = Math.random();
      out.push({
        wx:    (Math.random() - 0.5) * 2.4,
        wy:    (Math.random() - 0.5) * 2.4,
        z_s:   Z_STAR_NEAR + (Z_STAR_FAR - Z_STAR_NEAR) * Math.random(),
        r:     big ? Math.random() * 1.1 + 1.2 : Math.random() * 0.8 + 0.22,
        base:  Math.random() * 0.32 + 0.36,
        amp:   Math.random() * 0.32 + 0.18,
        freq:  Math.random() * 0.007 + 0.002,
        phase: Math.random() * 6.2832,
        col:   cr < 0.55 ? [180,200,255]   // blue-white
             : cr < 0.78 ? [235,242,255]   // white
             : cr < 0.92 ? [120,225,190]   // teal
             :              [200,215,255],
      });
    }
    return out;
  }());

  // ── Nebulae (cool blue / teal clouds) ──────────────────────
  var nebulae = [
    { nx:0.18, ny:0.20, nr:0.56, col:[40, 60,150], a:0.16 },
    { nx:0.80, ny:0.66, nr:0.48, col:[20, 90, 90], a:0.12 },
    { nx:0.08, ny:0.82, nr:0.42, col:[60, 40,140], a:0.10 },
    { nx:0.86, ny:0.12, nr:0.46, col:[30, 70,160], a:0.12 },
    { nx:0.52, ny:0.84, nr:0.38, col:[24,110,110], a:0.09 },
    { nx:0.40, ny:0.48, nr:0.34, col:[36, 56,130], a:0.08 },
  ];

  // ── Hexagon tunnel ─────────────────────────────────────────
  var HEX_N   = 8;
  var Z_RESET = 0.35;
  var Z_PEAK  = 2.5;
  var Z_FAR   = 20;
  var Z_SPAN  = Z_FAR - Z_RESET;
  var SPEED   = 0.009;

  var hexes = (function () {
    var out = [], j;
    for (j = 0; j < HEX_N; j++) {
      out.push({ z: Z_RESET + Z_SPAN * (j / HEX_N), rot: (j % 2) ? 0.2618 : 0 });
    }
    return out;
  }());

  function hexRadius(z) { return Math.min(W, H) * 0.05 * Z_FAR / z; }

  var STEP = 1.04719755;  // 60° in radians

  function drawHex(z, rot0) {
    var R = hexRadius(z), k;
    var quickIn = (z - Z_RESET) / 0.25;
    quickIn = quickIn < 0 ? 0 : quickIn > 1 ? 1 : quickIn;
    var fadeOut = z > Z_PEAK ? (Z_FAR - z) / (Z_FAR - Z_PEAK) : 1.0;
    fadeOut = fadeOut < 0 ? 0 : fadeOut > 1 ? 1 : fadeOut;
    var alpha = 0.62 * quickIn * fadeOut;
    if (alpha <= 0.01) return;

    ctx.beginPath();
    for (k = 0; k < 6; k++) {
      var a = rot0 + STEP * k;
      var x = cx + Math.cos(a) * R, y = cy + Math.sin(a) * R;
      if (k === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    }
    ctx.closePath();
    // colour shifts blue→teal as it recedes
    var t = (z - Z_RESET) / Z_SPAN;
    var rr = Math.round(124 + (63 - 124) * t);
    var gg = Math.round(155 + (224 - 155) * t);
    var bb = Math.round(255 + (173 - 255) * t);
    ctx.strokeStyle = 'rgba(' + rr + ',' + gg + ',' + bb + ',' + alpha.toFixed(3) + ')';
    ctx.lineWidth = 1.1;
    ctx.stroke();

    if (alpha > 0.05) {
      ctx.fillStyle = 'rgba(' + rr + ',' + gg + ',' + bb + ',' + (alpha * 0.045).toFixed(4) + ')';
      ctx.fill();
    }
  }

  // ── Render loop ────────────────────────────────────────────
  var tick = 0;
  function frame() {
    tick++;
    ctx.fillStyle = '#0a0f1c';
    ctx.fillRect(0, 0, W, H);

    var i, n, grd, c, px, py, rad;
    for (i = 0; i < nebulae.length; i++) {
      n = nebulae[i]; px = n.nx * W; py = n.ny * H; rad = n.nr * Math.max(W, H); c = n.col;
      grd = ctx.createRadialGradient(px, py, 0, px, py, rad);
      grd.addColorStop(0,    'rgba(' + c[0] + ',' + c[1] + ',' + c[2] + ',' + n.a + ')');
      grd.addColorStop(0.42, 'rgba(' + c[0] + ',' + c[1] + ',' + c[2] + ',' + (n.a * 0.42).toFixed(3) + ')');
      grd.addColorStop(1,    'rgba(' + c[0] + ',' + c[1] + ',' + c[2] + ',0)');
      ctx.fillStyle = grd; ctx.fillRect(0, 0, W, H);
    }

    var s, bri, sx, sy, depthFade;
    for (i = 0; i < stars.length; i++) {
      s = stars[i];
      s.z_s += STAR_SPEED;
      if (s.z_s > Z_STAR_FAR) s.z_s = Z_STAR_NEAR;
      sx = cx + s.wx * (W / 2) / s.z_s;
      sy = cy + s.wy * (H / 2) / s.z_s;
      if (sx < -10 || sx > W + 10 || sy < -10 || sy > H + 10) continue;
      bri = s.base + s.amp * Math.sin(tick * s.freq * 6.2832 + s.phase);
      bri = bri < 0 ? 0 : bri > 1 ? 1 : bri;
      depthFade = (Z_STAR_FAR - s.z_s) / (Z_STAR_FAR - Z_STAR_NEAR * 4);
      depthFade = depthFade < 0 ? 0 : depthFade > 1 ? 1 : depthFade;
      bri *= depthFade;
      c = s.col;
      if (s.r > 1.1 && bri > 0.05) {
        grd = ctx.createRadialGradient(sx, sy, 0, sx, sy, s.r * 5.5);
        grd.addColorStop(0, 'rgba(' + c[0] + ',' + c[1] + ',' + c[2] + ',' + (bri * 0.28).toFixed(3) + ')');
        grd.addColorStop(1, 'rgba(0,0,0,0)');
        ctx.fillStyle = grd;
        ctx.beginPath(); ctx.arc(sx, sy, s.r * 5.5, 0, 6.2832); ctx.fill();
      }
      ctx.globalAlpha = bri;
      ctx.fillStyle = 'rgb(' + c[0] + ',' + c[1] + ',' + c[2] + ')';
      ctx.beginPath(); ctx.arc(sx, sy, s.r, 0, 6.2832); ctx.fill();
      ctx.globalAlpha = 1;
    }

    grd = ctx.createRadialGradient(cx, cy, 0, cx, cy, 120);
    grd.addColorStop(0, 'rgba(124,155,255,0.06)');
    grd.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.fillStyle = grd; ctx.fillRect(0, 0, W, H);

    for (i = 0; i < hexes.length; i++) {
      hexes[i].z += SPEED;
      if (hexes[i].z > Z_FAR) hexes[i].z = Z_RESET;
      drawHex(hexes[i].z, hexes[i].rot);
    }

    requestAnimationFrame(frame);
  }
  frame();
}());
