'use client';

import { useEffect, useRef, type CSSProperties } from 'react';
import { MASK_COLS, MASK_ROWS, MASK_PLAIN, MASK_GREEN } from '@/lib/krakenOrbMask';

interface KrakenOrbProps {
  size?: number;
  className?: string;
  style?: CSSProperties;
}

const RAMP2 = " .'`,:;-~+=*!?Lvxz7CZmqpdbk#MW&8%B@";
const RAMP_SCRAMBLE = "!@#$%&*+=?xz7Ckhao#MW8B".split('');

const PALETTES: string[][] = [
  ['#3a1c10', '#6a3018', '#a04820', '#cc6a30', '#e08a3a', '#f0a858', '#ffd49a', '#7ee07e', 'rgba(126,224,126,.7)', '#3aa03a'],
  ['#200808', '#481010', '#701818', '#982828', '#c84038', '#f06858', '#ffc8a8', '#ffd23a', 'rgba(255,210,58,.7)', '#c89020'],
  ['#0a1018', '#182028', '#283038', '#3a4858', '#586878', '#88a0b8', '#d8e8f8', '#ffaa3a', 'rgba(255,170,58,.7)', '#c87018'],
  ['#1a1f1a', '#2a322a', '#404a40', '#5a685a', '#80908a', '#b0c0b8', '#f0f8f4', '#7ee07e', 'rgba(126,224,126,.7)', '#3aa03a'],
];

function chBright(c: string): number {
  if (c === ' ' || c === '.') return 0;
  const i = RAMP2.indexOf(c);
  if (i < 0) return 0.6;
  return i / (RAMP2.length - 1);
}

function noise(ix: number, iy: number): number {
  let h = ix * 374761393 + iy * 668265263;
  h = (h ^ (h >>> 13)) * 1274126177;
  h = (h ^ (h >>> 16)) >>> 0;
  return (h % 1000) / 1000;
}

interface Cell {
  el: HTMLElement;
  ch: string;
  gx: number;
  gy: number;
  isGreen: boolean;
  lum: number;
}

interface Ripple {
  ox: number;
  oy: number;
  born: number;
  spd: number;
  life: number;
  amp: number;
}

export default function KrakenOrb({ size = 112, className, style }: KrakenOrbProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const orbRef = useRef<HTMLDivElement | null>(null);
  const surfaceRef = useRef<HTMLPreElement | null>(null);

  useEffect(() => {
    const containerNullable = containerRef.current;
    const surfaceNullable = surfaceRef.current;
    const orb = orbRef.current;
    if (!containerNullable || !surfaceNullable || !orb) return;
    const container: HTMLDivElement = containerNullable;
    const surface: HTMLPreElement = surfaceNullable;

    const prefersReducedMotion =
      typeof window !== 'undefined' &&
      typeof window.matchMedia === 'function' &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    const KPLAIN = MASK_PLAIN.split('\n');
    const KGREEN = MASK_GREEN;

    const cellEls: Cell[] = [];
    const ripples: Ripple[] = [];

    // Build ramp neighbor map for shimmer character swaps
    const RAMP_CLOSE: Record<string, string[]> = {};
    for (let i = 1; i < RAMP2.length; i++) {
      const ch = RAMP2[i];
      const left = RAMP2[Math.max(1, i - 1)];
      const right = RAMP2[Math.min(RAMP2.length - 1, i + 1)];
      RAMP_CLOSE[ch] = [left, ch, right];
    }

    // Build the orb DOM
    surface.innerHTML = '';
    const frag = document.createDocumentFragment();
    for (let gy = 0; gy < MASK_ROWS; gy++) {
      const row = KPLAIN[gy] || '';
      for (let gx = 0; gx < MASK_COLS; gx++) {
        const ch = row[gx] || ' ';
        const e = document.createElement('i');
        const isGreen = KGREEN[gy * MASK_COLS + gx] === '1';
        const lum = chBright(ch);
        if (ch === ' ' || ch === '.') {
          e.className = 'kraken-void';
          e.textContent = ' ';
        } else if (isGreen) {
          e.className = lum > 0.5 ? 'kraken-iris' : 'kraken-iris-d';
          e.textContent = ch;
        } else {
          let bucket: string;
          if (lum < 0.15) bucket = 'kraken-d0';
          else if (lum < 0.3) bucket = 'kraken-d1';
          else if (lum < 0.45) bucket = 'kraken-d2';
          else if (lum < 0.6) bucket = 'kraken-d3';
          else if (lum < 0.75) bucket = 'kraken-d4';
          else if (lum < 0.9) bucket = 'kraken-d5';
          else bucket = 'kraken-d6';
          e.className = bucket;
          e.textContent = ch;
        }
        cellEls.push({ el: e, ch, gx, gy, isGreen, lum });
        frag.appendChild(e);
      }
      frag.appendChild(document.createTextNode('\n'));
    }
    surface.appendChild(frag);

    // ----- Intro: blank visible cells so the form-up animation owns first paint -----
    // Cells flagged with dataset.morphing are skipped by updateSurface and morphPalette,
    // so the kraken art only appears once introScrambleStep clears the flag.
    // Skipped under prefers-reduced-motion so the static kraken renders immediately.
    if (!prefersReducedMotion) {
      for (let i = 0; i < cellEls.length; i++) {
        const c = cellEls[i];
        if (c.ch === ' ' || c.ch === '.') continue;
        c.el.dataset.morphing = '1';
        c.el.textContent = ' ';
        c.el.className = 'kraken-void';
      }
    }

    // ----- Ripple system -----
    const RIPPLE_WIDTH = 2.2;
    const RIPPLE_AMP = 0.55;
    const RIPPLE_TROUGH = -0.18;
    let nextRippleAt = 0;

    function spawnRipple(now: number) {
      let pick: Cell | null = null;
      for (let tries = 0; tries < 20; tries++) {
        const c = cellEls[Math.floor(Math.random() * cellEls.length)];
        if (c.ch !== ' ' && c.ch !== '.') {
          pick = c;
          break;
        }
      }
      if (!pick) return;
      ripples.push({
        ox: pick.gx,
        oy: pick.gy,
        born: now,
        spd: 14 + Math.random() * 8,
        life: 1.8 + Math.random() * 1.2,
        amp: RIPPLE_AMP * (0.7 + Math.random() * 0.6),
      });
    }

    function rippleAt(c: Cell, t: number): number {
      if (ripples.length === 0) return 0;
      let total = 0;
      for (let k = 0; k < ripples.length; k++) {
        const rp = ripples[k];
        const age = t - rp.born;
        if (age < 0 || age > rp.life) continue;
        const dx = c.gx - rp.ox;
        const dy = c.gy - rp.oy;
        const dist = Math.sqrt(dx * dx + dy * dy);
        const front = age * rp.spd;
        const offset = dist - front;
        const w = RIPPLE_WIDTH;
        const fade = 1 - age / rp.life;
        let v = 0;
        if (offset > -w && offset < w) {
          v = Math.exp(-(offset * offset) / (w * w * 0.6)) * rp.amp * fade;
        } else if (offset > w && offset < w * 3) {
          const t2 = (offset - w) / (w * 2);
          v = RIPPLE_TROUGH * (1 - t2) * fade;
        }
        total += v;
      }
      return total;
    }

    function updateSurface(t: number) {
      if (t > nextRippleAt) {
        spawnRipple(t);
        if (Math.random() < 0.25) spawnRipple(t);
        nextRippleAt = t + 0.5 + Math.random() * 1.8;
      }
      for (let k = ripples.length - 1; k >= 0; k--) {
        if (t - ripples[k].born > ripples[k].life) ripples.splice(k, 1);
      }

      for (let i = 0; i < cellEls.length; i++) {
        const c = cellEls[i];
        if (c.ch === ' ' || c.ch === '.') continue;
        if (c.el.dataset.morphing === '1') continue;
        if (c.el.dataset.gone === '1') continue;
        const shimmer =
          Math.sin(t * 1.3 + (c.gx * 0.18 + c.gy * 0.22)) * 0.12 +
          Math.sin(t * 0.7 + c.gx * 0.1 - c.gy * 0.07) * 0.08;
        const ripple = rippleAt(c, t);
        const lum = Math.max(0, Math.min(1, c.lum + shimmer + ripple));
        let cls: string;
        if (c.isGreen) {
          cls = lum > 0.5 ? 'kraken-iris' : 'kraken-iris-d';
        } else {
          if (lum < 0.15) cls = 'kraken-d0';
          else if (lum < 0.3) cls = 'kraken-d1';
          else if (lum < 0.45) cls = 'kraken-d2';
          else if (lum < 0.6) cls = 'kraken-d3';
          else if (lum < 0.75) cls = 'kraken-d4';
          else if (lum < 0.9) cls = 'kraken-d5';
          else cls = 'kraken-d6';
        }
        if (c.el.className !== cls) c.el.className = cls;

        if (ripple > 0.18) {
          const baseIdx = RAMP2.indexOf(c.ch);
          const bumpedIdx = Math.min(RAMP2.length - 1, baseIdx + Math.round(ripple * 14));
          const pick = RAMP2[bumpedIdx];
          if (c.el.textContent !== pick) c.el.textContent = pick;
        } else {
          const swap = noise(c.gx + Math.floor(t * 1.5), c.gy);
          if (swap > 0.94) {
            const variants = RAMP_CLOSE[c.ch];
            if (variants) {
              const pick = variants[Math.floor(noise(c.gx, c.gy + Math.floor(t * 1.5)) * variants.length) % variants.length];
              if (c.el.textContent !== pick) c.el.textContent = pick;
            }
          } else if (c.el.textContent !== c.ch) {
            c.el.textContent = c.ch;
          }
        }
      }
    }

    updateSurface(0);
    let lastSurfT = 0;
    let surfaceRAF = 0;
    function surfaceLoop(now: number) {
      const t = now / 1000;
      if (now - lastSurfT > 50) {
        updateSurface(t);
        lastSurfT = now;
      }
      surfaceRAF = requestAnimationFrame(surfaceLoop);
    }
    if (!prefersReducedMotion) {
      surfaceRAF = requestAnimationFrame(surfaceLoop);
    }

    // ----- Palette morph cycle (scoped to container) -----
    let paletteIdx = 0;
    function applyPalette(p: string[]) {
      if (!container) return;
      container.style.setProperty('--c0', p[0]);
      container.style.setProperty('--c1', p[1]);
      container.style.setProperty('--c2', p[2]);
      container.style.setProperty('--c3', p[3]);
      container.style.setProperty('--c4', p[4]);
      container.style.setProperty('--c5', p[5]);
      container.style.setProperty('--c6', p[6]);
      container.style.setProperty('--ci', p[7]);
      container.style.setProperty('--ci-glow', p[8]);
      container.style.setProperty('--cid', p[9]);
    }
    applyPalette(PALETTES[0]);

    let morphing = false;
    const pendingTimeouts = new Set<ReturnType<typeof setTimeout>>();
    function scheduleTimeout(fn: () => void, ms: number) {
      const id = setTimeout(() => {
        pendingTimeouts.delete(id);
        fn();
      }, ms);
      pendingTimeouts.add(id);
      return id;
    }

    // ----- Intro: paint a full circle in the active palette, then run the same scramble char-morph (see morphPalette) into the kraken. -----
    function originalClass(c: Cell): string {
      if (c.isGreen) return c.lum > 0.5 ? 'kraken-iris' : 'kraken-iris-d';
      if (c.lum < 0.15) return 'kraken-d0';
      if (c.lum < 0.3) return 'kraken-d1';
      if (c.lum < 0.45) return 'kraken-d2';
      if (c.lum < 0.6) return 'kraken-d3';
      if (c.lum < 0.75) return 'kraken-d4';
      if (c.lum < 0.9) return 'kraken-d5';
      return 'kraken-d6';
    }

    // Cells are ~8px tall, ~4.8px wide (monospace), so we need RX > RY in cell
    // units for the disc to *look* circular on screen: RX ≈ RY * (cellH/cellW).
    const ORB_CX = 50;
    const ORB_CY = 27;
    const ORB_RY = 19;
    const ORB_RX = 32; // ≈ RY * 1.67
    // Off-center highlight position for sphere shading (normalized -1..1).
    const HX = -0.35;
    const HY = -0.45;

    function classForLum(l: number): string {
      if (l < 0.15) return 'kraken-d0';
      if (l < 0.3) return 'kraken-d1';
      if (l < 0.45) return 'kraken-d2';
      if (l < 0.6) return 'kraken-d3';
      if (l < 0.75) return 'kraken-d4';
      if (l < 0.9) return 'kraken-d5';
      return 'kraken-d6';
    }
    function charForLum(l: number): string {
      const idx = Math.min(RAMP2.length - 1, Math.max(1, Math.round(l * (RAMP2.length - 1))));
      return RAMP2[idx];
    }
    // Green ramp for the intro hex — applied inline so it overrides the palette
    // classes; cleared when each cell settles so the kraken inherits the active
    // palette colors.
    const HEX_GREEN_RAMP = ['#0a2010', '#143820', '#205830', '#308040', '#48b058', '#78d878', '#c8ffc0'];
    function greenForLum(l: number): string {
      if (l < 0.15) return HEX_GREEN_RAMP[0];
      if (l < 0.3) return HEX_GREEN_RAMP[1];
      if (l < 0.45) return HEX_GREEN_RAMP[2];
      if (l < 0.6) return HEX_GREEN_RAMP[3];
      if (l < 0.75) return HEX_GREEN_RAMP[4];
      if (l < 0.9) return HEX_GREEN_RAMP[5];
      return HEX_GREEN_RAMP[6];
    }

    // Pointy-top hexagon inscribed in the (RX, RY) ellipse. Same RX/RY ratio as
    // the disc keeps it visually regular under the cell aspect ratio.
    const SQRT3 = Math.sqrt(3);
    const krakenCells: Cell[] = [];
    const extraDiscEls: HTMLElement[] = [];
    for (let i = 0; i < cellEls.length; i++) {
      const c = cellEls[i];
      const isKraken = c.ch !== ' ' && c.ch !== '.';
      if (isKraken) krakenCells.push(c);
      const ndx = (c.gx - ORB_CX) / ORB_RX;
      const ndy = (c.gy - ORB_CY) / ORB_RY;
      const ax = Math.abs(ndx);
      const ay = Math.abs(ndy);
      // Inside pointy-top hex: |a| <= √3/2  AND  |a|/√3 + |b| <= 1
      if (ax > SQRT3 / 2 || ax / SQRT3 + ay > 1) continue;
      // Hex distance metric (0 at center, 1 at boundary) for sphere shading.
      const hexD = Math.max(ay, ay / 2 + ax * SQRT3 / 2);
      const depth = Math.sqrt(Math.max(0, 1 - hexD * hexD));
      const hd = Math.hypot(ndx - HX, ndy - HY);
      const highlight = Math.max(0, 1 - hd * 1.4) * 0.55;
      const lum = Math.min(1, depth * 0.55 + highlight);
      c.el.textContent = charForLum(lum);
      c.el.className = classForLum(lum);
      c.el.style.color = greenForLum(lum);
      if (lum > 0.85) c.el.style.textShadow = '0 0 5px rgba(120, 216, 120, 0.55)';
      if (!isKraken) extraDiscEls.push(c.el);
    }

    // Each cell gets its own settle threshold so the disc dissolves smoothly into
    // the kraken instead of a hard cut. Extras (disc cells outside the kraken
    // silhouette) settle in the first half — the disc visibly shrinks to expose
    // the kraken's outline. Kraken cells settle through the second half — they
    // briefly scramble in place, then snap to their final char.
    interface IntroAnimItem {
      el: HTMLElement;
      thr: number;
      settled: boolean;
      finalCh: string;
      finalCls: string;
    }
    const animItems: IntroAnimItem[] = [];
    for (let i = 0; i < krakenCells.length; i++) {
      const c = krakenCells[i];
      animItems.push({
        el: c.el,
        thr: 0.32 + Math.random() * 0.68,
        settled: false,
        finalCh: c.ch,
        finalCls: originalClass(c),
      });
    }
    for (let i = 0; i < extraDiscEls.length; i++) {
      animItems.push({
        el: extraDiscEls[i],
        thr: Math.random() * 0.58,
        settled: false,
        finalCh: ' ',
        finalCls: 'kraken-void',
      });
    }

    const INTRO_HOLD_MS = 110;
    const INTRO_DURATION_MS = 280;
    const INTRO_SCRAMBLE_WIN = 0.18; // fraction of duration before settle

    let introRAF = 0;
    function startIntroMorph() {
      const start = performance.now();
      function step() {
        const t = Math.min(1, (performance.now() - start) / INTRO_DURATION_MS);
        for (let i = 0; i < animItems.length; i++) {
          const item = animItems[i];
          if (item.settled) continue;
          if (t >= item.thr) {
            item.el.style.color = '';
            item.el.style.textShadow = '';
            item.el.textContent = item.finalCh;
            item.el.className = item.finalCls;
            delete item.el.dataset.morphing;
            item.settled = true;
          } else if (t >= item.thr - INTRO_SCRAMBLE_WIN) {
            const ch = RAMP_SCRAMBLE[Math.floor(Math.random() * RAMP_SCRAMBLE.length)];
            item.el.textContent = ch;
          }
        }
        if (t < 1) {
          introRAF = requestAnimationFrame(step);
        } else {
          introRAF = 0;
        }
      }
      introRAF = requestAnimationFrame(step);
    }

    if (!prefersReducedMotion) {
      scheduleTimeout(startIntroMorph, INTRO_HOLD_MS);
    }

    function morphPalette() {
      if (morphing) return;
      morphing = true;
      paletteIdx = (paletteIdx + 1) % PALETTES.length;
      const next = PALETTES[paletteIdx];

      const cells = cellEls.filter((c) => c.ch !== ' ' && c.ch !== '.');
      cells.forEach((c) => {
        c.el.dataset.morphing = '1';
      });
      let scrambleTicks = 0;
      const TICK_MS = 90;
      const SCRAMBLE_TICKS = 7;
      function scrambleStep() {
        cells.forEach((c) => {
          const ch = RAMP_SCRAMBLE[Math.floor(Math.random() * RAMP_SCRAMBLE.length)];
          c.el.textContent = ch;
        });
        scrambleTicks++;
        if (scrambleTicks === Math.floor(SCRAMBLE_TICKS / 2)) {
          applyPalette(next);
        }
        if (scrambleTicks < SCRAMBLE_TICKS) {
          scheduleTimeout(scrambleStep, TICK_MS);
        } else {
          cells.forEach((c) => {
            c.el.textContent = c.ch;
            delete c.el.dataset.morphing;
          });
          morphing = false;
        }
      }
      scrambleStep();
    }

    function scheduleMorph() {
      const wait = 3000 + Math.random() * 800;
      scheduleTimeout(() => {
        morphPalette();
        scheduleMorph();
      }, wait);
    }
    if (!prefersReducedMotion) {
      scheduleMorph();
    }

    // The <pre> renders at its natural content size (~50 rows × 8px = 400px tall;
    // width depends on monospace char aspect). Scale by height so the orb body
    // (~30 visible rows) fills the container.
    const baseScale = size / 560;
    orb.style.transform = `translate(-50%, -50%) scale(${baseScale})`;

    // ----- Click-to-shatter -----
    interface SelectedCell {
      cell: HTMLElement;
      ccx: number;
      ccy: number;
      dist: number;
    }

    function regrow(selected: SelectedCell[], hitX: number, hitY: number, maxDist: number) {
      const list = selected
        .map((s) => ({ cell: s.cell, d: Math.hypot(s.ccx - hitX, s.ccy - hitY) }))
        .sort((a, b) => a.d - b.d);
      const REGROW_MS = 420;
      list.forEach((entry) => {
        const norm = entry.d / Math.max(1, maxDist);
        const t = Math.pow(norm, 0.85) * REGROW_MS;
        scheduleTimeout(() => {
          const cell = entry.cell;
          if (cell.dataset.gone !== '1') return;
          const ch = cell.dataset.origCh;
          const cls = cell.dataset.origCls;
          if (ch != null) cell.textContent = ch;
          if (cls) cell.className = cls;
          delete cell.dataset.gone;
          delete cell.dataset.origCh;
          delete cell.dataset.origCls;
          cell.style.textShadow = '';
          cell.style.filter = '';
          cell.animate(
            [
              { opacity: 0, filter: 'brightness(2.6)', textShadow: '0 0 6px #ffd49a' },
              { opacity: 0.85, filter: 'brightness(1.6)', textShadow: '0 0 3px #ffd49a', offset: 0.55 },
              { opacity: 1, filter: 'brightness(1)', textShadow: 'none' },
            ],
            { duration: 260, easing: 'cubic-bezier(.22,.61,.36,1)' },
          );
        }, t);
      });
    }

    function shatter(hitX: number, hitY: number) {
      const surfaceRect = surface.getBoundingClientRect();
      const containerRect = container.getBoundingClientRect();
      if (surfaceRect.width === 0) return;

      const orbRadius = Math.min(surfaceRect.width, surfaceRect.height) * 0.5;
      const chunkRadius = orbRadius * (0.10 + Math.random() * 0.12);
      const angle = Math.random() * Math.PI * 2;
      const ax = Math.cos(angle), ay = Math.sin(angle);
      const elongate = 0.75 + Math.random() * 0.5;

      // Shockwave ring (relative to container)
      const shock = document.createElement('div');
      shock.className = 'kraken-shock';
      const SZ = chunkRadius * 0.5;
      shock.style.width = `${SZ}px`;
      shock.style.height = `${SZ}px`;
      shock.style.left = `${hitX - SZ / 2 - containerRect.left}px`;
      shock.style.top = `${hitY - SZ / 2 - containerRect.top}px`;
      container.appendChild(shock);
      const shockScale = (chunkRadius * 1.4) / SZ;
      const shockAnim = shock.animate(
        [
          { transform: 'scale(0.5)', opacity: 0.55 },
          { transform: `scale(${shockScale})`, opacity: 0 },
        ],
        { duration: 520, easing: 'cubic-bezier(.16,.85,.3,1)' },
      );
      shockAnim.onfinish = () => shock.remove();

      // Select cells inside the chunk
      const selected: SelectedCell[] = [];
      let maxDist = 0;
      for (let i = 0; i < cellEls.length; i++) {
        const c = cellEls[i];
        if (c.ch === ' ' || c.ch === '.') continue;
        if (c.el.dataset.gone === '1') continue;
        const cr = c.el.getBoundingClientRect();
        if (cr.width === 0) continue;
        const ccx = cr.left + cr.width / 2;
        const ccy = cr.top + cr.height / 2;
        const dx = ccx - hitX;
        const dy = ccy - hitY;
        const u = dx * ax + dy * ay;
        const v = -dx * ay + dy * ax;
        const dist = Math.sqrt((u / elongate) * (u / elongate) + (v * elongate) * (v * elongate));
        const edgeJitter = (Math.random() - 0.5) * chunkRadius * 0.30;
        if (dist < chunkRadius + edgeJitter) {
          const trueDist = Math.hypot(dx, dy);
          if (trueDist > maxDist) maxDist = trueDist;
          selected.push({ cell: c.el, ccx, ccy, dist: trueDist });
        }
      }
      if (selected.length === 0) return;
      if (maxDist < 1) maxDist = 1;

      const SWEEP_MS = 300;
      const FLASH_MS = 100;
      const fragSize = Math.max(6, baseScale * 9);

      selected.forEach((s) => {
        const norm = s.dist / maxDist;
        // Ease-out cascade: cells near the hit fire quickly, distant ones stretch out gracefully.
        const t = (1 - Math.pow(1 - norm, 1.8)) * SWEEP_MS;
        scheduleTimeout(() => {
          const cell = s.cell;
          if (cell.dataset.gone === '1') return;
          const origCh = cell.textContent ?? ' ';
          const origCls = cell.className;

          // Smooth hot flash via WAAPI — brightness/scale ramps in, fades to detach.
          cell.animate(
            [
              { filter: 'brightness(1)', textShadow: 'none', transform: 'scale(1)' },
              { filter: 'brightness(2.4)', textShadow: '0 0 8px #ffd49a, 0 0 14px #f0a858', transform: 'scale(1.18)', offset: 0.55 },
              { filter: 'brightness(1.8)', textShadow: '0 0 5px #ffd49a', transform: 'scale(1.05)' },
            ],
            { duration: FLASH_MS, easing: 'cubic-bezier(.22,.61,.36,1)', fill: 'forwards' },
          );
          cell.textContent = '@';
          cell.className = 'kraken-d6';

          scheduleTimeout(() => {
            if (cell.dataset.gone === '1') return;
            const cr = cell.getBoundingClientRect();
            // Mark gone & blank the cell first so updateSurface skips it
            cell.dataset.gone = '1';
            cell.dataset.origCh = origCh;
            cell.dataset.origCls = origCls;
            cell.textContent = ' ';
            cell.className = 'kraken-void';
            cell.style.textShadow = '';
            cell.style.filter = '';
            cell.style.transform = '';

            if (cr.width === 0) return;

            const f = document.createElement('div');
            f.className = 'kraken-frag';
            f.textContent = origCh;
            f.style.left = `${cr.left - containerRect.left}px`;
            f.style.top = `${cr.top - containerRect.top}px`;
            f.style.fontSize = `${fragSize}px`;
            f.style.lineHeight = `${fragSize}px`;
            container.appendChild(f);

            // Outward ballistics — smoother arc with two intermediate keyframes for an
            // eased rise then settle, and a longer life so motion blur isn't choppy.
            const dx2 = s.ccx - hitX;
            const dy2 = s.ccy - hitY;
            const distP = Math.hypot(dx2, dy2) || 1;
            const ux = dx2 / distP, uy = dy2 / distP;
            const distNorm = s.dist / maxDist;
            const power = (38 + distNorm * 80 + Math.random() * 40) * Math.max(0.6, baseScale);
            const tx = ux * power + (Math.random() - 0.5) * 18;
            const ty = uy * power + (Math.random() - 0.5) * 18 - 12;
            const rot = (Math.random() - 0.5) * 360;
            const dur = 580 + Math.random() * 280;
            const anim = f.animate(
              [
                { transform: 'translate(0,0) rotate(0deg) scale(1.15)', opacity: 1 },
                { transform: `translate(${tx * 0.35}px, ${ty * 0.35 - 6}px) rotate(${rot * 0.3}deg) scale(1.05)`, opacity: 0.95, offset: 0.3 },
                { transform: `translate(${tx * 0.7}px, ${ty * 0.7 - 2}px) rotate(${rot * 0.6}deg) scale(0.92)`, opacity: 0.7, offset: 0.65 },
                { transform: `translate(${tx}px, ${ty + 32}px) rotate(${rot}deg) scale(0.5)`, opacity: 0 },
              ],
              { duration: dur, easing: 'cubic-bezier(.22,.61,.36,1)', fill: 'forwards' },
            );
            anim.onfinish = () => f.remove();
          }, FLASH_MS - 20);
        }, t);
      });

      scheduleTimeout(
        () => regrow(selected, hitX, hitY, maxDist),
        SWEEP_MS + 480 + Math.random() * 180,
      );
    }

    function handlePointerDown(e: PointerEvent) {
      shatter(e.clientX, e.clientY);
    }
    container.addEventListener('pointerdown', handlePointerDown);

    return () => {
      cancelAnimationFrame(surfaceRAF);
      if (introRAF) cancelAnimationFrame(introRAF);
      pendingTimeouts.forEach((id) => clearTimeout(id));
      pendingTimeouts.clear();
      container.removeEventListener('pointerdown', handlePointerDown);
      // Clean up any in-flight fragments / shockwave
      container.querySelectorAll('.kraken-frag, .kraken-shock').forEach((el) => el.remove());
    };
  }, [size]);

  return (
    <div
      ref={containerRef}
      className={className}
      style={{
        width: size,
        height: size,
        position: 'relative',
        cursor: 'pointer',
        ...style,
      }}
    >
      {/* Outer halo — extends past the clip box for a glow that radiates outward */}
      <div className="kraken-orb-halo kraken-orb-halo-outer" aria-hidden />
      {/* Inner halo — tighter, brighter, tracks the iris color */}
      <div className="kraken-orb-halo kraken-orb-halo-inner" aria-hidden />

      {/* Clip box for the ASCII orb itself (its natural pre is wider than the visible area) */}
      <div style={{ position: 'absolute', inset: 0, overflow: 'hidden' }}>
        <div
          ref={orbRef}
          style={{
            position: 'absolute',
            left: '50%',
            top: '50%',
            transformOrigin: 'center center',
            willChange: 'transform',
            pointerEvents: 'none',
          }}
        >
          <pre
            ref={surfaceRef}
            className="kraken-orb-surface"
            style={{
              fontFamily: '"SF Mono", "JetBrains Mono", Menlo, Consolas, monospace',
              fontSize: 14,
              lineHeight: '14px',
              letterSpacing: 0,
              whiteSpace: 'pre',
              margin: 0,
              color: 'var(--c4, #e08a3a)',
              fontWeight: 650,
              textShadow: '0 0 4px rgba(224,138,58,.18)',
              pointerEvents: 'none',
            }}
          />
        </div>
      </div>
      <style jsx global>{`
        @keyframes kraken-halo-pulse {
          0%, 100% { transform: translate(-50%, -50%) scale(1);    opacity: .32; }
          50%      { transform: translate(-50%, -50%) scale(1.04); opacity: .48; }
        }
        @keyframes kraken-halo-pulse-outer {
          0%, 100% { transform: translate(-50%, -50%) scale(1) rotate(0deg);  opacity: .18; }
          50%      { transform: translate(-50%, -50%) scale(1.05) rotate(4deg); opacity: .28; }
        }
        .kraken-orb-halo {
          position: absolute;
          left: 50%;
          top: 50%;
          border-radius: 50%;
          pointer-events: none;
          transform: translate(-50%, -50%);
          transition: background .8s ease;
          mix-blend-mode: screen;
          will-change: transform, opacity;
        }
        .kraken-orb-halo-inner {
          width: 90%;
          height: 90%;
          background: radial-gradient(circle at center,
            color-mix(in srgb, var(--ci, #7ee07e) 28%, transparent) 0%,
            color-mix(in srgb, var(--ci, #7ee07e) 12%, transparent) 35%,
            color-mix(in srgb, var(--ci, #7ee07e)  3%, transparent) 60%,
            transparent 78%);
          filter: blur(20px);
          animation: kraken-halo-pulse 5.5s ease-in-out infinite;
        }
        .kraken-orb-halo-outer {
          width: 145%;
          height: 145%;
          background: radial-gradient(circle at center,
            color-mix(in srgb, var(--c5, #f0a858) 10%, transparent) 0%,
            color-mix(in srgb, var(--c5, #f0a858)  4%, transparent) 38%,
            transparent 70%);
          filter: blur(40px);
          animation: kraken-halo-pulse-outer 10s ease-in-out infinite;
        }
        .kraken-orb-surface i { font-style: normal; display: inline; }
        .kraken-orb-surface .kraken-void { color: transparent; }
        .kraken-orb-surface .kraken-d0 { color: var(--c0, #3a1c10); transition: color 1s ease; }
        .kraken-orb-surface .kraken-d1 { color: var(--c1, #6a3018); transition: color 1s ease; }
        .kraken-orb-surface .kraken-d2 { color: var(--c2, #a04820); transition: color 1s ease; }
        .kraken-orb-surface .kraken-d3 { color: var(--c3, #cc6a30); transition: color 1s ease; }
        .kraken-orb-surface .kraken-d4 { color: var(--c4, #e08a3a); transition: color 1s ease; }
        .kraken-orb-surface .kraken-d5 { color: var(--c5, #f0a858); transition: color 1s ease; }
        .kraken-orb-surface .kraken-d6 { color: var(--c6, #ffd49a); transition: color 1s ease; }
        .kraken-orb-surface .kraken-iris {
          color: var(--ci, #7ee07e);
          text-shadow: 0 0 6px var(--ci-glow, rgba(126,224,126,.7));
          transition: color 1s ease, text-shadow 1s ease;
        }
        .kraken-orb-surface .kraken-iris-d { color: var(--cid, #3aa03a); transition: color 1s ease; }
        .kraken-frag {
          position: absolute;
          font-family: "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
          color: #ffd49a;
          text-shadow: 0 0 6px rgba(255,212,154,.6);
          pointer-events: none;
          will-change: transform, opacity;
          letter-spacing: 0;
          white-space: pre;
        }
        .kraken-shock {
          position: absolute;
          border-radius: 50%;
          border: 1px solid color-mix(in srgb, var(--c5, #f0a858) 45%, transparent);
          pointer-events: none;
          box-shadow: 0 0 8px rgba(240,168,88,.18);
        }
        @media (prefers-reduced-motion: reduce) {
          .kraken-orb-halo-inner,
          .kraken-orb-halo-outer {
            animation: none;
          }
          .kraken-orb-surface .kraken-d0,
          .kraken-orb-surface .kraken-d1,
          .kraken-orb-surface .kraken-d2,
          .kraken-orb-surface .kraken-d3,
          .kraken-orb-surface .kraken-d4,
          .kraken-orb-surface .kraken-d5,
          .kraken-orb-surface .kraken-d6,
          .kraken-orb-surface .kraken-iris,
          .kraken-orb-surface .kraken-iris-d {
            transition: none;
          }
        }
      `}</style>
    </div>
  );
}
