import { NextRequest } from 'next/server';
import fs from 'fs';
import path from 'path';
import { buildPostHogSnippet } from '@/lib/posthogSnippet';

const SHOWCASES_ENABLED = process.env.VIGOLIUM_SHOWCASES_ENABLED === 'true';
const POSTHOG_SNIPPET = buildPostHogSnippet({ capturePageview: true });

interface ProjectStats {
  project: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
  project_desc?: string;
  project_link?: string;
  github_stars?: string;
}

interface StatsData {
  generated_at: string;
  project_count: number;
  summary: { total: number; critical: number; high: number; medium: number };
  projects: ProjectStats[];
}

export async function GET(req: NextRequest) {
  if (!SHOWCASES_ENABLED) {
    return new Response('Not Found', { status: 404 });
  }

  const statsPath = path.join(process.cwd(), 'showcases', 'stats.json');
  if (!fs.existsSync(statsPath)) {
    return new Response('Not Found', { status: 404 });
  }

  const stats: StatsData = JSON.parse(fs.readFileSync(statsPath, 'utf-8'));

  // Forward view_key from query string into report links
  const viewKey = req.nextUrl.searchParams.get('view_key');
  const keySuffix = viewKey ? `?view_key=${encodeURIComponent(viewKey)}` : '';

  // Pre-sort by total descending for initial render
  const sortedProjects = stats.projects.sort((a, b) => b.total - a.total);

  // Derive owner/repo from GitHub URL (e.g. https://github.com/apache/airflow -> apache/airflow)
  const deriveRepoName = (link?: string): string => {
    if (!link) return '';
    const m = link.match(/github\.com\/([^/]+\/[^/?#]+)/i);
    return m ? m[1] : '';
  };

  // Embed project data as JSON for client-side sort/search
  const projectsJSON = JSON.stringify(sortedProjects.map((p) => ({
    project: p.project,
    slug: `vigolium-report-${p.project}`,
    total: p.total,
    critical: p.critical,
    high: p.high,
    medium: p.medium,
    desc: p.project_desc || '',
    repo: deriveRepoName(p.project_link),
    link: p.project_link || '',
    stars: p.github_stars || '',
  })));

  const totalFindings = stats.summary.total;
  const critPct = totalFindings > 0 ? (stats.summary.critical / totalFindings * 100) : 0;
  const highPct = totalFindings > 0 ? (stats.summary.high / totalFindings * 100) : 0;
  const medPct = totalFindings > 0 ? (stats.summary.medium / totalFindings * 100) : 0;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Vigolium Static Audit Showcases</title>
  ${POSTHOG_SNIPPET}
  <script>
    (function() {
      try {
        var t = localStorage.getItem('vigolium-showcases-theme');
        if (t === 'dark') document.documentElement.setAttribute('data-theme', 'dark');
      } catch (e) {}
    })();
  </script>
  <style>
    :root {
      --bg-page: #f5f0e8;
      --bg-panel: #ebe6dd;
      --bg-hover: #e2dcd2;
      --border: #d5cfc4;
      --border-hover: #a09888;
      --text: #2c2c2c;
      --text-alt: #4a4a4a;
      --text-soft: #6b6b6b;
      --text-muted: #9a9080;
      --text-faint: #b0a898;
      --link: #2c6fad;
      --grad-top: rgba(232,123,53,0.22);
      --grad-right: rgba(232,160,80,0.14);
      --grad-bottom: rgba(220,100,40,0.08);
      --grid-dot: rgba(44,36,28,0.07);
    }
    :root[data-theme="dark"] {
      --bg-page: #1a1814;
      --bg-panel: #26221d;
      --bg-hover: #322c24;
      --border: #3a342b;
      --border-hover: #5a5248;
      --text: #ece7dc;
      --text-alt: #d2ccc0;
      --text-soft: #9a9488;
      --text-muted: #756f64;
      --text-faint: #4f4a42;
      --link: #6eaeda;
      --grad-top: rgba(232,123,53,0.20);
      --grad-right: rgba(232,180,100,0.08);
      --grad-bottom: rgba(232,123,53,0.06);
      --grid-dot: rgba(255,240,220,0.035);
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    html, body { transition: background-color 0.2s ease, color 0.2s ease; }
    body {
      background-color: var(--bg-page);
      background-image:
        radial-gradient(var(--grid-dot) 1px, transparent 1px),
        radial-gradient(ellipse 960px 480px at 50% -100px, var(--grad-top), transparent 65%),
        radial-gradient(circle 560px at 88% 22%, var(--grad-right), transparent 70%),
        radial-gradient(circle 480px at 12% 82%, var(--grad-bottom), transparent 72%);
      background-size: 24px 24px, auto, auto, auto;
      background-attachment: fixed;
      color: var(--text);
      font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace;
      min-height: 100vh;
    }
    .container { max-width: 1280px; margin: 0 auto; padding: 56px 24px 48px; }

    /* Hero */
    .hero { text-align: center; margin-bottom: 24px; }
    .hero-logo {
      height: 72px; width: 72px;
      border-radius: 14px;
      border: 1px solid rgba(232,123,53,0.4);
      margin-bottom: 16px;
      animation: logo-beat 5.5s ease-in-out infinite;
      cursor: pointer;
      user-select: none;
      will-change: transform, box-shadow;
    }
    .hero-logo:hover { animation-duration: 4.5s; }
    .hero-logo:active { animation-play-state: paused; filter: brightness(0.95); }
    @keyframes logo-beat {
      0%, 100% {
        transform: scale(1);
        box-shadow: 0 0 12px rgba(232,123,53,0.25);
      }
      18% {
        transform: scale(1.06);
        box-shadow: 0 0 28px rgba(232,123,53,0.55), 0 0 48px rgba(232,123,53,0.20);
      }
      32% {
        transform: scale(0.99);
        box-shadow: 0 0 18px rgba(232,123,53,0.32);
      }
      46% {
        transform: scale(1.035);
        box-shadow: 0 0 24px rgba(232,123,53,0.45), 0 0 40px rgba(232,123,53,0.16);
      }
      65% {
        transform: scale(1);
        box-shadow: 0 0 14px rgba(232,123,53,0.28);
      }
    }
    .hero h1 { color: var(--text); font-size: 26px; margin-bottom: 8px; letter-spacing: -0.3px; }
    .hero .tagline { color: var(--text-soft); font-size: 14px; max-width: 560px; margin: 0 auto; line-height: 1.5; }

    /* Insight strip */
    .insight {
      max-width: 640px;
      margin: 28px auto 24px;
      padding: 22px 28px 18px;
      background: var(--bg-panel);
      border: 1px solid var(--border);
    }
    .insight-top {
      display: flex;
      align-items: baseline;
      justify-content: center;
      gap: 14px;
      margin-bottom: 14px;
      flex-wrap: wrap;
    }
    .insight-top .big {
      font-size: 20px;
      font-weight: 700;
      color: var(--text);
      line-height: 1;
    }
    .insight-top .ctx {
      font-size: 13px;
      color: var(--text-soft);
      text-transform: uppercase;
      letter-spacing: 0.6px;
    }
    .insight-top .ctx strong { color: var(--text); font-weight: 700; font-size: 20px; }
    .insight-bar {
      display: flex;
      height: 10px;
      background: var(--border);
      margin-bottom: 12px;
      overflow: hidden;
    }
    .insight-bar .seg-crit { background: #dc2626; }
    .insight-bar .seg-high { background: #e87b35; }
    .insight-bar .seg-med { background: #d4a017; }
    .insight-legend {
      display: flex;
      justify-content: center;
      gap: 24px;
      font-size: 12px;
      color: var(--text-soft);
      text-transform: uppercase;
      letter-spacing: 0.5px;
      flex-wrap: wrap;
    }
    .insight-legend .dot {
      display: inline-block; width: 8px; height: 8px; margin-right: 6px; vertical-align: 0;
    }
    .insight-legend .dot-crit { background: #dc2626; }
    .insight-legend .dot-high { background: #e87b35; }
    .insight-legend .dot-med { background: #d4a017; }
    .insight-legend strong { color: var(--text); font-weight: 700; font-size: 13px; }

    .insight-meta {
      margin-top: 14px;
      padding-top: 12px;
      border-top: 1px solid var(--border);
      text-align: center;
      color: var(--text-muted);
      font-size: 12px;
    }
    .insight-meta a { color: var(--link); text-decoration: none; }
    .insight-meta a:hover { text-decoration: underline; }
    .insight-actions { margin-top: 14px; display: flex; gap: 10px; justify-content: center; flex-wrap: wrap; }

    /* Note */
    .note {
      text-align: center;
      color: var(--text-soft);
      font-size: 13px;
      margin-bottom: 20px;
      border: 1px solid var(--border);
      padding: 10px;
      background: var(--bg-panel);
    }
    .note code { color: var(--link); }
    .note-btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-family: inherit;
      font-size: 12px;
      padding: 6px 14px;
      border: 1px solid var(--border);
      background: var(--bg-page);
      color: var(--text) !important;
      text-decoration: none;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      font-weight: 600;
    }
    .note-btn svg { width: 14px; height: 14px; display: block; }
    .note-btn:hover { border-color: var(--border-hover); background: var(--bg-hover); text-decoration: none !important; }
    .note-btn.primary { background: #e87b35; border-color: #e87b35; color: #fff !important; }
    .note-btn.primary:hover { background: #d96b25; border-color: #d96b25; }

    /* Controls */
    .controls { display: flex; gap: 12px; margin-bottom: 10px; align-items: stretch; }
    .search-box { flex: 1; position: relative; }
    .search-box input { width: 100%; height: 100%; background: var(--bg-panel); border: 1px solid var(--border); color: var(--text); padding: 10px 14px 10px 38px; font-family: inherit; font-size: 14px; outline: none; }
    .search-box input:focus { border-color: var(--border-hover); }
    .search-box input::placeholder { color: var(--text-muted); }
    .search-box .search-icon { position: absolute; left: 12px; top: 50%; transform: translateY(-50%); width: 16px; height: 16px; color: var(--text-muted); pointer-events: none; }

    .dropdown { position: relative; }
    .dropdown-toggle { background: var(--bg-panel); border: 1px solid var(--border); color: var(--text); padding: 10px 34px 10px 14px; font-family: inherit; font-size: 14px; cursor: pointer; height: 100%; white-space: nowrap; position: relative; }
    .dropdown-toggle::after { content: ''; position: absolute; right: 12px; top: 50%; transform: translateY(-50%); border-left: 5px solid transparent; border-right: 5px solid transparent; border-top: 5px solid var(--text-soft); }
    .dropdown-toggle:hover { border-color: var(--border-hover); }
    .dropdown-menu { display: none; position: absolute; top: 100%; right: 0; margin-top: 4px; background: var(--bg-panel); border: 1px solid var(--border); z-index: 10; min-width: 100%; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
    .dropdown-menu.open { display: block; }
    .dropdown-item { padding: 8px 14px; font-family: inherit; font-size: 14px; color: var(--text); cursor: pointer; white-space: nowrap; }
    .dropdown-item:hover { background: var(--bg-hover); }
    .dropdown-item.active { background: var(--border); font-weight: 600; }

    /* Table */
    table { width: 100%; border-collapse: collapse; background: var(--bg-panel); border: 1px solid var(--border); }
    thead th { padding: 12px 14px; text-align: center; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-soft); border-bottom: 2px solid var(--border); background: var(--bg-hover); cursor: pointer; user-select: none; white-space: nowrap; }
    thead th:hover { color: var(--text); }
    thead th .sort-arrow { margin-left: 4px; font-size: 10px; }
    tbody tr:hover { background: var(--bg-hover); }
    tbody td { padding: 12px 14px; border-bottom: 1px solid var(--border); vertical-align: middle; text-align: center; }
    tbody td.project-cell { min-width: 240px; white-space: nowrap; }
    tbody td.project-cell .repo-line { display: inline-flex; align-items: center; justify-content: center; gap: 8px; font-size: 13px; }
    tbody td.project-cell .repo-name { font-weight: 600; color: var(--link); }
    tbody td.project-cell .stars { color: var(--text-muted); font-weight: 400; font-size: 12px; }
    tbody td.project-cell .gh-icon { display: inline-flex; align-items: center; color: var(--text-soft); }
    tbody td.project-cell .gh-icon:hover { color: var(--text); }
    tbody td.project-cell .gh-icon svg { width: 16px; height: 16px; display: block; }
    tbody td.desc-cell { color: var(--text-alt); font-size: 13px; max-width: 380px; line-height: 1.5; text-align: left; }

    a { color: var(--link); text-decoration: none; font-weight: 500; }
    a:hover { text-decoration: underline !important; }
    .no-results { text-align: center; padding: 24px; color: var(--text-muted); }

    /* Pagination */
    .pagination { display: flex; align-items: center; justify-content: space-between; margin-top: 12px; font-size: 13px; color: var(--text-soft); }
    .pagination .page-buttons { display: flex; gap: 6px; }
    .pagination button { background: var(--bg-panel); border: 1px solid var(--border); color: var(--text); padding: 6px 12px; font-family: inherit; font-size: 13px; cursor: pointer; }
    .pagination button:hover:not(:disabled) { background: var(--bg-hover); }
    .pagination button:disabled { color: var(--text-faint); cursor: default; }
    .pagination button.active { background: var(--border); font-weight: 600; }

  </style>
</head>
<body>
  <div class="container">
    <div class="hero">
      <img class="hero-logo" id="theme-toggle" src="/vigolium-logo-minimal.png" alt="Vigolium — click to toggle theme" title="Click to toggle theme" />
      <h1>Vigolium Static Audit Showcases</h1>
      <p class="tagline">Real vulnerability scan reports from popular open-source projects, powered by Vigolium's agentic scanning engine.</p>
    </div>

    <div class="insight">
      <div class="insight-top">
        <div class="big">${stats.summary.total}</div>
        <div class="ctx">findings across <strong>${stats.project_count}</strong> projects</div>
      </div>
      <div class="insight-bar">
        <div class="seg-crit" style="width:${critPct.toFixed(2)}%"></div>
        <div class="seg-high" style="width:${highPct.toFixed(2)}%"></div>
        <div class="seg-med" style="width:${medPct.toFixed(2)}%"></div>
      </div>
      <div class="insight-legend">
        <span><span class="dot dot-crit"></span><strong>${stats.summary.critical}</strong> Critical</span>
        <span><span class="dot dot-high"></span><strong>${stats.summary.high}</strong> High</span>
        <span><span class="dot dot-med"></span><strong>${stats.summary.medium}</strong> Medium</span>
      </div>
      <div class="insight-meta">
        Generated ${new Date(stats.generated_at).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}
        &middot; <a href="https://www.vigolium.com/">vigolium.com</a>
        &middot; <a href="https://docs.vigolium.com/">docs.vigolium.com</a>
      </div>
    </div>

    <div class="note">
      ${viewKey
        ? `<div>Want to scan your own repository? Request a demo below.</div>`
        : `<div>Reports are gated — append <code style="color:#38bdf8">?view_key=YOUR_KEY</code> to any link to unlock. Contact us below for a sample <code style="color:#38bdf8">view_key</code>.</div>`}
      <div class="insight-actions" style="margin-top:12px">
        <a class="note-btn primary" href="https://www.vigolium.com/request-demo" target="_blank" rel="noopener noreferrer" onclick="window.posthog&&window.posthog.capture('request_demo_clicked',{source:'showcases_listing'})">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>
          Request a Demo
        </a>
        <a class="note-btn" href="mailto:contact@vigolium.com">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="5" width="18" height="14" rx="2"/><polyline points="3 7 12 13 21 7"/></svg>
          Contact Us
        </a>
      </div>
    </div>

    <div class="controls">
      <div class="search-box">
        <svg class="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        <input type="text" id="search" placeholder="Search projects..." />
      </div>
      <div class="dropdown" id="dropdown">
        <div class="dropdown-toggle" id="dropdown-toggle">25 / page</div>
        <div class="dropdown-menu" id="dropdown-menu">
          <div class="dropdown-item" data-value="10">10 / page</div>
          <div class="dropdown-item active" data-value="25">25 / page</div>
          <div class="dropdown-item" data-value="50">50 / page</div>
          <div class="dropdown-item" data-value="100">100 / page</div>
        </div>
      </div>
    </div>

    <table>
      <thead>
        <tr>
          <th data-col="project" data-type="string">Project <span class="sort-arrow"></span></th>
          <th data-col="desc" data-type="string" style="text-align:left">Description <span class="sort-arrow"></span></th>
          <th data-col="total" data-type="number">Total <span class="sort-arrow"></span></th>
          <th data-col="critical" data-type="number">Critical <span class="sort-arrow"></span></th>
          <th data-col="high" data-type="number">High <span class="sort-arrow"></span></th>
          <th data-col="medium" data-type="number">Medium <span class="sort-arrow"></span></th>
        </tr>
      </thead>
      <tbody id="tbody"></tbody>
    </table>
    <div class="pagination" id="pagination"></div>
  </div>

  <script>
    (function() {
      var projects = ${projectsJSON};
      var keySuffix = ${JSON.stringify(keySuffix)};
      var sortCol = 'total';
      var sortAsc = false;
      var searchTerm = '';
      var perPage = 25;
      var currentPage = 1;

      function esc(s) {
        return String(s == null ? '' : s)
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#39;');
      }

      function badge(val, bg, fg) {
        if (val > 0) return '<span style="background:' + bg + ';color:' + fg + ';padding:1px 6px;border-radius:3px;font-size:12px">' + val + '</span>';
        return '<span style="color:var(--text-faint)">0</span>';
      }

      function getFiltered() {
        var filtered = projects.filter(function(p) {
          return p.project.toLowerCase().indexOf(searchTerm) !== -1
            || (p.desc && p.desc.toLowerCase().indexOf(searchTerm) !== -1);
        });
        filtered.sort(function(a, b) {
          var va = a[sortCol], vb = b[sortCol];
          if (typeof va === 'string') { va = va.toLowerCase(); vb = vb.toLowerCase(); }
          if (va < vb) return sortAsc ? -1 : 1;
          if (va > vb) return sortAsc ? 1 : -1;
          return b.total - a.total; // stable tiebreak
        });
        return filtered;
      }

      function render() {
        var filtered = getFiltered();
        var totalPages = Math.max(1, Math.ceil(filtered.length / perPage));
        if (currentPage > totalPages) currentPage = totalPages;

        var start = (currentPage - 1) * perPage;
        var pageItems = filtered.slice(start, start + perPage);

        var tbody = document.getElementById('tbody');
        if (filtered.length === 0) {
          tbody.innerHTML = '<tr><td colspan="6" class="no-results">No matching projects</td></tr>';
        } else {
          var ghIcon = '<svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>';
          tbody.innerHTML = pageItems.map(function(p) {
            var label = p.repo || p.project;
            var projectCell = '<div class="repo-line">'
              + '<a class="repo-name" href="/showcases/' + p.slug + keySuffix + '">' + esc(label) + '</a>'
              + (p.stars ? '<span class="stars">(' + esc(p.stars) + ' stars)</span>' : '')
              + (p.link ? '<a class="gh-icon" href="' + esc(p.link) + '" target="_blank" rel="noopener noreferrer" aria-label="View ' + esc(label) + ' on GitHub" title="View on GitHub">' + ghIcon + '</a>' : '')
              + '</div>';
            var descCell = p.desc ? esc(p.desc) : '<span style="color:var(--text-faint)">—</span>';
            return '<tr>'
              + '<td class="project-cell">' + projectCell + '</td>'
              + '<td class="desc-cell">' + descCell + '</td>'
              + '<td style="font-weight:600;color:var(--text)">' + p.total + '</td>'
              + '<td>' + badge(p.critical, '#dc2626', '#fff') + '</td>'
              + '<td>' + badge(p.high, '#e87b35', '#fff') + '</td>'
              + '<td>' + badge(p.medium, '#d4a017', '#fff') + '</td>'
              + '</tr>';
          }).join('');
        }

        // Update sort arrows
        document.querySelectorAll('thead th').forEach(function(th) {
          var arrow = th.querySelector('.sort-arrow');
          if (th.dataset.col === sortCol) {
            arrow.textContent = sortAsc ? '\\u25B2' : '\\u25BC';
          } else {
            arrow.textContent = '';
          }
        });

        // Render pagination
        var pag = document.getElementById('pagination');
        if (filtered.length === 0 || totalPages <= 1) {
          pag.innerHTML = '<span>' + filtered.length + ' of ' + projects.length + ' projects</span><span></span>';
          return;
        }

        var info = 'Showing ' + (start + 1) + '–' + Math.min(start + perPage, filtered.length) + ' of ' + filtered.length + ' projects';
        var buttons = '';

        buttons += '<button ' + (currentPage <= 1 ? 'disabled' : '') + ' data-page="' + (currentPage - 1) + '">&laquo; Prev</button>';
        for (var i = 1; i <= totalPages; i++) {
          buttons += '<button class="' + (i === currentPage ? 'active' : '') + '" data-page="' + i + '">' + i + '</button>';
        }
        buttons += '<button ' + (currentPage >= totalPages ? 'disabled' : '') + ' data-page="' + (currentPage + 1) + '">Next &raquo;</button>';

        pag.innerHTML = '<span class="page-info">' + info + '</span><div class="page-buttons">' + buttons + '</div>';

        pag.querySelectorAll('button[data-page]').forEach(function(btn) {
          btn.addEventListener('click', function() {
            var p = parseInt(btn.dataset.page);
            if (p >= 1 && p <= totalPages) { currentPage = p; render(); }
          });
        });
      }

      // Sort on header click
      document.querySelectorAll('thead th').forEach(function(th) {
        th.addEventListener('click', function() {
          var col = th.dataset.col;
          if (sortCol === col) { sortAsc = !sortAsc; }
          else { sortCol = col; sortAsc = col === 'project'; }
          currentPage = 1;
          render();
        });
      });

      // Search
      document.getElementById('search').addEventListener('input', function(e) {
        searchTerm = e.target.value.toLowerCase();
        currentPage = 1;
        render();
      });

      // Custom dropdown
      var ddToggle = document.getElementById('dropdown-toggle');
      var ddMenu = document.getElementById('dropdown-menu');

      ddToggle.addEventListener('click', function(e) {
        e.stopPropagation();
        ddMenu.classList.toggle('open');
      });

      ddMenu.querySelectorAll('.dropdown-item').forEach(function(item) {
        item.addEventListener('click', function(e) {
          e.stopPropagation();
          perPage = parseInt(item.dataset.value);
          currentPage = 1;
          ddToggle.textContent = item.textContent;
          ddMenu.querySelectorAll('.dropdown-item').forEach(function(i) { i.classList.remove('active'); });
          item.classList.add('active');
          ddMenu.classList.remove('open');
          render();
        });
      });

      document.addEventListener('click', function() {
        ddMenu.classList.remove('open');
      });

      // Theme toggle on logo click
      var themeToggle = document.getElementById('theme-toggle');
      if (themeToggle) {
        themeToggle.addEventListener('click', function() {
          var root = document.documentElement;
          var isDark = root.getAttribute('data-theme') === 'dark';
          if (isDark) {
            root.removeAttribute('data-theme');
            try { localStorage.setItem('vigolium-showcases-theme', 'light'); } catch (e) {}
          } else {
            root.setAttribute('data-theme', 'dark');
            try { localStorage.setItem('vigolium-showcases-theme', 'dark'); } catch (e) {}
          }
        });
      }

      render();
    })();
  </script>
</body>
</html>`;

  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}
