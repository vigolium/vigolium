import { NextRequest } from 'next/server';
import fs from 'fs';
import path from 'path';

const SHOWCASES_ENABLED = process.env.VIGOLIUM_SHOWCASES_ENABLED === 'true';

interface ProjectStats {
  project: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
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

  // Embed project data as JSON for client-side sort/search
  const projectsJSON = JSON.stringify(sortedProjects.map((p) => ({
    project: p.project,
    slug: `vigolium-report-${p.project}`,
    total: p.total,
    critical: p.critical,
    high: p.high,
    medium: p.medium,
  })));

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Vigolium Static Audit Showcases</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { background: #f5f0e8; color: #2c2c2c; font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace; min-height: 100vh; }
    .container { max-width: 960px; margin: 0 auto; padding: 48px 24px; }
    .header { text-align: center; margin-bottom: 40px; }
    .header img { height: 80px; width: 80px; border-radius: 12px; border: 1px solid rgba(232,123,53,0.4); margin-bottom: 16px; animation: logo-glow 3s ease-in-out infinite; }
    @keyframes logo-glow {
      0%, 100% { box-shadow: 0 0 12px rgba(232,123,53,0.25); }
      50% { box-shadow: 0 0 28px rgba(232,123,53,0.55), 0 0 48px rgba(232,123,53,0.20); }
    }
    .header h1 { color: #2c2c2c; font-size: 22px; margin-bottom: 6px; }
    .header p { color: #6b6b6b; font-size: 14px; max-width: 500px; margin: 0 auto 20px; }
    .summary { display: flex; gap: 16px; justify-content: center; margin-bottom: 32px; flex-wrap: wrap; }
    .stat-card { background: #ebe6dd; border: 1px solid #d5cfc4; padding: 14px 24px; text-align: center; min-width: 120px; }
    .stat-card .value { font-size: 28px; font-weight: 700; }
    .stat-card .label { font-size: 12px; color: #6b6b6b; margin-top: 2px; text-transform: uppercase; letter-spacing: 0.5px; }
    .stat-card.critical .value { color: #dc2626; }
    .stat-card.high .value { color: #e87b35; }
    .stat-card.medium .value { color: #d4a017; }
    .stat-card.total .value { color: #2c2c2c; }
    .stat-card.projects .value { color: #6b6b6b; }
    .search-row { display: flex; gap: 12px; margin-bottom: 16px; align-items: stretch; }
    .search-box { flex: 1; }
    .search-box input { width: 100%; height: 100%; background: #ebe6dd; border: 1px solid #d5cfc4; color: #2c2c2c; padding: 10px 14px; font-family: inherit; font-size: 14px; outline: none; }
    .search-box input:focus { border-color: #a09888; }
    .search-box input::placeholder { color: #9a9080; }
    .dropdown { position: relative; }
    .dropdown-toggle { background: #ebe6dd; border: 1px solid #d5cfc4; color: #2c2c2c; padding: 10px 34px 10px 14px; font-family: inherit; font-size: 14px; cursor: pointer; height: 100%; white-space: nowrap; position: relative; }
    .dropdown-toggle::after { content: ''; position: absolute; right: 12px; top: 50%; transform: translateY(-50%); border-left: 5px solid transparent; border-right: 5px solid transparent; border-top: 5px solid #6b6b6b; }
    .dropdown-toggle:hover { border-color: #a09888; }
    .dropdown-menu { display: none; position: absolute; top: 100%; right: 0; margin-top: 4px; background: #ebe6dd; border: 1px solid #d5cfc4; z-index: 10; min-width: 100%; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
    .dropdown-menu.open { display: block; }
    .dropdown-item { padding: 8px 14px; font-family: inherit; font-size: 14px; color: #2c2c2c; cursor: pointer; white-space: nowrap; }
    .dropdown-item:hover { background: #e2dcd2; }
    .dropdown-item.active { background: #d5cfc4; font-weight: 600; }
    .pagination { display: flex; align-items: center; justify-content: space-between; margin-top: 12px; font-size: 13px; color: #6b6b6b; }
    .pagination .page-info { }
    .pagination .page-buttons { display: flex; gap: 6px; }
    .pagination button { background: #ebe6dd; border: 1px solid #d5cfc4; color: #2c2c2c; padding: 6px 12px; font-family: inherit; font-size: 13px; cursor: pointer; }
    .pagination button:hover:not(:disabled) { background: #e2dcd2; }
    .pagination button:disabled { color: #b0a898; cursor: default; }
    .pagination button.active { background: #d5cfc4; font-weight: 600; }
    table { width: 100%; border-collapse: collapse; background: #ebe6dd; border: 1px solid #d5cfc4; }
    thead th { padding: 12px 14px; text-align: left; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; color: #6b6b6b; border-bottom: 2px solid #d5cfc4; background: #e2dcd2; cursor: pointer; user-select: none; white-space: nowrap; }
    thead th:hover { color: #2c2c2c; }
    thead th:nth-child(n+2) { text-align: center; }
    thead th .sort-arrow { margin-left: 4px; font-size: 10px; }
    tbody tr:hover { background: #e2dcd2; }
    tbody td { padding: 10px 14px; border-bottom: 1px solid #d5cfc4; }
    tbody td:nth-child(n+2) { text-align: center; }
    a { color: #2c6fad; text-decoration: none; font-weight: 500; }
    a:hover { text-decoration: underline !important; }
    .no-results { text-align: center; padding: 24px; color: #9a9080; }
    .meta { color: #9a9080; font-size: 13px; margin-top: 12px; }
    .meta a { color: #2c6fad; text-decoration: none; }
    .note { text-align: center; color: #6b6b6b; font-size: 13px; margin-bottom: 24px; border: 1px solid #d5cfc4; padding: 10px; background: #ebe6dd; }
    .note code { color: #2c6fad; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <img src="/vigolium-logo-minimal.png" alt="Vigolium" />
      <h1>Vigolium Static Audit Showcases</h1>
      <p>Real vulnerability scan reports from popular open-source projects, powered by Vigolium's agentic scanning engine.</p>
      <div class="meta">
        Generated ${new Date(stats.generated_at).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}
        &middot; <a href="https://www.vigolium.com/">vigolium.com</a>
        &middot; <a href="https://docs.vigolium.com/">docs</a>
      </div>
    </div>

    <div class="summary">
      <div class="stat-card projects"><div class="value">${stats.project_count}</div><div class="label">Projects</div></div>
      <div class="stat-card total"><div class="value">${stats.summary.total}</div><div class="label">Total</div></div>
      <div class="stat-card critical"><div class="value">${stats.summary.critical}</div><div class="label">Critical</div></div>
      <div class="stat-card high"><div class="value">${stats.summary.high}</div><div class="label">High</div></div>
      <div class="stat-card medium"><div class="value">${stats.summary.medium}</div><div class="label">Medium</div></div>
    </div>

    <div class="note">Reports require a <code style="color:#38bdf8">view_key</code> to access. Append <code style="color:#38bdf8">?view_key=YOUR_KEY</code> to any report link.</div>

    <div class="search-row">
      <div class="search-box">
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

      function badge(val, bg, fg) {
        if (val > 0) return '<span style="background:' + bg + ';color:' + fg + ';padding:1px 6px;border-radius:3px;font-size:12px">' + val + '</span>';
        return '<span style="color:#b0a898">0</span>';
      }

      function getFiltered() {
        var filtered = projects.filter(function(p) {
          return p.project.toLowerCase().indexOf(searchTerm) !== -1;
        });
        filtered.sort(function(a, b) {
          var va = a[sortCol], vb = b[sortCol];
          if (typeof va === 'string') { va = va.toLowerCase(); vb = vb.toLowerCase(); }
          if (va < vb) return sortAsc ? -1 : 1;
          if (va > vb) return sortAsc ? 1 : -1;
          return 0;
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
          tbody.innerHTML = '<tr><td colspan="5" class="no-results">No matching projects</td></tr>';
        } else {
          tbody.innerHTML = pageItems.map(function(p) {
            return '<tr>'
              + '<td><a href="/showcases/' + p.slug + keySuffix + '">' + p.project + '</a></td>'
              + '<td style="font-weight:600;color:#2c2c2c">' + p.total + '</td>'
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

      render();
    })();
  </script>
</body>
</html>`;

  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}
