/**
 * ThreatPulse — Unified Navigation Component
 * Include before </body> on every page.
 * Body attributes:
 *   data-page-title  — shown in topbar center
 *   data-back-url    — if set, shows a BACK button
 */
(function () {
  'use strict';

  const token = localStorage.getItem('token');
  const path  = location.pathname;

  if (!token && !path.endsWith('login.html')) {
    location.href = '/login.html';
    return;
  }

  const topbar = document.querySelector('.topbar');
  if (!topbar) return;

  const pageTitle = document.body.dataset.pageTitle || '';
  const backUrl   = document.body.dataset.backUrl   || '';
  const username  = (localStorage.getItem('display_name') || localStorage.getItem('username') || 'user').toUpperCase();

  const css = `
    .nav-brand{display:flex;align-items:center;gap:10px;flex-shrink:0}
    .nav-logo{font-family:'JetBrains Mono',monospace;font-size:10px;font-weight:700;letter-spacing:3px;color:var(--teal,#00d4aa);text-decoration:none}
    .nav-back{font-family:'JetBrains Mono',monospace;font-size:8px;letter-spacing:1px;color:var(--muted,#4e5d72);text-decoration:none;border:1px solid var(--border,rgba(255,255,255,.07));padding:3px 8px;transition:all .15s}
    .nav-back:hover{color:var(--teal,#00d4aa);border-color:var(--teal,#00d4aa)}
    .nav-sep{width:1px;height:18px;background:var(--border,rgba(255,255,255,.07));flex-shrink:0}
    .nav-title{font-family:'JetBrains Mono',monospace;font-size:9px;letter-spacing:2px;color:var(--muted,#4e5d72)}
    .nav-spacer{flex:1}
    .nav-user{font-family:'JetBrains Mono',monospace;font-size:9px;color:var(--muted,#4e5d72);letter-spacing:.5px}
    .nav-logout{font-family:'JetBrains Mono',monospace;font-size:8px;letter-spacing:1px;padding:3px 9px;background:transparent;border:1px solid var(--border,rgba(255,255,255,.07));color:var(--muted,#4e5d72);cursor:pointer;transition:all .15s}
    .nav-logout:hover{border-color:var(--red,#f0595a);color:var(--red,#f0595a)}
    .nav-pulse{width:5px;height:5px;border-radius:50%;background:var(--teal,#00d4aa);animation:nav-pulse-anim 2.4s ease-in-out infinite;flex-shrink:0}
    @keyframes nav-pulse-anim{0%,100%{opacity:1}50%{opacity:.2}}
  `;
  const style = document.createElement('style');
  style.textContent = css;
  document.head.appendChild(style);

  const brand = document.createElement('div');
  brand.className = 'nav-brand';

  let html = `<div class="nav-pulse"></div><a class="nav-logo" href="/index.html">THREATPULSE</a>`;

  if (backUrl) {
    html += `<a class="nav-back" href="${backUrl}">&#8592; BACK</a>`;
  }

  if (pageTitle) {
    html += `<div class="nav-sep"></div><span class="nav-title">${pageTitle}</span>`;
  }

  brand.innerHTML = html;
  topbar.insertBefore(brand, topbar.firstChild);

  const right = document.createElement('div');
  right.className = 'nav-brand';
  right.style.marginLeft = 'auto';
  right.innerHTML = `
    <span class="nav-user">${username}</span>
    <button class="nav-logout" onclick="navLogout()">LOGOUT</button>
  `;
  topbar.appendChild(right);

  window.navLogout = function () {
    localStorage.clear();
    location.href = '/login.html';
  };
})();
