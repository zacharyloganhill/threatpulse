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
    .nav-bell-wrap{position:relative}
    .nav-bell{font-family:'JetBrains Mono',monospace;font-size:10px;letter-spacing:.5px;padding:3px 9px;background:transparent;border:1px solid var(--border,rgba(255,255,255,.07));color:var(--muted,#4e5d72);cursor:pointer;transition:all .15s;line-height:1}
    .nav-bell:hover,.nav-bell.has-notifs{border-color:var(--amber,#e8a530);color:var(--amber,#e8a530)}
    .nav-bell-badge{position:absolute;top:-5px;right:-5px;background:#f0595a;color:#fff;font-family:'JetBrains Mono',monospace;font-size:7px;min-width:14px;height:14px;border-radius:7px;display:none;align-items:center;justify-content:center;font-weight:700;padding:0 2px}
    .nav-notif-drop{position:absolute;top:calc(100% + 6px);right:0;width:300px;background:#0c0f14;border:1px solid rgba(255,255,255,.12);z-index:9999;box-shadow:0 10px 32px rgba(0,0,0,.7);display:none}
    .nav-notif-drop.open{display:block}
    .nav-notif-hdr{padding:7px 12px;border-bottom:1px solid rgba(255,255,255,.07);font-family:'JetBrains Mono',monospace;font-size:7px;letter-spacing:1.5px;color:#4e5d72;text-transform:uppercase;display:flex;justify-content:space-between;align-items:center}
    .nav-notif-hdr a{font-size:7px;color:#00d4aa;text-decoration:none;letter-spacing:1px}
    .nav-notif-item{padding:8px 12px;border-bottom:1px solid rgba(255,255,255,.04);border-left:3px solid transparent;transition:background .12s}
    .nav-notif-item:hover{background:rgba(255,255,255,.02)}
    .nav-notif-item.cr{border-left-color:#f0595a}
    .nav-notif-item.hi{border-left-color:#e8a530}
    .nav-notif-item.ok{border-left-color:#00d4aa}
    .nav-notif-title{font-family:'JetBrains Mono',monospace;font-size:9px;color:#c9d4e3;margin-bottom:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .nav-notif-meta{font-family:'JetBrains Mono',monospace;font-size:7px;color:#4e5d72}
    .nav-notif-empty{padding:16px 12px;font-family:'JetBrains Mono',monospace;font-size:9px;color:#4e5d72;text-align:center}
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
    <div class="nav-bell-wrap" id="nav-bell-wrap">
      <button class="nav-bell" id="nav-bell" onclick="navToggleBell()" title="Notifications">&#9679;</button>
      <span class="nav-bell-badge" id="nav-bell-badge"></span>
      <div class="nav-notif-drop" id="nav-notif-drop">
        <div class="nav-notif-hdr">
          <span>NOTIFICATIONS</span>
          <a href="/index.html">VIEW ALL</a>
        </div>
        <div id="nav-notif-body"><div class="nav-notif-empty">Loading...</div></div>
      </div>
    </div>
    <button class="nav-logout" onclick="navLogout()">LOGOUT</button>
  `;
  topbar.appendChild(right);

  window.navLogout = function () {
    localStorage.clear();
    location.href = '/login.html';
  };

  // Close dropdown when clicking outside
  document.addEventListener('click', function(e) {
    const wrap = document.getElementById('nav-bell-wrap');
    if (wrap && !wrap.contains(e.target)) {
      const drop = document.getElementById('nav-notif-drop');
      if (drop) drop.classList.remove('open');
    }
  });

  window.navToggleBell = function() {
    const drop = document.getElementById('nav-notif-drop');
    if (drop) drop.classList.toggle('open');
  };

  // Verify session + surface /me
  async function navLoadMe() {
    if (!token) return;
    try {
      const r = await fetch('/api/v1/me', { headers: { Authorization: 'Bearer ' + token } });
      if (!r.ok) {
        if (r.status === 401) { localStorage.removeItem('token'); location.href = '/login.html'; }
        return;
      }
      const d = await r.json();
      if (d.username) localStorage.setItem('display_name', d.display_name || d.username);
      if (d.role) localStorage.setItem('role', d.role);
      const userEl = topbar.querySelector('.nav-user');
      if (userEl) {
        const roleLabel = d.role ? ` <span style="font-size:7px;color:var(--muted,#4e5d72);margin-left:4px;letter-spacing:1px">[${d.role.toUpperCase()}]</span>` : '';
        userEl.innerHTML = (d.display_name || d.username || '').toUpperCase() + roleLabel;
      }
    } catch(e) {}
  }
  navLoadMe();

  // Fetch notifications
  async function navLoadNotifications() {
    if (!token) return;
    try {
      const r = await fetch('/api/v1/notifications?limit=6', {
        headers: { Authorization: 'Bearer ' + token }
      });
      if (!r.ok) return;
      const d = await r.json();
      const items = d.notifications || [];
      const unread = items.filter(n => !n.read).length;
      const badge = document.getElementById('nav-bell-badge');
      const bell = document.getElementById('nav-bell');
      if (badge) {
        badge.textContent = unread > 9 ? '9+' : String(unread);
        badge.style.display = unread > 0 ? 'flex' : 'none';
      }
      if (bell && unread > 0) bell.classList.add('has-notifs');
      const body = document.getElementById('nav-notif-body');
      if (!body) return;
      if (!items.length) {
        body.innerHTML = '<div class="nav-notif-empty">No recent notifications</div>';
        return;
      }
      body.innerHTML = items.map(n => {
        const cls = n.severity === 'CRITICAL' ? 'cr' : n.severity === 'HIGH' ? 'hi' : 'ok';
        const ts = (n.timestamp || '').slice(0, 16).replace('T', ' ');
        const title = String(n.title || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
        const detail = String(n.detail || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
        return `<div class="nav-notif-item ${cls}">
          <div class="nav-notif-title">${title}</div>
          <div class="nav-notif-meta">${detail ? detail + ' · ' : ''}${ts}</div>
        </div>`;
      }).join('');
    } catch(e) {}
  }

  navLoadNotifications();
  setInterval(navLoadNotifications, 60000);
})();
