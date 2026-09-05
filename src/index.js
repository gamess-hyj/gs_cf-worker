/**
 * 게임세상(Gamess) Cloudflare Worker 서비스 점검 안내 & 헬스체크 / 관리자 시스템
 */

import { LOGO_BASE64 } from './logo.js';

// In-Memory Fallback Config Store (KV 미설정 시 동작)
let memoryStore = {
  enabled: true,
  status: "ongoing", // "ongoing" | "scheduled" | "completed"
  title: "게임세상 서비스 정기 점검 안내",
  startTime: "2026-08-25T02:00:00+09:00",
  endTime: "2026-08-26T08:00:00+09:00",
  noticeText: "게임세상 서비스를 보다 안정적이고 원활하게 제공해 드리기 위해 시스템 서버 점검 및 데이터베이스 최적화를 진행하고 있습니다.\n점검 시간 동안에는 게임세상 주요 서비스 이용이 일시 중지되오니 고객 여러분의 양해 부탁드립니다.",
  impactedServices: [
    "www.gamess.co.kr (메인 포털)",
    "play.gamess.co.kr (게임 서비스 & 결제)",
    "emul.gamess.co.kr (에뮬레이터 서비스)",
    "로그인 및 회원 계정 서비스"
  ],
  contactInfo: "support@gamess.co.kr"
};

// Target Health Check Domains
const TARGET_DOMAINS = [
  { domain: "www.gamess.co.kr", name: "메인 포털", url: "https://www.gamess.co.kr/" },
  { domain: "play.gamess.co.kr", name: "게임 서비스", url: "https://play.gamess.co.kr/" },
  { domain: "emul.gamess.co.kr", name: "에뮬레이터 서비스", url: "https://emul.gamess.co.kr/" }
];

// Helper: Escape HTML to prevent XSS
function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Helper: Get Security Headers
function getSecurityHeaders(extraHeaders = {}) {
  return {
    'Content-Security-Policy': "default-src 'self' 'unsafe-inline' data: https:; img-src 'self' data: https:; connect-src 'self' https:;",
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    ...extraHeaders
  };
}

// Helper: Read maintenance config from KV or memory fallback
async function getMaintenanceConfig(env) {
  let config = { ...memoryStore };
  if (env && env.MAINTENANCE_KV) {
    try {
      const data = await env.MAINTENANCE_KV.get('config', { type: 'json' });
      if (data && typeof data === 'object') {
        config = { ...memoryStore, ...data };
      }
    } catch (e) {
      console.error('KV Read Error:', e);
    }
  }
  return config;
}

// Helper: Save maintenance config to KV and memory fallback
async function setMaintenanceConfig(env, newConfig) {
  const current = await getMaintenanceConfig(env);
  const updated = { ...current, ...newConfig };
  memoryStore = updated;
  if (env && env.MAINTENANCE_KV) {
    try {
      await env.MAINTENANCE_KV.put('config', JSON.stringify(updated));
    } catch (e) {
      console.error('KV Write Error:', e);
    }
  }
  return updated;
}

// Helper: Verify Admin Auth Session (Multi-strategy)
async function checkAdminAuth(request, env) {
  const adminSecret = String((env && env.ADMIN_KEY) || (env && env.DEFAULT_ADMIN_KEY) || 'gamess2026!').trim();
  const sessionToken = btoa(adminSecret);
  const url = new URL(request.url);

  // Strategy 1: URL Query Parameter (?key=gamess2026! or ?token=... or ?adminKey=...)
  const queryKey = url.searchParams.get('key') || url.searchParams.get('adminKey');
  const queryToken = url.searchParams.get('token');
  if (queryKey && queryKey.trim() === adminSecret) return true;
  if (queryToken && queryToken.trim() === sessionToken) return true;

  // Strategy 2: Authorization Header
  const authHeader = request.headers.get('Authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7).trim();
    if (token === adminSecret || token === sessionToken) return true;
  }

  // Strategy 3: Custom Headers (X-Admin-Key or X-Admin-Token)
  const customKey = request.headers.get('X-Admin-Key') || request.headers.get('X-Admin-Token');
  if (customKey && (customKey.trim() === adminSecret || customKey.trim() === sessionToken)) return true;

  // Strategy 4: Cookie Session
  const cookieHeader = request.headers.get('Cookie') || '';
  const cookies = Object.fromEntries(
    cookieHeader.split(';').map(c => {
      const [k, ...v] = c.trim().split('=');
      return [k, v.join('=')];
    })
  );

  const session = cookies['gs_admin_session'];
  if (session) {
    const dec = decodeURIComponent(session).trim();
    if (dec === sessionToken || dec === adminSecret) return true;
  }

  // Strategy 5: Referer header (?key=...)
  const referer = request.headers.get('Referer');
  if (referer) {
    try {
      const refUrl = new URL(referer);
      const refKey = refUrl.searchParams.get('key') || refUrl.searchParams.get('adminKey');
      const refToken = refUrl.searchParams.get('token');
      if (refKey && refKey.trim() === adminSecret) return true;
      if (refToken && refToken.trim() === sessionToken) return true;
    } catch (e) {}
  }

  // Strategy 6: Form POST password or JSON body key
  if (request.method === 'POST') {
    try {
      const clonedReq = request.clone();
      const contentType = clonedReq.headers.get('content-type') || '';
      if (contentType.includes('application/x-www-form-urlencoded') || contentType.includes('multipart/form-data')) {
        const formData = await clonedReq.formData();
        const postPassword = String(formData.get('password') || formData.get('key') || formData.get('admin_key') || '').trim();
        if (postPassword === adminSecret || postPassword === sessionToken) return true;
      } else if (contentType.includes('application/json')) {
        const jsonBody = await clonedReq.json();
        const postPassword = String(jsonBody.password || jsonBody.key || jsonBody.adminKey || '').trim();
        if (postPassword === adminSecret || postPassword === sessionToken) return true;
      }
    } catch (e) {
      // Ignore clone/body errors
    }
  }

  return false;
}

// Helper: Run Health Check on Target Domains
async function checkServicesHealth() {
  const results = await Promise.all(
    TARGET_DOMAINS.map(async (item) => {
      const startTime = performance.now();
      let status = 'offline';
      let httpStatus = 0;
      let latencyMs = 0;

      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 4000);

        const response = await fetch(item.url, {
          method: 'GET',
          signal: controller.signal,
          headers: {
            'User-Agent': 'Gamess-HealthCheck-Worker/1.0'
          }
        });

        clearTimeout(timeoutId);
        latencyMs = Math.round(performance.now() - startTime);
        httpStatus = response.status;

        if (response.status >= 200 && response.status < 400) {
          status = 'online';
        } else if (response.status >= 500 && response.status < 600) {
          status = 'maintenance';
        } else {
          status = 'offline';
        }
      } catch (err) {
        latencyMs = Math.round(performance.now() - startTime);
        status = 'offline';
        httpStatus = 0;
      }

      return {
        domain: item.domain,
        name: item.name,
        url: item.url,
        status,
        httpStatus,
        latencyMs,
        checkedAt: new Date().toISOString()
      };
    })
  );

  return results;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    let path = url.pathname;
    if (path.length > 1 && path.endsWith('/')) {
      path = path.slice(0, -1);
    }

    // Route 1: Raw Logo Endpoint
    if (path === '/logo.png') {
      const binaryStr = atob(LOGO_BASE64);
      const bytes = new Uint8Array(binaryStr.length);
      for (let i = 0; i < binaryStr.length; i++) {
        bytes[i] = binaryStr.charCodeAt(i);
      }
      return new Response(bytes.buffer, {
        headers: {
          'Content-Type': 'image/png',
          'Cache-Control': 'public, max-age=31536000, immutable',
          ...getSecurityHeaders()
        }
      });
    }

    // Route 1.5: On-the-fly Media Edge Optimization & Caching (/img-edge)
    if (path === '/img-edge' || path === '/media-proxy') {
      const srcUrl = url.searchParams.get('url');
      if (!srcUrl) {
        return new Response(JSON.stringify({ error: 'Missing image url parameter (?url=...)' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...getSecurityHeaders() }
        });
      }

      // 허용된 원본 도메인 검증 (SSRF 방지)
      try {
        const parsedSrc = new URL(srcUrl, 'https://storage.gamess.co.kr');
        const allowedHosts = ['storage.gamess.co.kr', 'www.gamess.co.kr', 'gamess.co.kr', 'wiki.gamess.co.kr', 'emul.gamess.co.kr'];
        if (!allowedHosts.includes(parsedSrc.hostname)) {
          return new Response(JSON.stringify({ error: 'Forbidden origin host' }), {
            status: 403,
            headers: { 'Content-Type': 'application/json', ...getSecurityHeaders() }
          });
        }

        // Cloudflare Cache API 조회 (캐시 히트 시 초고속 반환)
        const cache = caches.default;
        const cacheKey = new Request(request.url, request);
        let cachedResponse = await cache.match(cacheKey);
        if (cachedResponse) {
          return cachedResponse;
        }

        // 원본 이미지 페치 (Cloudflare Image Resizing 지원 환경 자동 활용)
        const width = parseInt(url.searchParams.get('w') || '0', 10);
        const quality = parseInt(url.searchParams.get('q') || '85', 10);
        const fetchOpts = {
          headers: {
            'Accept': 'image/avif,image/webp,image/apng,image/*,*/*;q=0.8',
            'User-Agent': 'Gamess-Edge-Worker/2.0'
          }
        };

        if (width > 0 && request.cf) {
          fetchOpts.cf = {
            image: {
              width: width,
              quality: quality,
              format: 'auto'
            }
          };
        }

        const imgRes = await fetch(parsedSrc.toString(), fetchOpts);
        if (!imgRes.ok) {
          return new Response('Failed to fetch origin media', { status: imgRes.status });
        }

        // 엣지 캐싱 헤더 적용 (브라우저 7일, CDN 30일 캐시)
        const newHeaders = new Headers(imgRes.headers);
        newHeaders.set('Cache-Control', 'public, max-age=604800, s-maxage=2592000, immutable');
        newHeaders.set('Access-Control-Allow-Origin', '*');
        newHeaders.set('X-Edge-Optimized', 'true');

        const responseToCache = new Response(imgRes.body, {
          status: imgRes.status,
          headers: newHeaders
        });

        // 백그라운드 엣지 캐시 저장
        ctx.waitUntil(cache.put(cacheKey, responseToCache.clone()));
        return responseToCache;
      } catch (err) {
        return new Response(JSON.stringify({ error: 'Invalid URL or fetch failed', detail: err.message }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }

    // Route 2: Public Status API
    if (path === '/api/status') {
      const config = await getMaintenanceConfig(env);
      return new Response(JSON.stringify(config), {
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Access-Control-Allow-Origin': '*',
          ...getSecurityHeaders()
        }
      });
    }

    // Route 3: Public Domain Health Check API
    if (path === '/api/health') {
      const healthData = await checkServicesHealth();
      return new Response(JSON.stringify({
        timestamp: new Date().toISOString(),
        services: healthData
      }), {
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Access-Control-Allow-Origin': '*',
          ...getSecurityHeaders()
        }
      });
    }

    // Route 4: Admin Login Endpoint (AJAX)
    if (path === '/api/admin/login' && request.method === 'POST') {
      try {
        const body = await request.json();
        const inputPassword = String(body.password || '').trim();
        const adminSecret = String((env && env.ADMIN_KEY) || (env && env.DEFAULT_ADMIN_KEY) || 'gamess2026!').trim();
        
        if (inputPassword === adminSecret) {
          const sessionToken = btoa(adminSecret);
          const isSecure = url.protocol === 'https:';
          const cookieHeader = `gs_admin_session=${sessionToken}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400${isSecure ? '; Secure' : ''}`;
          
          return new Response(JSON.stringify({ success: true, message: '로그인 성공' }), {
            headers: {
              'Content-Type': 'application/json',
              'Set-Cookie': cookieHeader,
              ...getSecurityHeaders()
            }
          });
        } else {
          return new Response(JSON.stringify({ success: false, message: '비밀번호가 일치하지 않습니다.' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json', ...getSecurityHeaders() }
          });
        }
      } catch (e) {
        return new Response(JSON.stringify({ success: false, message: '잘못된 요청 형식입니다.' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...getSecurityHeaders() }
        });
      }
    }

    // Route 5: Admin Update Endpoint
    if (path === '/api/admin/update' && request.method === 'POST') {
      if (!(await checkAdminAuth(request, env))) {
        return new Response(JSON.stringify({ success: false, message: '권한이 없습니다. 관리자 로그인이 필요합니다.' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json', ...getSecurityHeaders() }
        });
      }

      try {
        const body = await request.json();
        
        // Validate inputs
        const updatedConfig = {
          enabled: Boolean(body.enabled),
          status: ['ongoing', 'scheduled', 'completed'].includes(body.status) ? body.status : 'ongoing',
          title: String(body.title || '게임세상 서비스 점검 안내'),
          startTime: String(body.startTime || ''),
          endTime: String(body.endTime || ''),
          noticeText: String(body.noticeText || ''),
          impactedServices: Array.isArray(body.impactedServices) 
            ? body.impactedServices.map(s => String(s).trim()).filter(Boolean)
            : String(body.impactedServices || '').split('\n').map(s => s.trim()).filter(Boolean),
          contactInfo: String(body.contactInfo || 'support@gamess.co.kr')
        };

        const result = await setMaintenanceConfig(env, updatedConfig);
        
        return new Response(JSON.stringify({ success: true, config: result, message: '점검 설정이 성공적으로 저장되었습니다.' }), {
          headers: { 'Content-Type': 'application/json', ...getSecurityHeaders() }
        });
      } catch (e) {
        return new Response(JSON.stringify({ success: false, message: '설정 저장 중 오류 발생: ' + e.message }), {
          status: 500,
          headers: { 'Content-Type': 'application/json', ...getSecurityHeaders() }
        });
      }
    }

    // Route 6: Admin Logout Endpoint
    if (path === '/api/admin/logout' && request.method === 'POST') {
      return new Response(JSON.stringify({ success: true }), {
        headers: {
          'Content-Type': 'application/json',
          'Set-Cookie': 'gs_admin_session=; Path=/; HttpOnly; Max-Age=0',
          ...getSecurityHeaders()
        }
      });
    }

    // Route 7: Admin Dashboard Page (GET & POST supported for native HTML form submission)
    if (path === '/admin') {
      const adminSecret = String((env && env.ADMIN_KEY) || (env && env.DEFAULT_ADMIN_KEY) || 'gamess2026!').trim();
      const sessionToken = btoa(adminSecret);
      
      let isAuthenticated = await checkAdminAuth(request, env);
      let responseHeaders = getSecurityHeaders({ 'Content-Type': 'text/html; charset=utf-8' });
      let toastInfo = null;

      // If native POST form submission to /admin
      if (request.method === 'POST') {
        try {
          const formData = await request.formData();
          const action = String(formData.get('action') || '').trim();
          const pass = String(formData.get('password') || formData.get('key') || formData.get('admin_key') || '').trim();
          
          if (pass === adminSecret || isAuthenticated) {
            isAuthenticated = true;
            const isSecure = url.protocol === 'https:';
            responseHeaders['Set-Cookie'] = `gs_admin_session=${sessionToken}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400${isSecure ? '; Secure' : ''}`;
            
            if (action === 'update' || formData.has('title')) {
              const updatedConfig = {
                enabled: true,
                status: ['ongoing', 'scheduled', 'completed'].includes(formData.get('status')) ? formData.get('status') : 'ongoing',
                title: String(formData.get('title') || '게임세상 서비스 정기 점검 안내'),
                startTime: String(formData.get('startTime') || ''),
                endTime: String(formData.get('endTime') || ''),
                noticeText: String(formData.get('noticeText') || ''),
                impactedServices: String(formData.get('impactedServices') || '').split('\n').map(s => s.trim()).filter(Boolean),
                contactInfo: String(formData.get('contactInfo') || 'support@gamess.co.kr')
              };
              await setMaintenanceConfig(env, updatedConfig);
              toastInfo = { message: '점검 설정이 성공적으로 저장되었습니다.', isSuccess: true };
            }
          }
        } catch (e) {
          toastInfo = { message: '저장 중 오류 발생: ' + e.message, isSuccess: false };
        }
      }

      if (isAuthenticated) {
        const isSecure = url.protocol === 'https:';
        responseHeaders['Set-Cookie'] = `gs_admin_session=${sessionToken}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400${isSecure ? '; Secure' : ''}`;
      }

      const config = await getMaintenanceConfig(env);
      return new Response(renderAdminHtml(config, isAuthenticated, adminSecret, toastInfo), {
        headers: responseHeaders
      });
    }

    // Route 8: Public Notice Page (`/`)
    const config = await getMaintenanceConfig(env);
    return new Response(renderPublicNoticeHtml(config), {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        ...getSecurityHeaders()
      }
    });
  }
};

/**
 * Public Service Maintenance Notice HTML Renderer
 */
function renderPublicNoticeHtml(config) {
  const logoDataUri = `data:image/png;base64,${LOGO_BASE64}`;
  
  const statusBadgeMap = {
    ongoing: { text: "서비스 점검 진행 중", class: "status-ongoing" },
    scheduled: { text: "점검 예정", class: "status-scheduled" },
    completed: { text: "점검 완료 / 정상 가동", class: "status-completed" }
  };
  
  const badgeInfo = statusBadgeMap[config.status] || statusBadgeMap.ongoing;
  
  const formattedNotice = escapeHtml(config.noticeText).replace(/\n/g, '<br>');
  const impactedListHtml = (config.impactedServices || [])
    .map(service => `<div class="tag-item"><span>⚙️</span> ${escapeHtml(service)}</div>`)
    .join('');

  return `<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(config.title)} | 게임세상</title>
  <meta name="description" content="게임세상 서비스 점검 및 시스템 점검 안내 페이지입니다.">
  <link rel="icon" href="/logo.png">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;700;800&family=Noto+Sans+KR:wght@400;500;700;900&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-dark: #090d16;
      --card-bg: rgba(18, 24, 38, 0.75);
      --card-border: rgba(255, 255, 255, 0.1);
      --accent-purple: #6366f1;
      --accent-cyan: #06b6d4;
      --accent-gold: #f59e0b;
      --text-main: #f3f4f6;
      --text-muted: #9ca3af;
      --status-ongoing: #ef4444;
      --status-scheduled: #f59e0b;
      --status-completed: #10b981;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      font-family: 'Noto Sans KR', 'Outfit', sans-serif;
      background-color: var(--bg-dark);
      color: var(--text-main);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: space-between;
      overflow-x: hidden;
      background-image: 
        radial-gradient(circle at 15% 20%, rgba(99, 102, 241, 0.15) 0%, transparent 40%),
        radial-gradient(circle at 85% 80%, rgba(6, 182, 212, 0.12) 0%, transparent 40%);
    }

    .container {
      width: 100%;
      max-width: 900px;
      padding: 2.5rem 1.5rem;
      margin: 0 auto;
    }

    .logo-container {
      text-align: center;
      margin-bottom: 2rem;
    }

    .logo-img {
      max-width: 220px;
      height: auto;
      filter: drop-shadow(0 0 20px rgba(99, 102, 241, 0.3));
      transition: transform 0.3s ease;
    }
    
    .logo-img:hover {
      transform: scale(1.02);
    }

    .main-card {
      background: var(--card-bg);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border: 1px solid var(--card-border);
      border-radius: 24px;
      padding: 2.5rem;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.5);
      position: relative;
      overflow: hidden;
    }

    .main-card::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 4px;
      background: linear-gradient(90deg, var(--accent-purple), var(--accent-cyan));
    }

    .badge-wrapper {
      display: flex;
      justify-content: center;
      margin-bottom: 1.5rem;
    }

    .badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 8px 18px;
      border-radius: 30px;
      font-size: 0.95rem;
      font-weight: 700;
      letter-spacing: -0.02em;
    }

    .badge.status-ongoing {
      background: rgba(239, 68, 68, 0.15);
      color: #f87171;
      border: 1px solid rgba(239, 68, 68, 0.3);
    }

    .badge.status-scheduled {
      background: rgba(245, 158, 11, 0.15);
      color: #fbbf24;
      border: 1px solid rgba(245, 158, 11, 0.3);
    }

    .badge.status-completed {
      background: rgba(16, 185, 129, 0.15);
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.3);
    }

    .pulse-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background-color: currentColor;
      box-shadow: 0 0 10px currentColor;
      animation: pulse 1.8s infinite;
    }

    @keyframes pulse {
      0% { opacity: 0.4; transform: scale(0.9); }
      50% { opacity: 1; transform: scale(1.2); }
      100% { opacity: 0.4; transform: scale(0.9); }
    }

    .page-title {
      font-size: 2rem;
      font-weight: 800;
      text-align: center;
      margin-bottom: 1.5rem;
      background: linear-gradient(135deg, #ffffff 0%, #cbd5e1 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      line-height: 1.3;
    }

    /* Timer Section */
    .timer-section {
      background: rgba(10, 15, 26, 0.6);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 16px;
      padding: 1.5rem;
      margin-bottom: 2rem;
      text-align: center;
    }

    .time-range {
      font-size: 1rem;
      color: var(--accent-cyan);
      font-weight: 600;
      margin-bottom: 1rem;
    }

    .countdown-grid {
      display: flex;
      justify-content: center;
      gap: 1.5rem;
    }

    .count-box {
      display: flex;
      flex-direction: column;
      align-items: center;
    }

    .count-val {
      font-family: 'Outfit', sans-serif;
      font-size: 2.2rem;
      font-weight: 800;
      color: #ffffff;
      background: rgba(255, 255, 255, 0.05);
      padding: 8px 16px;
      border-radius: 12px;
      border: 1px solid rgba(255, 255, 255, 0.1);
      min-width: 68px;
    }

    .count-label {
      font-size: 0.75rem;
      color: var(--text-muted);
      margin-top: 6px;
      font-weight: 500;
    }

    .notice-box {
      font-size: 1.05rem;
      line-height: 1.7;
      color: #e2e8f0;
      margin-bottom: 2rem;
      background: rgba(255, 255, 255, 0.02);
      padding: 1.5rem;
      border-radius: 14px;
      border-left: 4px solid var(--accent-purple);
    }

    /* Impacted Services */
    .section-title {
      font-size: 1.1rem;
      font-weight: 700;
      color: #f1f5f9;
      margin-bottom: 1rem;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .tag-grid {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-bottom: 2.5rem;
    }

    .tag-item {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.08);
      padding: 8px 14px;
      border-radius: 10px;
      font-size: 0.9rem;
      color: #cbd5e1;
      display: flex;
      align-items: center;
      gap: 6px;
    }

    /* Health Check Widget */
    .health-widget {
      background: rgba(10, 15, 26, 0.8);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 18px;
      padding: 1.5rem;
      margin-top: 1.5rem;
    }

    .health-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1.2rem;
    }

    .refresh-btn {
      background: rgba(99, 102, 241, 0.2);
      color: #a5b4fc;
      border: 1px solid rgba(99, 102, 241, 0.4);
      padding: 6px 14px;
      border-radius: 8px;
      font-size: 0.85rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .refresh-btn:hover {
      background: rgba(99, 102, 241, 0.4);
      color: #ffffff;
    }

    .domain-list {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 12px;
    }

    .domain-card {
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid rgba(255, 255, 255, 0.06);
      border-radius: 12px;
      padding: 1rem;
      display: flex;
      flex-direction: column;
      gap: 6px;
      transition: border-color 0.2s ease;
    }

    .domain-card:hover {
      border-color: rgba(255, 255, 255, 0.2);
    }

    .domain-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .domain-name {
      font-weight: 700;
      font-size: 0.95rem;
      color: #f8fafc;
    }

    .domain-url {
      font-size: 0.8rem;
      color: var(--text-muted);
      font-family: monospace;
    }

    .domain-status {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 0.8rem;
      font-weight: 700;
      padding: 4px 10px;
      border-radius: 6px;
      margin-top: 4px;
      width: fit-content;
    }

    .status-online {
      background: rgba(16, 185, 129, 0.2);
      color: #34d399;
    }

    .status-offline {
      background: rgba(239, 68, 68, 0.2);
      color: #f87171;
    }

    .status-checking {
      background: rgba(245, 158, 11, 0.2);
      color: #fbbf24;
    }

    .latency-text {
      font-size: 0.75rem;
      color: #94a3b8;
      margin-left: auto;
    }

    footer {
      text-align: center;
      padding: 2rem 1rem;
      font-size: 0.85rem;
      color: var(--text-muted);
      width: 100%;
    }

    footer a {
      color: var(--text-muted);
      text-decoration: none;
      transition: color 0.2s;
    }

    footer a:hover {
      color: var(--accent-cyan);
    }

    @media (max-width: 640px) {
      .main-card {
        padding: 1.5rem;
      }
      .page-title {
        font-size: 1.5rem;
      }
      .countdown-grid {
        gap: 0.75rem;
      }
      .count-val {
        font-size: 1.6rem;
        min-width: 52px;
        padding: 6px 10px;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <!-- Standalone Resilient Logo Component -->
    <div class="logo-container">
      <a href="/">
        <img 
          src="/logo.png" 
          onerror="this.onerror=null; this.src='${logoDataUri}';" 
          alt="게임세상" 
          class="logo-img"
        />
      </a>
    </div>

    <!-- Main Card -->
    <div class="main-card">
      <div class="badge-wrapper">
        <div class="badge ${badgeInfo.class}">
          <div class="pulse-dot"></div>
          <span>${escapeHtml(badgeInfo.text)}</span>
        </div>
      </div>

      <h1 class="page-title">${escapeHtml(config.title)}</h1>

      <!-- Countdown & Time Window -->
      <div class="timer-section">
        <div class="time-range">
          ⏱️ 점검 일시: <span id="startTimeText">${escapeHtml(config.startTime)}</span> ~ <span id="endTimeText">${escapeHtml(config.endTime)}</span>
        </div>
        <div class="countdown-grid">
          <div class="count-box">
            <span class="count-val" id="cd-hours">00</span>
            <span class="count-label">시간</span>
          </div>
          <div class="count-box">
            <span class="count-val" id="cd-mins">00</span>
            <span class="count-label">분</span>
          </div>
          <div class="count-box">
            <span class="count-val" id="cd-secs">00</span>
            <span class="count-label">초</span>
          </div>
        </div>
      </div>

      <!-- Notice Content -->
      <div class="notice-box">
        ${formattedNotice}
      </div>

      <!-- Impacted Services -->
      <div class="section-title">
        <span>📢</span> 점검 대상 및 영향 서비스
      </div>
      <div class="tag-grid">
        ${impactedListHtml}
      </div>

      <!-- Domain Health Check Widget -->
      <div class="health-widget">
        <div class="health-header">
          <div class="section-title" style="margin-bottom:0;">
            <span>🌐</span> 주요 서비스 서버 모니터링 (Health Check)
          </div>
          <button class="refresh-btn" onclick="fetchHealthChecks()">
            🔄 상태 다시 조회
          </button>
        </div>
        <div class="domain-list" id="domainList">
          <!-- Populated dynamically via JS -->
          <div class="domain-card">
            <div class="domain-header">
              <span class="domain-name">www.gamess.co.kr</span>
            </div>
            <span class="domain-url">메인 포털</span>
            <div class="domain-status status-checking">확인 중...</div>
          </div>
          <div class="domain-card">
            <div class="domain-header">
              <span class="domain-name">play.gamess.co.kr</span>
            </div>
            <span class="domain-url">게임 서비스</span>
            <div class="domain-status status-checking">확인 중...</div>
          </div>
          <div class="domain-card">
            <div class="domain-header">
              <span class="domain-name">emul.gamess.co.kr</span>
            </div>
            <span class="domain-url">에뮬레이터</span>
            <div class="domain-status status-checking">확인 중...</div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <footer>
    <p>© GAMESS All rights reserved. | 문의: ${escapeHtml(config.contactInfo)}</p>
    <p style="margin-top:8px;"><a href="/admin">🔐 관리자 설정</a></p>
  </footer>

  <script>
    // Live Countdown Timer logic
    const endTimeStr = "${escapeHtml(config.endTime)}";
    function updateCountdown() {
      if (!endTimeStr) return;
      const targetDate = new Date(endTimeStr).getTime();
      if (isNaN(targetDate)) return;

      const now = new Date().getTime();
      const distance = targetDate - now;

      if (distance < 0) {
        document.getElementById('cd-hours').textContent = "00";
        document.getElementById('cd-mins').textContent = "00";
        document.getElementById('cd-secs').textContent = "00";
        return;
      }

      const hours = Math.floor(distance / (1000 * 60 * 60));
      const minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
      const seconds = Math.floor((distance % (1000 * 60)) / 1000);

      document.getElementById('cd-hours').textContent = String(hours).padStart(2, '0');
      document.getElementById('cd-mins').textContent = String(minutes).padStart(2, '0');
      document.getElementById('cd-secs').textContent = String(seconds).padStart(2, '0');
    }

    updateCountdown();
    setInterval(updateCountdown, 1000);

    // Dynamic Server Health Check logic
    async function fetchHealthChecks() {
      const container = document.getElementById('domainList');
      container.querySelectorAll('.domain-status').forEach(el => {
        el.className = 'domain-status status-checking';
        el.textContent = '확인 중...';
      });

      try {
        const res = await fetch('/api/health');
        const data = await res.json();
        
        if (data && data.services) {
          container.replaceChildren();
          
          data.services.forEach(item => {
            const card = document.createElement('div');
            card.className = 'domain-card';

            const header = document.createElement('div');
            header.className = 'domain-header';

            const nameSpan = document.createElement('span');
            nameSpan.className = 'domain-name';
            nameSpan.textContent = item.name;

            const latencySpan = document.createElement('span');
            latencySpan.className = 'latency-text';
            latencySpan.textContent = item.status === 'online' ? item.latencyMs + 'ms' : '';

            header.appendChild(nameSpan);
            header.appendChild(latencySpan);

            const urlSpan = document.createElement('span');
            urlSpan.className = 'domain-url';
            urlSpan.textContent = item.domain;

            const statusBadge = document.createElement('div');
            if (item.status === 'online') {
              statusBadge.className = 'domain-status status-online';
              statusBadge.textContent = '🟢 정상 (Online)';
            } else if (item.status === 'maintenance') {
              statusBadge.className = 'domain-status status-checking';
              statusBadge.textContent = '🟡 점검 중 (' + item.httpStatus + ')';
            } else {
              statusBadge.className = 'domain-status status-offline';
              statusBadge.textContent = '🔴 연결 불가 (Offline)';
            }

            card.appendChild(header);
            card.appendChild(urlSpan);
            card.appendChild(statusBadge);

            container.appendChild(card);
          });
        }
      } catch (err) {
        console.error('Health Check Fetch Error:', err);
      }
    }

    fetchHealthChecks();
  </script>
</body>
</html>`;
}

/**
 * Admin Management Dashboard HTML Renderer
 */
function renderAdminHtml(config, isAuthenticated, adminSecret = 'gamess2026!', toastInfo = null) {
  const logoDataUri = `data:image/png;base64,${LOGO_BASE64}`;

  return `<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>점검 안내 관리자 설정 | 게임세상</title>
  <link rel="icon" href="/logo.png">
  <link href="https://fonts.googleapis.com/css2?family=Noto+Sans+KR:wght@400;500;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-dark: #0f172a;
      --card-bg: #1e293b;
      --border-color: #334155;
      --accent: #6366f1;
      --accent-hover: #4f46e5;
      --text: #f8fafc;
      --muted: #94a3b8;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: 'Noto Sans KR', sans-serif;
      background-color: var(--bg-dark);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 2rem 1rem;
    }

    .admin-container {
      width: 100%;
      max-width: 680px;
    }

    .admin-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 2rem;
    }

    .logo-img {
      height: 48px;
    }

    .card {
      background: var(--card-bg);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      padding: 2rem;
      box-shadow: 0 10px 25px rgba(0,0,0,0.3);
    }

    h2 {
      font-size: 1.4rem;
      margin-bottom: 1.5rem;
      color: var(--text);
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .form-group {
      margin-bottom: 1.4rem;
    }

    label {
      display: block;
      font-size: 0.9rem;
      font-weight: 600;
      color: #cbd5e1;
      margin-bottom: 6px;
    }

    input[type="text"],
    input[type="password"],
    input[type="datetime-local"],
    select,
    textarea {
      width: 100%;
      padding: 10px 14px;
      background: #0f172a;
      border: 1px solid var(--border-color);
      border-radius: 8px;
      color: #ffffff;
      font-size: 0.95rem;
      outline: none;
      transition: border-color 0.2s;
    }

    input:focus, select:focus, textarea:focus {
      border-color: var(--accent);
    }

    textarea {
      resize: vertical;
      min-height: 100px;
      line-height: 1.5;
    }

    .btn {
      width: 100%;
      padding: 12px;
      background: var(--accent);
      color: #ffffff;
      border: none;
      border-radius: 8px;
      font-size: 1rem;
      font-weight: 700;
      cursor: pointer;
      transition: background 0.2s;
      margin-top: 1rem;
    }

    .btn:hover {
      background: var(--accent-hover);
    }

    .btn-secondary {
      background: #475569;
      margin-top: 0.5rem;
    }

    .btn-secondary:hover {
      background: #334155;
    }

    .flex-row {
      display: flex;
      gap: 12px;
    }

    .toast {
      padding: 12px 16px;
      border-radius: 8px;
      margin-bottom: 1.5rem;
      font-weight: 500;
      display: none;
    }
    .toast.success { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #059669; }
    .toast.error { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #dc2626; }

    .quick-link-box {
      background: rgba(99, 102, 241, 0.1);
      border: 1px dashed rgba(99, 102, 241, 0.4);
      padding: 12px;
      border-radius: 8px;
      font-size: 0.85rem;
      color: #a5b4fc;
      margin-bottom: 1.5rem;
    }

    .back-link {
      display: inline-block;
      margin-top: 1.5rem;
      color: var(--muted);
      text-decoration: none;
      font-size: 0.9rem;
    }
    .back-link:hover { color: var(--text); }
  </style>
</head>
<body>
  <div class="admin-container">
    <div class="admin-header">
      <img src="/logo.png" onerror="this.onerror=null; this.src='${logoDataUri}';" alt="게임세상" class="logo-img">
      <a href="/" class="back-link">← 점검 페이지로 돌아가기</a>
    </div>

    <div class="card">
      <div id="toast" class="toast"></div>

      ${!isAuthenticated ? `
        <h2>🔐 관리자 인증</h2>
        <div class="quick-link-box">
          💡 <strong>바로 접속 팁</strong>: 로그인 버튼을 누르면 즉시 관리자 페이지로 이동합니다.<br>
          또는 주소창에 <code>https://maintenance.gamess.co.kr/admin?key=gamess2026!</code> 로 바로 접속하실 수도 있습니다.
        </div>
        <!-- Standard HTML POST Form + JS Enhancement -->
        <form method="POST" action="/admin" id="loginForm">
          <div class="form-group">
            <label for="adminPass">관리자 비밀번호</label>
            <input type="password" id="adminPass" name="password" placeholder="비밀번호 입력 (예: gamess2026!)" value="gamess2026!" required autofocus>
          </div>
          <button type="submit" class="btn">🔑 로그인하기</button>
        </form>
      ` : `
        <h2>⚙️ 점검 내용 및 시간 관리 설정</h2>
        <form method="POST" action="/admin" id="updateForm">
          <input type="hidden" name="action" value="update">
          <input type="hidden" name="admin_key" value="${escapeHtml(adminSecret)}">

          <div class="form-group">
            <label for="status">점검 진행 상태</label>
            <select id="status" name="status">
              <option value="ongoing" ${config.status === 'ongoing' ? 'selected' : ''}>🔴 서비스 점검 진행 중 (ongoing)</option>
              <option value="scheduled" ${config.status === 'scheduled' ? 'selected' : ''}>🟡 점검 예정 (scheduled)</option>
              <option value="completed" ${config.status === 'completed' ? 'selected' : ''}>🟢 점검 완료 / 서비스 정상 (completed)</option>
            </select>
          </div>

          <div class="form-group">
            <label for="title">점검 안내 제목</label>
            <input type="text" id="title" name="title" value="${escapeHtml(config.title)}" required>
          </div>

          <div class="flex-row">
            <div class="form-group" style="flex:1;">
              <label for="startTime">점검 시작 시간</label>
              <input type="text" id="startTime" name="startTime" value="${escapeHtml(config.startTime)}" placeholder="예: 2026-08-25T02:00:00+09:00" required>
            </div>
            <div class="form-group" style="flex:1;">
              <label for="endTime">점검 종료 시간</label>
              <input type="text" id="endTime" name="endTime" value="${escapeHtml(config.endTime)}" placeholder="예: 2026-08-26T08:00:00+09:00" required>
            </div>
          </div>

          <div class="form-group">
            <label for="noticeText">점검 안내 상세 설명</label>
            <textarea id="noticeText" name="noticeText" required>${escapeHtml(config.noticeText)}</textarea>
          </div>

          <div class="form-group">
            <label for="impactedServices">영향 받는 서비스 목록 (줄바꿈 구분)</label>
            <textarea id="impactedServices" name="impactedServices" required>${escapeHtml((config.impactedServices || []).join('\n'))}</textarea>
          </div>

          <div class="form-group">
            <label for="contactInfo">고객 지원 연락처 / 이메일</label>
            <input type="text" id="contactInfo" name="contactInfo" value="${escapeHtml(config.contactInfo)}" required>
          </div>

          <button type="submit" class="btn">💾 점검 설정 저장</button>
          <button type="button" class="btn btn-secondary" onclick="handleLogout()">로그아웃</button>
        </form>
      `}
    </div>
  </div>

  <script>
    function showToast(msg, isSuccess) {
      const toast = document.getElementById('toast');
      toast.textContent = msg;
      toast.className = 'toast ' + (isSuccess ? 'success' : 'error');
      toast.style.display = 'block';
      setTimeout(() => { toast.style.display = 'none'; }, 4000);
    }

    ${toastInfo ? `showToast(${JSON.stringify(toastInfo.message)}, ${Boolean(toastInfo.isSuccess)});` : ''}

    const adminSecret = ${JSON.stringify(adminSecret)};

    const updateForm = document.getElementById('updateForm');
    if (updateForm) {
      updateForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const searchParams = new URLSearchParams(window.location.search);
        const urlKey = searchParams.get('key') || '';
        const keyToSend = urlKey || adminSecret;

        const payload = {
          enabled: true,
          status: document.getElementById('status').value,
          title: document.getElementById('title').value,
          startTime: document.getElementById('startTime').value,
          endTime: document.getElementById('endTime').value,
          noticeText: document.getElementById('noticeText').value,
          impactedServices: document.getElementById('impactedServices').value.split('\n').map(s => s.trim()).filter(Boolean),
          contactInfo: document.getElementById('contactInfo').value,
          key: keyToSend
        };

        const submitBtn = updateForm.querySelector('button[type="submit"]');
        if (submitBtn) {
          submitBtn.disabled = true;
          submitBtn.textContent = '⏳ 저장 중...';
        }

        try {
          const updateUrl = keyToSend ? '/api/admin/update?key=' + encodeURIComponent(keyToSend) : '/api/admin/update';
          const res = await fetch(updateUrl, {
            method: 'POST',
            credentials: 'include',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': 'Bearer ' + keyToSend,
              'X-Admin-Key': keyToSend
            },
            body: JSON.stringify(payload)
          });
          const data = await res.json();
          if (data.success) {
            showToast(data.message || '설정이 저장되었습니다!', true);
          } else {
            showToast(data.message || '저장 실패', false);
          }
        } catch (err) {
          showToast('설정 저장 중 오류가 발생했습니다: ' + err.message, false);
        } finally {
          if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.textContent = '💾 점검 설정 저장';
          }
        }
      });
    }

    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
      loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const password = document.getElementById('adminPass').value;
        try {
          const res = await fetch('/api/admin/login', {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password })
          });
          const data = await res.json();
          if (data.success) {
            location.href = '/admin?key=' + encodeURIComponent(password);
          } else {
            showToast(data.message || '비밀번호가 일치하지 않습니다.', false);
          }
        } catch (err) {
          loginForm.submit();
        }
      });
    }

    async function handleLogout() {
      try {
        await fetch('/api/admin/logout', { method: 'POST', credentials: 'include' });
      } catch (e) {}
      location.href = '/admin';
    }
  </script>
</body>
</html>`;
}
