#!/usr/bin/env python3
"""
Cloudflare Turnstile token 获取模块

某些 NewAPI 站点（如 seekai.cc）在 POST /api/user/checkin 上启用了
middleware.TurnstileCheck()，必须携带 ?turnstile=<token> 才能签到。

获取顺序
--------
1. 若配置了 TWOCAPTCHA_API_KEY，直接走 2Captcha 的 Turnstile 接口。
   这条路不依赖本机浏览器环境，在 CI（数据中心 IP）上最可靠。
2. 浏览器方案：同源 stub 页面（page.route 伪造 {origin}/__hermes_turnstile__），
   页面内用原生 <script> + onload 回调 explicit render，token 从 DOM 隐藏域读取。
3. 浏览器方案：真实登录页，勾选协议触发站点自身 widget。

实现要点
--------
* 不用 main_world_eval / forceScopeAccess —— 这两个会改动 JS 环境，容易被
  Turnstile 识别；stub 页面的 render 调用写在页面原生 <script> 里，本身就跑在
  主世界，不需要跨 world evaluate。
* token 统一从 DOM 隐藏域 input[name="cf-turnstile-response"] 读取（DOM 在
  隔离世界与主世界之间共享），并用 document.title 传递 ready/err 信号。
* 不用 page.wait_for_function（无法指定 world），改为自己轮询。

常见失败
--------
Turnstile 报 600010 且 iframe 数为 0 时，通常是 IP 信誉问题（数据中心 / CI IP）
或浏览器指纹被判定不可信。此时应配置 PROXY（住宅代理）或 TWOCAPTCHA_API_KEY。
"""

from __future__ import annotations

import json
import os
import tempfile
import time
import urllib.parse
import urllib.request
from urllib.parse import urlparse

from camoufox.async_api import AsyncCamoufox
from playwright_captcha import CaptchaType, ClickSolver, FrameworkType

try:  # uBlock Origin 会拦掉 challenges.cloudflare.com 的脚本
    from camoufox import DefaultAddons

    _EXCLUDE_ADDONS = [DefaultAddons.UBO]
except Exception:  # pragma: no cover
    _EXCLUDE_ADDONS = None

TURNSTILE_API = "https://challenges.cloudflare.com/turnstile/v0/api.js"
_STUB_PATH = "/__hermes_turnstile__"

_STUB_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>ts</title></head>
<body style="background:#fff;font-family:sans-serif">
<form id="f"><div id="box"></div></form>
<script>
  window.onloadTurnstileCallback = function () {
    document.title = 'ts-ready';
    try {
      window.turnstile.render('#box', {
        sitekey: '__SITEKEY__',
        callback: function () { document.title = 'ts-ok'; },
        'error-callback': function (e) { document.title = 'ts-err:' + e; }
      });
    } catch (e) {
      document.title = 'ts-throw:' + e;
    }
  };
</script>
<script src="__API__?onload=onloadTurnstileCallback&render=explicit" async defer></script>
</body></html>
"""

# 只读 DOM —— 隔离世界也能访问
_DOM_TOKEN_JS = """() => {
    for (const el of document.querySelectorAll('input[name="cf-turnstile-response"]')) {
        if (el.value) return el.value;
    }
    return null;
}"""

_DOM_STATE_JS = """() => ({
    iframes: document.querySelectorAll('iframe[src*="turnstile"]').length,
    inputs: document.querySelectorAll('input[name="cf-turnstile-response"]').length,
    title: document.title,
})"""


# --------------------------------------------------------------------------- #
# 2Captcha
# --------------------------------------------------------------------------- #
def _http_json(url: str, payload: dict | None = None, timeout: int = 30) -> dict:
    if payload is None:
        req = urllib.request.Request(url, headers={"User-Agent": "hermes"})
    else:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "User-Agent": "hermes"},
            method="POST",
        )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "ignore") or "{}")


def solve_turnstile_via_2captcha(
    page_url: str, site_key: str, api_key: str, account_name: str, timeout_s: int = 180
) -> str | None:
    """用 2Captcha 求解 Turnstile，返回 token"""
    print(f"ℹ️ {account_name}: Solving Turnstile via 2Captcha")
    try:
        created = _http_json(
            "https://api.2captcha.com/createTask",
            {
                "clientKey": api_key,
                "task": {
                    "type": "TurnstileTaskProxyless",
                    "websiteURL": page_url,
                    "websiteKey": site_key,
                },
            },
        )
    except Exception as e:
        print(f"❌ {account_name}: 2Captcha createTask failed: {e}")
        return None
    if created.get("errorId"):
        print(f"❌ {account_name}: 2Captcha error: {created.get('errorDescription')}")
        return None
    task_id = created.get("taskId")
    print(f"ℹ️ {account_name}: 2Captcha taskId={task_id}, waiting…")

    deadline = time.time() + timeout_s
    while time.time() < deadline:
        time.sleep(6)
        try:
            res = _http_json(
                "https://api.2captcha.com/getTaskResult",
                {"clientKey": api_key, "taskId": task_id},
            )
        except Exception as e:
            print(f"⚠️ {account_name}: 2Captcha poll error: {e}")
            continue
        if res.get("errorId"):
            print(f"❌ {account_name}: 2Captcha task error: {res.get('errorDescription')}")
            return None
        if res.get("status") == "ready":
            tok = (res.get("solution") or {}).get("token")
            if tok:
                print(f"✅ {account_name}: 2Captcha returned token (len={len(tok)})")
                return tok
            print(f"❌ {account_name}: 2Captcha ready but no token: {res}")
            return None
    print(f"❌ {account_name}: 2Captcha timed out after {timeout_s}s")
    return None


# --------------------------------------------------------------------------- #
# 浏览器方案
# --------------------------------------------------------------------------- #
def _cam_kwargs(proxy_config: dict | None) -> dict:
    kw = dict(
        headless=False,
        humanize=True,
        locale="en-US",
        geoip=True if proxy_config else False,
        proxy=proxy_config,
        os="windows",
    )
    if _EXCLUDE_ADDONS:
        kw["exclude_addons"] = _EXCLUDE_ADDONS
    return kw


async def _dom_state(page) -> dict:
    try:
        return await page.evaluate(_DOM_STATE_JS)
    except Exception:
        return {}


async def _read_token(page) -> str | None:
    try:
        return await page.evaluate(_DOM_TOKEN_JS)
    except Exception:
        return None


async def _poll_token(page, timeout_ms: int) -> str | None:
    waited, step = 0, 2000
    while waited < timeout_ms:
        tok = await _read_token(page)
        if tok:
            return tok
        await page.wait_for_timeout(step)
        waited += step
    return None


async def _harvest(page, solver, account_name: str, timeout_ms: int) -> str | None:
    tok = await _read_token(page)
    if tok:
        return tok

    print(f"ℹ️ {account_name}: dom before solve -> {await _dom_state(page)}")
    try:
        await solver.solve_captcha(
            captcha_container=page, captcha_type=CaptchaType.CLOUDFLARE_TURNSTILE
        )
        print(f"✅ {account_name}: widget solved by ClickSolver")
    except Exception as e:
        print(f"⚠️ {account_name}: ClickSolver did not complete ({e}), polling anyway")

    tok = await _poll_token(page, timeout_ms)
    if not tok:
        print(f"⚠️ {account_name}: no token; dom={await _dom_state(page)}")
    return tok


async def _wait_stub_ready(page, account_name: str, timeout_ms: int = 45000) -> bool:
    waited = 0
    while waited < timeout_ms:
        st = await _dom_state(page)
        title = str(st.get("title", ""))
        if title in ("ts-ready", "ts-ok") or st.get("iframes") or st.get("inputs"):
            return True
        if title.startswith("ts-err") or title.startswith("ts-throw"):
            print(f"⚠️ {account_name}: stub widget error -> {title}")
            return False
        await page.wait_for_timeout(2000)
        waited += 2000
    return False


async def _try_stub_page(browser, site_key: str, origin: str, account_name: str, timeout_ms: int):
    page = await browser.new_page()
    html = _STUB_HTML.replace("__SITEKEY__", site_key).replace("__API__", TURNSTILE_API)
    stub_url = f"{origin}{_STUB_PATH}"

    async def handler(route):
        await route.fulfill(status=200, content_type="text/html; charset=utf-8", body=html)

    try:
        await page.route(stub_url, handler)
        async with ClickSolver(
            framework=FrameworkType.CAMOUFOX, page=page, max_attempts=3, attempt_delay=3
        ) as solver:
            await page.goto(stub_url, wait_until="domcontentloaded")
            if not await _wait_stub_ready(page, account_name):
                print(f"⚠️ {account_name}: stub widget not ready, dom={await _dom_state(page)}")
                return None
            await page.wait_for_timeout(3000)
            return await _harvest(page, solver, account_name, timeout_ms)
    except Exception as e:
        print(f"⚠️ {account_name}: stub page strategy failed: {e}")
        return None
    finally:
        try:
            await page.close()
        except Exception:
            pass


async def _try_login_page(browser, login_url: str, account_name: str, timeout_ms: int):
    page = await browser.new_page()
    try:
        async with ClickSolver(
            framework=FrameworkType.CAMOUFOX, page=page, max_attempts=3, attempt_delay=3
        ) as solver:
            await page.goto(login_url, wait_until="domcontentloaded")
            try:
                await page.wait_for_load_state("networkidle", timeout=30000)
            except Exception:
                pass
            print(f"ℹ️ {account_name}: login page loaded, title={await page.title()!r}")

            # Turnstile 常藏在“同意用户协议”之后
            for _ in range(3):
                try:
                    for cb in await page.query_selector_all('input[type="checkbox"]'):
                        try:
                            if not await cb.is_checked():
                                await cb.click(timeout=5000)
                        except Exception:
                            pass
                except Exception:
                    pass
                await page.wait_for_timeout(3000)
                st = await _dom_state(page)
                if st.get("iframes") or st.get("inputs"):
                    print(f"ℹ️ {account_name}: site widget appeared, dom={st}")
                    break
            return await _harvest(page, solver, account_name, timeout_ms)
    except Exception as e:
        print(f"⚠️ {account_name}: login page strategy failed: {e}")
        return None
    finally:
        try:
            await page.close()
        except Exception:
            pass


async def get_turnstile_token(
    login_url: str,
    site_key: str,
    account_name: str,
    proxy_config: dict | None = None,
    timeout_ms: int = 90000,
) -> str | None:
    """获取指定站点的 Turnstile token

    Args:
        login_url: 站点登录页地址（须与 site_key 同域，token 才有效）
        site_key: Turnstile site key（可从 /api/status 的 turnstile_site_key 获取）
        account_name: 账号名，仅用于日志
        proxy_config: 代理配置 {"server": ..., "username": ..., "password": ...}
        timeout_ms: 浏览器方案等待 token 的最长时间

    Returns:
        token 字符串，失败返回 None
    """
    parsed = urlparse(login_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    # 1) 2Captcha（若配置）——不依赖本机浏览器环境
    api_key = (os.getenv("TWOCAPTCHA_API_KEY") or "").strip()
    if api_key:
        tok = solve_turnstile_via_2captcha(login_url, site_key, api_key, account_name)
        if tok:
            return tok
        print(f"⚠️ {account_name}: 2Captcha failed, falling back to browser")

    print(
        f"ℹ️ {account_name}: Starting browser to get Turnstile token for {origin} "
        f"(sitekey={site_key[:12]}…, proxy: {'true' if proxy_config else 'false'})"
    )

    safe_name = "".join(c if c.isalnum() else "_" for c in account_name)
    with tempfile.TemporaryDirectory(prefix=f"camoufox_{safe_name}_turnstile_") as tmp_dir:
        async with AsyncCamoufox(
            persistent_context=True, user_data_dir=tmp_dir, **_cam_kwargs(proxy_config)
        ) as browser:
            strategies = (
                ("stub-page", _try_stub_page, (browser, site_key, origin, account_name, timeout_ms)),
                ("login-page", _try_login_page, (browser, login_url, account_name, timeout_ms)),
            )
            for label, fn, args in strategies:
                try:
                    token = await fn(*args)
                except Exception as e:
                    print(f"⚠️ {account_name}: strategy {label} raised: {e}")
                    token = None
                if token:
                    print(f"✅ {account_name}: Got Turnstile token via {label} (len={len(token)})")
                    return token
                print(f"ℹ️ {account_name}: strategy {label} produced no token")

    print(
        f"❌ {account_name}: Failed to get Turnstile token. "
        f"若日志中出现 600010 且 turnstile iframe 数为 0，通常是 IP 信誉问题："
        f"请配置 PROXY（住宅代理）或 TWOCAPTCHA_API_KEY。"
    )
    return None
