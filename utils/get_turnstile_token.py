#!/usr/bin/env python3
"""
Cloudflare Turnstile token 获取模块

某些 NewAPI 站点（如 seekai.cc）在 POST /api/user/checkin 上启用了
middleware.TurnstileCheck()，必须携带 ?turnstile=<token> 才能签到。

关键实现细节
------------
Camoufox 默认把 page.evaluate 跑在**隔离世界**（isolated world），因此看不到
页面主世界里的 window.turnstile / 自定义 window 变量。本模块因此：

  * 启动时开启 main_world_eval=True，需要访问主世界时用 "mw:" 前缀 evaluate；
  * 不用 wait_for_function（无法指定 world），改为自己轮询；
  * token 优先从 DOM 隐藏域 input[name="cf-turnstile-response"] 读取
    —— DOM 在两个 world 之间是共享的，这条路最稳。

策略顺序：
  1. 同源 stub 页面（page.route 伪造 {origin}/__hermes_turnstile__）+ explicit render。
     没有 SPA / CSP / 广告拦截干扰，且 token 的 hostname 仍是目标站点。
  2. 回退到真实登录页（勾选协议触发站点自身 widget）。
"""

from __future__ import annotations

import asyncio
import tempfile
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
  window.__TS_TOKEN__ = null;
  window.__TS_ERROR__ = null;
  window.__TS_READY__ = false;
  window.onloadTurnstileCallback = function () {
    window.__TS_READY__ = true;
    document.title = 'ts-ready';
    window.__TS_WIDGET__ = window.turnstile.render('#box', {
      sitekey: '__SITEKEY__',
      callback: function (t) { window.__TS_TOKEN__ = t; document.title = 'ts-ok'; },
      'error-callback': function (e) { window.__TS_ERROR__ = String(e); document.title = 'ts-err'; }
    });
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

# 需要主世界（"mw:" 前缀）
_MW_TOKEN_JS = """() => {
    if (window.__TS_TOKEN__) return window.__TS_TOKEN__;
    try {
        if (window.turnstile && window.turnstile.getResponse) {
            if (window.__TS_WIDGET__) {
                const v = window.turnstile.getResponse(window.__TS_WIDGET__);
                if (v) return v;
            }
            const v2 = window.turnstile.getResponse();
            if (v2) return v2;
        }
    } catch (e) {}
    return null;
}"""

_DOM_STATE_JS = """() => ({
    iframes: document.querySelectorAll('iframe[src*="turnstile"]').length,
    inputs: document.querySelectorAll('input[name="cf-turnstile-response"]').length,
    title: document.title,
})"""


def _cam_kwargs(proxy_config: dict | None) -> dict:
    kw = dict(
        headless=False,
        humanize=True,
        locale="en-US",
        geoip=True if proxy_config else False,
        proxy=proxy_config,
        os="macos",
        main_world_eval=True,  # 允许 "mw:" 前缀访问主世界
        config={"forceScopeAccess": True},
    )
    if _EXCLUDE_ADDONS:
        kw["exclude_addons"] = _EXCLUDE_ADDONS
    return kw


async def _mw(page, script: str):
    """在主世界执行脚本，失败返回 None"""
    try:
        return await page.evaluate("mw:" + script)
    except Exception:
        return None


async def _read_token(page) -> str | None:
    """先 DOM 后主世界"""
    try:
        tok = await page.evaluate(_DOM_TOKEN_JS)
    except Exception:
        tok = None
    if tok:
        return tok
    return await _mw(page, _MW_TOKEN_JS)


async def _poll_token(page, account_name: str, timeout_ms: int) -> str | None:
    """轮询等待 token（不用 wait_for_function，它无法指定 world）"""
    waited = 0
    step = 2000
    while waited < timeout_ms:
        tok = await _read_token(page)
        if tok:
            return tok
        await page.wait_for_timeout(step)
        waited += step
    return None


async def _harvest(page, solver, account_name: str, timeout_ms: int) -> str | None:
    """widget 已挂上页面后：先直接读，再交给 solver 点击，最后轮询"""
    tok = await _read_token(page)
    if tok:
        return tok

    state = await page.evaluate(_DOM_STATE_JS)
    print(f"ℹ️ {account_name}: dom state before solve -> {state}")

    try:
        await solver.solve_captcha(
            captcha_container=page, captcha_type=CaptchaType.CLOUDFLARE_TURNSTILE
        )
        print(f"✅ {account_name}: widget solved by ClickSolver")
    except Exception as e:
        print(f"⚠️ {account_name}: ClickSolver did not complete ({e}), polling anyway")

    tok = await _poll_token(page, account_name, timeout_ms)
    if not tok:
        state = await page.evaluate(_DOM_STATE_JS)
        err = await _mw(page, "() => window.__TS_ERROR__")
        print(f"⚠️ {account_name}: no token; dom={state} ts_error={err}")
    return tok


async def _wait_stub_ready(page, account_name: str, timeout_ms: int = 45000) -> bool:
    """stub 页面：等 turnstile API onload 回调（通过 document.title 传信号，DOM 共享）"""
    waited = 0
    while waited < timeout_ms:
        try:
            state = await page.evaluate(_DOM_STATE_JS)
        except Exception:
            state = {}
        if state.get("title") in ("ts-ready", "ts-ok") or state.get("iframes"):
            return True
        if state.get("title") == "ts-err":
            return False
        await page.wait_for_timeout(2000)
        waited += 2000
    return False


async def _try_stub_page(browser, site_key: str, origin: str, account_name: str, timeout_ms: int):
    """策略 1：同源伪造页面 + explicit render"""
    page = await browser.new_page()
    html = _STUB_HTML.replace("__SITEKEY__", site_key).replace("__API__", TURNSTILE_API)
    stub_url = f"{origin}{_STUB_PATH}"

    async def handler(route):
        await route.fulfill(status=200, content_type="text/html; charset=utf-8", body=html)

    try:
        await page.route(stub_url, handler)
        async with ClickSolver(
            framework=FrameworkType.CAMOUFOX, page=page, max_attempts=5, attempt_delay=3
        ) as solver:
            await page.goto(stub_url, wait_until="domcontentloaded")
            if not await _wait_stub_ready(page, account_name):
                state = await page.evaluate(_DOM_STATE_JS)
                print(f"⚠️ {account_name}: stub page widget not ready, dom={state}")
                return None
            print(f"ℹ️ {account_name}: stub page widget rendered")
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


async def _try_login_page(browser, site_key: str, login_url: str, account_name: str, timeout_ms: int):
    """策略 2：真实登录页，勾协议触发站点自身 widget"""
    page = await browser.new_page()
    try:
        async with ClickSolver(
            framework=FrameworkType.CAMOUFOX, page=page, max_attempts=5, attempt_delay=3
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
                    boxes = await page.query_selector_all('input[type="checkbox"]')
                    for cb in boxes:
                        try:
                            if not await cb.is_checked():
                                await cb.click(timeout=5000)
                        except Exception:
                            pass
                except Exception:
                    pass
                await page.wait_for_timeout(3000)
                state = await page.evaluate(_DOM_STATE_JS)
                if state.get("iframes") or state.get("inputs"):
                    print(f"ℹ️ {account_name}: site widget appeared, dom={state}")
                    break
            else:
                state = await page.evaluate(_DOM_STATE_JS)
                print(f"ℹ️ {account_name}: site widget not visible yet, dom={state}")

            # 站点没渲染就自己 explicit render（主世界）
            tok = await _read_token(page)
            if not tok:
                await _mw(
                    page,
                    """() => {
                        if (!window.turnstile || !window.turnstile.render) return 'no-api';
                        window.__TS_TOKEN__ = null;
                        let host = document.getElementById('__ts_host__');
                        if (!host) {
                            host = document.createElement('div');
                            host.id = '__ts_host__';
                            host.style.cssText = 'position:fixed;left:12px;bottom:12px;z-index:2147483647;';
                            document.body.appendChild(host);
                        }
                        window.__TS_WIDGET__ = window.turnstile.render(host, {
                            sitekey: '%s',
                            callback: (t) => { window.__TS_TOKEN__ = t; },
                            'error-callback': (e) => { window.__TS_ERROR__ = String(e); },
                        });
                        return 'rendered';
                    }"""
                    % site_key,
                )
                await page.wait_for_timeout(3000)
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
        timeout_ms: 等待 token 的最长时间

    Returns:
        token 字符串，失败返回 None
    """
    parsed = urlparse(login_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    safe_name = "".join(c if c.isalnum() else "_" for c in account_name)

    print(
        f"ℹ️ {account_name}: Starting browser to get Turnstile token for {origin} "
        f"(sitekey={site_key[:12]}…, proxy: {'true' if proxy_config else 'false'})"
    )

    with tempfile.TemporaryDirectory(prefix=f"camoufox_{safe_name}_turnstile_") as tmp_dir:
        async with AsyncCamoufox(
            persistent_context=True, user_data_dir=tmp_dir, **_cam_kwargs(proxy_config)
        ) as browser:
            strategies = (
                ("stub-page", _try_stub_page, (browser, site_key, origin, account_name, timeout_ms)),
                ("login-page", _try_login_page, (browser, site_key, login_url, account_name, timeout_ms)),
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

    print(f"❌ {account_name}: Failed to get Turnstile token (all strategies exhausted)")
    return None
