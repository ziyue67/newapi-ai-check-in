#!/usr/bin/env python3
"""
Cloudflare Turnstile token 获取模块

某些 NewAPI 站点（如 seekai.cc）在 POST /api/user/checkin 上启用了
middleware.TurnstileCheck()，必须携带 ?turnstile=<token> 才能签到。

策略（按顺序尝试）：
  1. 路由拦截：在目标站点同源下伪造一个极简页面，自己 explicit render 一个
     Turnstile widget。好处是没有站点 SPA / CSP / 广告拦截干扰，且 token 的
     hostname 仍然是目标站点（Turnstile sitekey 通常按域名白名单校验）。
  2. 回退到真实登录页：等待站点自己加载 turnstile API，勾选协议触发渲染。

两种方式都用 playwright_captcha 的 ClickSolver 处理交互式（managed）widget。
"""

from __future__ import annotations

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
<div id="box"></div>
<script>
  window.__TS_TOKEN__ = null;
  window.__TS_ERROR__ = null;
  window.__TS_READY__ = false;
  window.onloadTurnstileCallback = function () {
    window.__TS_READY__ = true;
    window.__TS_WIDGET__ = window.turnstile.render('#box', {
      sitekey: '__SITEKEY__',
      callback: function (t) { window.__TS_TOKEN__ = t; },
      'error-callback': function (e) { window.__TS_ERROR__ = String(e); }
    });
  };
</script>
<script src="__API__?onload=onloadTurnstileCallback&render=explicit" async defer></script>
</body></html>
"""

_READ_TOKEN_JS = """() => {
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
    for (const el of document.querySelectorAll('input[name="cf-turnstile-response"]')) {
        if (el.value) return el.value;
    }
    return null;
}"""


def _cam_kwargs(proxy_config: dict | None) -> dict:
    kw = dict(
        headless=False,
        humanize=True,
        locale="en-US",
        geoip=True if proxy_config else False,
        proxy=proxy_config,
        os="macos",
        config={"forceScopeAccess": True},
    )
    if _EXCLUDE_ADDONS:
        kw["exclude_addons"] = _EXCLUDE_ADDONS
    return kw


async def _harvest(page, solver, account_name: str, timeout_ms: int) -> str | None:
    """widget 已在页面上后，处理交互并取回 token"""
    token = await page.evaluate(_READ_TOKEN_JS)
    if token:
        return token

    try:
        await solver.solve_captcha(
            captcha_container=page, captcha_type=CaptchaType.CLOUDFLARE_TURNSTILE
        )
        print(f"✅ {account_name}: widget solved by ClickSolver")
    except Exception as e:
        print(f"⚠️ {account_name}: ClickSolver did not complete ({e}), polling anyway")

    try:
        await page.wait_for_function("() => !!window.__TS_TOKEN__", timeout=timeout_ms)
    except Exception:
        pass
    return await page.evaluate(_READ_TOKEN_JS)


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
            try:
                await page.wait_for_function("() => window.__TS_READY__ === true", timeout=45000)
                print(f"ℹ️ {account_name}: Turnstile API loaded on stub page")
            except Exception:
                err = await page.evaluate("() => window.__TS_ERROR__")
                print(f"⚠️ {account_name}: stub page API not ready (err={err})")
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


async def _try_login_page(browser, site_key: str, login_url: str, account_name: str, timeout_ms: int):
    """策略 2：真实登录页，等站点自己加载 turnstile"""
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

            # Turnstile 常藏在“同意协议”之后
            try:
                for cb in await page.query_selector_all('input[type="checkbox"]'):
                    try:
                        if not await cb.is_checked():
                            await cb.click(timeout=5000)
                    except Exception:
                        pass
                await page.wait_for_timeout(3000)
            except Exception:
                pass

            try:
                await page.wait_for_function(
                    "() => typeof window.turnstile !== 'undefined' && !!window.turnstile.render",
                    timeout=30000,
                )
            except Exception:
                frames = await page.evaluate(
                    "() => document.querySelectorAll('iframe[src*=\"turnstile\"]').length"
                )
                print(
                    f"⚠️ {account_name}: site turnstile API unavailable "
                    f"(turnstile iframes={frames})"
                )
                return None

            token = await page.evaluate(_READ_TOKEN_JS)
            if not token:
                try:
                    await page.evaluate(
                        """(sitekey) => {
                            window.__TS_TOKEN__ = null;
                            let host = document.getElementById('__ts_host__');
                            if (!host) {
                                host = document.createElement('div');
                                host.id = '__ts_host__';
                                host.style.cssText = 'position:fixed;left:12px;bottom:12px;z-index:2147483647;';
                                document.body.appendChild(host);
                            }
                            window.__TS_WIDGET__ = window.turnstile.render(host, {
                                sitekey: sitekey,
                                callback: (t) => { window.__TS_TOKEN__ = t; },
                                'error-callback': (e) => { window.__TS_ERROR__ = String(e); },
                            });
                        }""",
                        site_key,
                    )
                    await page.wait_for_timeout(3000)
                except Exception as e:
                    print(f"⚠️ {account_name}: explicit render on login page failed: {e}")
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
            for label, coro in (
                ("stub-page", _try_stub_page(browser, site_key, origin, account_name, timeout_ms)),
                ("login-page", _try_login_page(browser, site_key, login_url, account_name, timeout_ms)),
            ):
                try:
                    token = await coro
                except Exception as e:
                    print(f"⚠️ {account_name}: strategy {label} raised: {e}")
                    token = None
                if token:
                    print(f"✅ {account_name}: Got Turnstile token via {label} (len={len(token)})")
                    return token
                print(f"ℹ️ {account_name}: strategy {label} produced no token")

    print(f"❌ {account_name}: Failed to get Turnstile token (all strategies exhausted)")
    return None
