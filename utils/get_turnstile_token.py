#!/usr/bin/env python3
"""
Cloudflare Turnstile token 获取模块

某些 NewAPI 站点（如 seekai.cc）在 POST /api/user/checkin 上启用了
middleware.TurnstileCheck()，必须携带 ?turnstile=<token> 才能签到。

本模块使用 Camoufox 打开站点登录页，优先复用站点自身的 Turnstile widget，
借助 playwright_captcha 的 ClickSolver 完成交互式验证并取回 token。
"""

from __future__ import annotations

import tempfile

from camoufox.async_api import AsyncCamoufox
from playwright_captcha import CaptchaType, ClickSolver, FrameworkType

try:  # uBlock Origin 有可能拦掉 challenges.cloudflare.com 的脚本
    from camoufox import DefaultAddons

    _EXCLUDE_ADDONS = [DefaultAddons.UBO]
except Exception:  # pragma: no cover - 老版本 camoufox 没有该枚举
    _EXCLUDE_ADDONS = None

TURNSTILE_API = "https://challenges.cloudflare.com/turnstile/v0/api.js"

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
    for (const el of document.querySelectorAll('input[name="cf-turnstile-response"], input[name="g-recaptcha-response"]')) {
        if (el.value) return el.value;
    }
    return null;
}"""


async def _wait_turnstile_api(page, account_name: str, timeout_ms: int) -> bool:
    """等待页面自身加载 turnstile API，返回是否可用"""
    try:
        await page.wait_for_function(
            "() => typeof window.turnstile !== 'undefined' && !!window.turnstile.render",
            timeout=timeout_ms,
        )
        return True
    except Exception:
        return False


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
    safe_name = "".join(c if c.isalnum() else "_" for c in account_name)
    print(
        f"ℹ️ {account_name}: Starting browser to get Turnstile token from {login_url} "
        f"(using proxy: {'true' if proxy_config else 'false'})"
    )

    cam_kwargs = dict(
        persistent_context=True,
        headless=False,
        humanize=True,
        locale="en-US",
        geoip=True if proxy_config else False,
        proxy=proxy_config,
        os="macos",
        config={"forceScopeAccess": True},
    )
    if _EXCLUDE_ADDONS:
        cam_kwargs["exclude_addons"] = _EXCLUDE_ADDONS

    with tempfile.TemporaryDirectory(prefix=f"camoufox_{safe_name}_turnstile_") as tmp_dir:
        async with AsyncCamoufox(user_data_dir=tmp_dir, **cam_kwargs) as browser:
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
                    print(f"ℹ️ {account_name}: page loaded, title={await page.title()!r}")

                    # 站点登录页通常把 Turnstile 藏在“同意协议”之后，先勾选触发渲染
                    try:
                        for cb in await page.query_selector_all('input[type="checkbox"]'):
                            try:
                                if not await cb.is_checked():
                                    await cb.click(timeout=5000)
                            except Exception:
                                pass
                        await page.wait_for_timeout(3000)
                    except Exception as e:
                        print(f"⚠️ {account_name}: agreement checkbox handling skipped: {e}")

                    # 站点自己会加载 challenges.cloudflare.com/api.js，先等它
                    has_api = await _wait_turnstile_api(page, account_name, 30000)
                    if has_api:
                        print(f"ℹ️ {account_name}: Turnstile API provided by site")
                    else:
                        print(f"ℹ️ {account_name}: Injecting Turnstile API script")
                        injected = False
                        for attempt in (1, 2):
                            try:
                                await page.add_script_tag(url=f"{TURNSTILE_API}?render=explicit")
                                injected = True
                                break
                            except Exception as e:
                                print(f"⚠️ {account_name}: add_script_tag attempt {attempt} failed: {e}")
                                await page.wait_for_timeout(3000)
                        if injected:
                            has_api = await _wait_turnstile_api(page, account_name, 30000)
                        if not has_api:
                            print(
                                f"❌ {account_name}: Turnstile API unavailable "
                                f"(site script blocked and injection failed)"
                            )
                            return None

                    # 站点自身的 widget 可能已经渲染好，先直接尝试读取
                    token = await page.evaluate(_READ_TOKEN_JS)

                    if not token:
                        # 自己渲染一个 widget，回调把 token 写到 window.__TS_TOKEN__
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
                                        'error-callback': () => { window.__TS_ERROR__ = true; },
                                    });
                                }""",
                                site_key,
                            )
                            await page.wait_for_timeout(4000)
                        except Exception as e:
                            print(f"⚠️ {account_name}: explicit render failed: {e}")

                        # 交互式（managed）widget 需要点击，交给 solver
                        try:
                            await solver.solve_captcha(
                                captcha_container=page,
                                captcha_type=CaptchaType.CLOUDFLARE_TURNSTILE,
                            )
                            print(f"✅ {account_name}: Turnstile widget solved by ClickSolver")
                        except Exception as e:
                            print(f"⚠️ {account_name}: ClickSolver did not complete ({e}), polling anyway")

                        try:
                            await page.wait_for_function(
                                "() => !!window.__TS_TOKEN__", timeout=timeout_ms
                            )
                        except Exception:
                            pass

                        token = await page.evaluate(_READ_TOKEN_JS)

                    if token:
                        print(f"✅ {account_name}: Got Turnstile token (len={len(token)})")
                        return token

                    frames = await page.evaluate(
                        "() => document.querySelectorAll('iframe[src*=\"turnstile\"]').length"
                    )
                    print(
                        f"❌ {account_name}: Failed to get Turnstile token "
                        f"(turnstile iframes on page: {frames})"
                    )
                    return None
            except Exception as e:
                print(f"❌ {account_name}: Error getting Turnstile token: {e}")
                return None
            finally:
                await page.close()
