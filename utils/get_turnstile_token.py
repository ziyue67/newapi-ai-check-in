#!/usr/bin/env python3
"""
Cloudflare Turnstile token 获取模块

某些 NewAPI 站点（如 seekai.cc）在 POST /api/user/checkin 上启用了
middleware.TurnstileCheck()，必须携带 ?turnstile=<token> 才能签到。

本模块使用 Camoufox 打开站点登录页，注入/复用 Turnstile widget，
借助 playwright_captcha 的 ClickSolver 完成交互式验证并取回 token。
"""

from __future__ import annotations

import tempfile

from camoufox.async_api import AsyncCamoufox
from playwright_captcha import CaptchaType, ClickSolver, FrameworkType

TURNSTILE_API = "https://challenges.cloudflare.com/turnstile/v0/api.js"


async def get_turnstile_token(
    login_url: str,
    site_key: str,
    account_name: str,
    proxy_config: dict | None = None,
    timeout_ms: int = 90000,
) -> str | None:
    """获取指定站点的 Turnstile token

    Args:
        login_url: 站点登录页地址（与 site_key 同域，token 才有效）
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

    with tempfile.TemporaryDirectory(prefix=f"camoufox_{safe_name}_turnstile_") as tmp_dir:
        async with AsyncCamoufox(
            persistent_context=True,
            user_data_dir=tmp_dir,
            headless=False,
            humanize=True,
            locale="en-US",
            geoip=True if proxy_config else False,
            proxy=proxy_config,
            os="macos",
            config={"forceScopeAccess": True},
        ) as browser:
            page = await browser.new_page()
            try:
                async with ClickSolver(
                    framework=FrameworkType.CAMOUFOX, page=page, max_attempts=5, attempt_delay=3
                ) as solver:
                    await page.goto(login_url, wait_until="networkidle")
                    await page.wait_for_timeout(4000)

                    # 站点登录页通常会把 Turnstile 藏在协议勾选之后，先尝试勾选
                    try:
                        for cb in await page.query_selector_all('input[type="checkbox"]'):
                            try:
                                if not await cb.is_checked():
                                    await cb.click()
                            except Exception:
                                pass
                        await page.wait_for_timeout(2000)
                    except Exception as e:
                        print(f"⚠️ {account_name}: agreement checkbox handling skipped: {e}")

                    # 确保 turnstile API 已加载
                    has_api = await page.evaluate("() => typeof window.turnstile !== 'undefined'")
                    if not has_api:
                        print(f"ℹ️ {account_name}: Injecting Turnstile API script")
                        await page.add_script_tag(url=f"{TURNSTILE_API}?render=explicit")
                        await page.wait_for_function(
                            "() => typeof window.turnstile !== 'undefined'", timeout=20000
                        )

                    # 自己渲染一个 widget，回调把 token 写到 window.__TS_TOKEN__
                    await page.evaluate(
                        """(sitekey) => {
                            window.__TS_TOKEN__ = null;
                            const host = document.createElement('div');
                            host.id = '__ts_host__';
                            host.style.cssText = 'position:fixed;left:12px;bottom:12px;z-index:2147483647;';
                            document.body.appendChild(host);
                            window.__TS_WIDGET__ = window.turnstile.render(host, {
                                sitekey: sitekey,
                                callback: (t) => { window.__TS_TOKEN__ = t; },
                                'error-callback': () => { window.__TS_ERROR__ = true; },
                            });
                        }""",
                        site_key,
                    )
                    await page.wait_for_timeout(4000)

                    # 交互式（managed）widget 需要点击，交给 solver 处理
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

                    token = await page.evaluate(
                        """() => {
                            if (window.__TS_TOKEN__) return window.__TS_TOKEN__;
                            try {
                                if (window.__TS_WIDGET__ && window.turnstile.getResponse) {
                                    return window.turnstile.getResponse(window.__TS_WIDGET__) || null;
                                }
                            } catch (e) {}
                            const el = document.querySelector('input[name="cf-turnstile-response"]');
                            return el && el.value ? el.value : null;
                        }"""
                    )

                    if token:
                        print(f"✅ {account_name}: Got Turnstile token (len={len(token)})")
                        return token

                    print(f"❌ {account_name}: Failed to get Turnstile token")
                    return None
            except Exception as e:
                print(f"❌ {account_name}: Error getting Turnstile token: {e}")
                return None
            finally:
                await page.close()
