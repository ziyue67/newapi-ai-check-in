#!/usr/bin/env python3
"""
签到状态查询模块

提供各种签到状态查询函数
"""

from __future__ import annotations

from datetime import datetime
import time
from typing import TYPE_CHECKING

from curl_cffi import requests as curl_requests

from utils.http_utils import proxy_resolve, response_resolve
from utils.get_headers import get_curl_cffi_impersonate

if TYPE_CHECKING:
    from utils.config import AccountConfig, ProviderConfig


def get_newapi_check_in_status(
    provider_config: "ProviderConfig",
    account_config: "AccountConfig",
    cookies: dict,
    headers: dict,
    path: str = "/api/user/checkin",
    attempts: int = 3,
) -> bool:
    """
    查询标准 newapi 签到状态，自动拼接当前月份

    Args:
        provider_config: Provider 配置
        account_config: 账号配置
        cookies: cookies 字典
        headers: 请求头字典
        path: 签到状态接口路径，默认为 "/api/user/checkin"
        attempts: 网络层失败时的重试次数（这些站点常在 CF 后偶发 502/超时）

    Returns:
        bool: 今日是否已签到
    """
    for attempt in range(1, attempts + 1):
        ok, result = _query_check_in_status_once(
            provider_config, account_config, cookies, headers, path
        )
        if ok:
            return result
        if attempt < attempts:
            account_name = account_config.get_display_name()
            print(f"⚠️ {account_name}: Retrying check-in status ({attempt}/{attempts - 1})")
            time.sleep(3 * attempt)
    return False


def _query_check_in_status_once(
    provider_config: "ProviderConfig",
    account_config: "AccountConfig",
    cookies: dict,
    headers: dict,
    path: str = "/api/user/checkin",
) -> tuple[bool, bool]:
    """单次查询签到状态。

    Returns:
        (query_ok, checked_in_today) —— query_ok=False 表示这次请求本身失败，
        调用方可以重试；不要把网络失败当成「今天没签到」以外的信号使用。
    """
    account_name = account_config.get_display_name()
    # 代理优先级: 账号配置 > 全局配置
    proxy_config = account_config.proxy or account_config.get("global_proxy")
    http_proxy = proxy_resolve(proxy_config)
    
    current_month = datetime.now().strftime("%Y-%m")
    check_in_status_url = f"{provider_config.origin}{path}?month={current_month}"

    print(f"🔍 {account_name}: Getting check-in status")

    # 根据 User-Agent 自动推断 impersonate 值
    user_agent = headers.get("User-Agent", "")
    impersonate = get_curl_cffi_impersonate(user_agent) if user_agent else "firefox135"

    try:
        session = curl_requests.Session(impersonate=impersonate, proxy=http_proxy, timeout=30)
        try:
            session.cookies.update(cookies)
            response = session.get(
                check_in_status_url,
                headers=headers,
                timeout=30,
            )

            if response.status_code == 200:
                json_data = response_resolve(response, "get_check_in_status", account_name)
                if json_data is None:
                    print(f"❌ {account_name}: Invalid response format for check-in status")
                    return False, False

                if json_data.get("success"):
                    status_data = json_data.get("data", {})
                    stats = status_data.get("stats", {})

                    checked_in_today = stats.get("checked_in_today", False)
                    checkin_count = stats.get("checkin_count", 0)
                    total_quota = stats.get("total_quota", 0)

                    total_quota_display = round(total_quota / 500000, 2) if total_quota else 0

                    print(
                        f"📊 {account_name}: Check-in status - "
                        f"Today: {'✅' if checked_in_today else '❌'}, "
                        f"Count: {checkin_count}, "
                        f"Total quota: ${total_quota_display}"
                    )

                    return True, checked_in_today
                else:
                    error_msg = json_data.get("message", "Unknown error")
                    print(f"❌ {account_name}: Failed to get check-in status: {error_msg}")
                    return True, False
            else:
                print(f"❌ {account_name}: Failed to get check-in status: HTTP {response.status_code}")
                return False, False
        finally:
            session.close()
    except Exception as e:
        print(f"❌ {account_name}: Error getting check-in status: {e}")
        return False, False


def create_newapi_check_in_status(
    path: str = "/api/user/checkin",
):
    """
    创建一个标准 newapi 签到状态查询函数

    用于 ProviderConfig 的 check_in_status 配置

    Args:
        path: 签到状态接口路径，默认为 "/api/user/checkin"

    Returns:
        Callable: 签到状态查询函数，签名为 (provider_config, account_config, cookies, headers) -> bool
    """

    def _check_status(
        provider_config: "ProviderConfig",
        account_config: "AccountConfig",
        cookies: dict,
        headers: dict,
    ) -> bool:
        return get_newapi_check_in_status(
            provider_config=provider_config,
            account_config=account_config,
            cookies=cookies,
            headers=headers,
            path=path,
        )

    return _check_status


# 预定义的标准 newapi 签到状态查询函数
newapi_check_in_status = create_newapi_check_in_status()