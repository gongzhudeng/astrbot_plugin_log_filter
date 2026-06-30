"""
Log filter plugin for AstrBot.

Injects a logging.Filter into the root logger that suppresses all log lines
produced by sessions that are NOT in the platform whitelist.

Each rejected message generates a burst of ~6 consecutive log lines:
  1. [DBUG] aiocqhttp_platform_adapter  – RawMessage <Event, {'group_id': ...}>
  2. [INFO] core.event_bus              – 昵称/sender_id: 消息
  3. [DBUG] waking_check.stage         – enabled_plugins_name
  4. [INFO] whitelist_check.stage      – 会话 ID ... 不在会话白名单中
  5. [DBUG] pipeline.scheduler         – 阶段 WhitelistCheckStage 已终止
  6. [DBUG] pipeline.scheduler         – pipeline 执行完毕

The filter is stateful: on seeing line 1 it decides to block, then suppresses
everything until the "pipeline 执行完毕" sentinel resets the flag.
"""

import logging
import re

from astrbot.api import logger
from astrbot.api.event import filter
from astrbot.api.star import Context, Star, register
from astrbot.core.config.astrbot_config import AstrBotConfig

# Regex to pull the group_id out of a RawMessage line.
_GROUP_ID_RE = re.compile(r"'group_id':\s*(\d+)")
# Sentinel that marks the end of a pipeline burst.
_PIPELINE_DONE = "pipeline 执行完毕"
# Sentinel that marks a non-whitelist INFO line from whitelist_check.
_WHITELIST_BLOCKED = "不在会话白名单中"


class _NonWhitelistFilter(logging.Filter):
    """Stateful log filter – suppresses log bursts for non-whitelisted sessions."""

    def __init__(self) -> None:
        super().__init__()
        self._blocking: bool = False
        # Populated by the plugin on init and on every config reload.
        self.platform_whitelist: set[str] = set()
        self.extra_blocklist: set[str] = set()
        self.extra_allowlist: set[str] = set()
        self.enabled: bool = True

    # ------------------------------------------------------------------
    # public helpers for the plugin to push updated sets
    # ------------------------------------------------------------------

    def update_lists(
        self,
        platform_whitelist: list[str],
        extra_blocklist: list[str],
        extra_allowlist: list[str],
        enabled: bool,
    ) -> None:
        self.platform_whitelist = {str(x).strip() for x in platform_whitelist if str(x).strip()}
        self.extra_blocklist = {str(x).strip() for x in extra_blocklist if str(x).strip()}
        self.extra_allowlist = {str(x).strip() for x in extra_allowlist if str(x).strip()}
        self.enabled = enabled

    # ------------------------------------------------------------------
    # internal helpers
    # ------------------------------------------------------------------

    def _effective_whitelist(self) -> set[str]:
        """Combine platform whitelist, removing explicitly blocked entries."""
        wl = self.platform_whitelist - self.extra_blocklist
        wl |= self.extra_allowlist
        return wl

    def _is_group_id_blocked(self, group_id_str: str) -> bool:
        """
        Return True if this group_id should be filtered out.

        Blocked when the ID appears in neither:
          - the platform whitelist (numeric form)
          - an explicit allowlist override
        OR when it explicitly appears in extra_blocklist.
        """
        if group_id_str in self.extra_allowlist:
            return False
        if group_id_str in self.extra_blocklist:
            return True
        # If whitelist is empty AstrBot doesn't filter at all – don't filter here either.
        if not self.platform_whitelist:
            return False
        # Check both bare group_id and common unified_msg_origin patterns.
        for pattern in (
            group_id_str,
            f"GroupMessage:{group_id_str}",
        ):
            for wl_entry in self.platform_whitelist:
                if pattern in wl_entry or wl_entry == group_id_str:
                    return False
        return True

    # ------------------------------------------------------------------
    # core filter method
    # ------------------------------------------------------------------

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        if not self.enabled:
            return True

        try:
            msg = record.getMessage()
        except Exception:
            return True

        # --- Detect burst start: the RawMessage line from the adapter ---
        if "RawMessage" in msg:
            m = _GROUP_ID_RE.search(msg)
            if m and self._is_group_id_blocked(m.group(1)):
                self._blocking = True
                return False
            # Recognised RawMessage but not blocked – ensure flag is clear.
            self._blocking = False
            return True

        # --- Carry-through suppression ---
        if self._blocking:
            if _PIPELINE_DONE in msg:
                self._blocking = False
            return False

        # --- Suppress the whitelist-check INFO line even outside a burst
        #     (edge case: filter was reloaded mid-burst).
        if _WHITELIST_BLOCKED in msg:
            return False

        return True


@register(
    "日志过滤器",
    "灵犀",
    "过滤非白名单会话产生的日志噪音，保持日志整洁",
    "1.0.0",
    "https://github.com/gongzhudeng/astrbot_plugin_log_filter",
)
class LogFilterPlugin(Star):
    def __init__(self, context: Context, config: AstrBotConfig) -> None:
        super().__init__(context)
        self.config = config
        self._filter = _NonWhitelistFilter()
        self._install_filter()
        self._reload_lists()
        logger.info("[日志过滤器] 已安装日志过滤器")

    # ------------------------------------------------------------------
    # filter lifecycle
    # ------------------------------------------------------------------

    def _install_filter(self) -> None:
        root = logging.getLogger()
        # Avoid double-installing if the plugin is hot-reloaded.
        for existing in root.filters:
            if isinstance(existing, _NonWhitelistFilter):
                self._filter = existing
                return
        root.addFilter(self._filter)

    def _remove_filter(self) -> None:
        root = logging.getLogger()
        root.filters = [f for f in root.filters if not isinstance(f, _NonWhitelistFilter)]

    # ------------------------------------------------------------------
    # whitelist sync
    # ------------------------------------------------------------------

    def _reload_lists(self) -> None:
        """Pull the current platform whitelist from AstrBot config."""
        try:
            platform_whitelist: list = (
                self.context.astrbot_config
                .get("platform_settings", {})
                .get("id_whitelist", [])
            )
        except Exception:
            platform_whitelist = []

        extra_blocklist: list = self.config.get("extra_blocklist", []) or []
        extra_allowlist: list = self.config.get("extra_allowlist", []) or []
        enabled: bool = bool(self.config.get("enabled", True))

        self._filter.update_lists(
            platform_whitelist=platform_whitelist,
            extra_blocklist=extra_blocklist,
            extra_allowlist=extra_allowlist,
            enabled=enabled,
        )

    # ------------------------------------------------------------------
    # commands
    # ------------------------------------------------------------------

    @filter.command("日志过滤状态")
    async def cmd_status(self, event):
        """显示当前过滤规则。"""
        self._reload_lists()
        f = self._filter
        lines = [
            "日志过滤器状态",
            f"启用：{'是' if f.enabled else '否'}",
            f"平台白名单（{len(f.platform_whitelist)} 条）：",
            *(([f"  {x}" for x in sorted(f.platform_whitelist)]) or ["  （空）"]),
            f"额外屏蔽（{len(f.extra_blocklist)} 条）：",
            *(([f"  {x}" for x in sorted(f.extra_blocklist)]) or ["  （空）"]),
            f"强制放行（{len(f.extra_allowlist)} 条）：",
            *(([f"  {x}" for x in sorted(f.extra_allowlist)]) or ["  （空）"]),
        ]
        yield event.plain_result("\n".join(lines))

    @filter.command("日志过滤刷新")
    async def cmd_reload(self, event):
        """从 AstrBot 配置重新同步白名单。"""
        self._reload_lists()
        yield event.plain_result(
            f"白名单已刷新，当前 {len(self._filter.platform_whitelist)} 条。"
        )

    # ------------------------------------------------------------------
    # cleanup
    # ------------------------------------------------------------------

    async def terminate(self) -> None:
        self._remove_filter()
        logger.info("[日志过滤器] 已移除日志过滤器")