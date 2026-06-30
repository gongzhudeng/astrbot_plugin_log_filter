"""
Log filter plugin for AstrBot.

Injects a logging.Filter into the "astrbot" (and root) logger handlers that
suppresses log bursts produced by sessions NOT in the platform whitelist.

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

# Regexes to extract IDs from a RawMessage line.
_GROUP_ID_RE = re.compile(r"'group_id':\s*(\d+)")
_USER_ID_RE = re.compile(r"'user_id':\s*(\d+)")
# Sentinel that marks the end of a pipeline burst.
_PIPELINE_DONE = "pipeline 执行完毕"
# Sentinel that marks a non-whitelist INFO line from whitelist_check.
_WHITELIST_BLOCKED = "不在会话白名单中"


class _NonWhitelistFilter(logging.Filter):
    """Stateful log filter – suppresses log bursts for non-whitelisted sessions."""

    def __init__(self) -> None:
        super().__init__()
        self._blocking: bool = False
        self.platform_whitelist: set[str] = set()
        self.extra_blocklist: set[str] = set()
        self.extra_allowlist: set[str] = set()
        self.enabled: bool = True

    # ------------------------------------------------------------------
    # public helpers
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

    def _should_block_raw(self, msg: str) -> bool:
        """
        Given a full RawMessage log line, decide whether this session is blocked.

        Group message : has group_id → match bare number or GroupMessage:xxx.
        Friend message: no group_id, has user_id → match FriendMessage:xxx /
                        platform:FriendMessage:xxx patterns.
        """
        if not self.platform_whitelist:
            # whitelist empty → AstrBot itself doesn't filter → pass everything
            return False

        group_m = _GROUP_ID_RE.search(msg)
        user_m = _USER_ID_RE.search(msg)

        if group_m:
            gid = group_m.group(1)
            candidates = (gid, f"GroupMessage:{gid}")
        elif user_m:
            uid = user_m.group(1)
            candidates = (uid, f"FriendMessage:{uid}", f"default:FriendMessage:{uid}")
        else:
            return False  # can't determine session → pass

        for candidate in candidates:
            if candidate in self.extra_allowlist:
                return False
            if candidate in self.extra_blocklist:
                return True
            for wl_entry in self.platform_whitelist:
                if candidate in wl_entry or wl_entry == candidate:
                    return False

        return True  # not found in whitelist → block

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

        # --- Detect burst start: RawMessage line from the adapter ---
        if "RawMessage" in msg:
            if self._should_block_raw(msg):
                self._blocking = True
                return False
            self._blocking = False
            return True

        # --- Carry-through suppression ---
        if self._blocking:
            if _PIPELINE_DONE in msg:
                self._blocking = False
            return False

        # --- Suppress whitelist-check INFO line even outside a burst ---
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
        # "astrbot" logger has propagate=False, so its handlers never reach root.
        # aiocqhttp.* loggers propagate=True and reach root handlers.
        # Attach the same filter instance to ALL handlers on both so the shared
        # _blocking flag is consistent across both log paths.
        count = 0
        for logger_name in (None, "astrbot"):
            target = logging.getLogger() if logger_name is None else logging.getLogger(logger_name)
            for handler in target.handlers:
                existing = next(
                    (f for f in handler.filters if isinstance(f, _NonWhitelistFilter)),
                    None,
                )
                if existing is not None:
                    self._filter = existing  # hot-reload: reuse to preserve _blocking state
                else:
                    handler.addFilter(self._filter)
                    count += 1
        logger.info(f"[日志过滤器] filter 已安装到 {count} 个 handler")

    def _remove_filter(self) -> None:
        for logger_name in (None, "astrbot"):
            target = logging.getLogger() if logger_name is None else logging.getLogger(logger_name)
            for handler in target.handlers:
                handler.filters = [
                    f for f in handler.filters if not isinstance(f, _NonWhitelistFilter)
                ]

    # ------------------------------------------------------------------
    # whitelist sync
    # ------------------------------------------------------------------

    def _reload_lists(self) -> None:
        try:
            cfg = self.context.get_config()
            platform_whitelist: list = (
                cfg.get("platform_settings", {})
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
        logger.info(f"[日志过滤器] 白名单已同步: {sorted(self._filter.platform_whitelist)}")

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