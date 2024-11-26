import asyncio
import logging
import os
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from functools import lru_cache
from io import StringIO
from logging.handlers import RotatingFileHandler
from typing import Any, FrozenSet, List, NamedTuple, Optional, Union

import interactions
import orjson
from interactions.api.events import RoleUpdate
from interactions.client.errors import Forbidden, NotFound
from interactions.ext.paginators import Paginator

BASE_DIR: str = os.path.dirname(os.path.abspath(__file__))
LOG_FILE: str = os.path.join(BASE_DIR, "permissions.log")

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    "%(asctime)s | %(process)d:%(thread)d | %(levelname)-8s | %(name)s:%(funcName)s:%(lineno)d - %(message)s",
    "%Y-%m-%d %H:%M:%S.%f %z",
)
file_handler = RotatingFileHandler(
    LOG_FILE, maxBytes=1024 * 1024, backupCount=1, encoding="utf-8"
)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)


# Models


class PermissionTemplate(NamedTuple):
    name: str
    description: str
    permissions: int
    duration: Optional[timedelta] = None


class PermissionChange(NamedTuple):
    role_id: int
    old_permissions: int
    new_permissions: int
    changed_by: int
    timestamp: datetime
    reason: str

    @property
    def permission_delta(self) -> int:
        return self.old_permissions ^ self.new_permissions


@lru_cache(maxsize=None)
def risk_level_value(level: "RiskLevel") -> int:
    return level.value


class RiskLevel(Enum):
    __slots__ = ()
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFO = auto()

    def __lt__(self, other: "RiskLevel") -> bool:
        return risk_level_value(self) < risk_level_value(other)


@dataclass(frozen=True, slots=True)
class PermissionRisk:
    level: RiskLevel
    description: str = ""
    mitigation: str = ""
    affected_permissions: FrozenSet[int] = frozenset()

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "affected_permissions", frozenset(self.affected_permissions)
        )


class EmbedColor(Enum):
    __slots__ = ()
    OFF = 0x5D5A58
    FATAL = 0xFF4343
    ERROR = 0xE81123
    WARN = 0xFFB900
    INFO = 0x0078D7
    DEBUG = 0x00B7C3
    TRACE = 0x8E8CD8
    ALL = 0x0063B1

    @property
    def rgb(self) -> tuple[int, int, int]:
        return self.value >> 16 & 0xFF, self.value >> 8 & 0xFF, self.value & 0xFF


@dataclass(slots=True)
class PermissionChangeLog:
    timestamp: datetime
    role_id: int
    old_perms: int
    new_perms: int
    changed_by: int
    reason: str
    channel_id: Optional[int] = None

    def format_embed(self) -> interactions.Embed:
        added = self.new_perms & ~self.old_perms
        removed = self.old_perms & ~self.new_perms
        return interactions.Embed(
            title="Permission Change",
            description=f"Role <@&{self.role_id}> permissions updated",
            fields=[
                interactions.EmbedField(
                    name="Changed By", value=f"<@{self.changed_by}>"
                ),
                interactions.EmbedField(name="Reason", value=self.reason),
                interactions.EmbedField(
                    name="Added Permissions",
                    value="\n".join(permission_value_to_names(added)),
                ),
                interactions.EmbedField(
                    name="Removed Permissions",
                    value="\n".join(permission_value_to_names(removed)),
                ),
            ],
            timestamp=self.timestamp,
        )


@dataclass(slots=True)
class TemporaryPermission:
    role_id: int
    old_permissions: int
    expiry: datetime
    reason: str
    granted_by: int

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) >= self.expiry


@dataclass(frozen=True, slots=True)
class RoleLevel:
    position: int
    roles: tuple[interactions.Role, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "roles",
            tuple(sorted(self.roles, key=lambda r: r.position, reverse=True)),
        )


# Controller


def permission_value_to_names(permission_value: int) -> List[str]:
    return [
        p.name.translate({95: 32}).title()
        for p in interactions.Permissions
        if permission_value & p.value
    ]


class Permissions(interactions.Extension):
    def __init__(self, bot: interactions.Client) -> None:
        self.bot: interactions.Client = bot
        self.role_hierarchy: dict[int, RoleLevel] = {}
        self.channel_overwrites: dict[
            int, dict[int, interactions.PermissionOverwrite]
        ] = {}
        self.guild: Optional[interactions.Guild] = None
        self.log_channel_id: int = 1166627731916734504
        self.log_forum_id: int = 1159097493875871784
        self.log_post_id: int = 1279118293936111707
        self.guild_id: int = 1150630510696075404

        self.permission_templates = {
            k: PermissionTemplate(k, d, sum(p.value for p in perms))
            for k, d, perms in (
                (
                    "basic",
                    "Basic member permissions",
                    (
                        interactions.Permissions.VIEW_CHANNEL,
                        interactions.Permissions.SEND_MESSAGES,
                        interactions.Permissions.READ_MESSAGE_HISTORY,
                        interactions.Permissions.CONNECT,
                        interactions.Permissions.SPEAK,
                    ),
                ),
                (
                    "moderator",
                    "Essential moderation permissions",
                    (
                        interactions.Permissions.KICK_MEMBERS,
                        interactions.Permissions.BAN_MEMBERS,
                        interactions.Permissions.MANAGE_MESSAGES,
                        interactions.Permissions.MUTE_MEMBERS,
                        interactions.Permissions.MOVE_MEMBERS,
                    ),
                ),
                (
                    "admin_lite",
                    "Limited administrative permissions",
                    (
                        interactions.Permissions.MANAGE_CHANNELS,
                        interactions.Permissions.MANAGE_THREADS,
                        interactions.Permissions.MANAGE_MESSAGES,
                        interactions.Permissions.MANAGE_NICKNAMES,
                        interactions.Permissions.VIEW_AUDIT_LOG,
                    ),
                ),
                (
                    "channel_mod",
                    "Channel moderation permissions",
                    (
                        interactions.Permissions.MANAGE_MESSAGES,
                        interactions.Permissions.MANAGE_THREADS,
                        interactions.Permissions.VIEW_CHANNEL,
                        interactions.Permissions.SEND_MESSAGES,
                    ),
                ),
            )
        }
        self.permission_history: defaultdict[Any, list] = defaultdict(list)
        self.temp_permissions: dict[Any, Any] = {}

    DANGEROUS_COMBINATIONS = {
        frozenset({interactions.Permissions.ADMINISTRATOR.value}): PermissionRisk(
            RiskLevel.CRITICAL,
            "Administrator permission grants full access",
            "Remove administrator permission and grant specific permissions instead",
            frozenset({interactions.Permissions.ADMINISTRATOR.value}),
        ),
        frozenset(
            {
                interactions.Permissions.MANAGE_GUILD.value,
                interactions.Permissions.MANAGE_ROLES.value,
            }
        ): PermissionRisk(
            RiskLevel.HIGH,
            "Dangerous combination of guild and role management",
            "Split these permissions across different roles",
            frozenset(
                {
                    interactions.Permissions.MANAGE_GUILD.value,
                    interactions.Permissions.MANAGE_ROLES.value,
                }
            ),
        ),
    }

    MFA_REQUIRED_PERMISSIONS = frozenset(
        p.value
        for p in (
            interactions.Permissions.KICK_MEMBERS,
            interactions.Permissions.BAN_MEMBERS,
            interactions.Permissions.ADMINISTRATOR,
            interactions.Permissions.MANAGE_CHANNELS,
            interactions.Permissions.MANAGE_GUILD,
            interactions.Permissions.MANAGE_MESSAGES,
            interactions.Permissions.MANAGE_ROLES,
            interactions.Permissions.MANAGE_WEBHOOKS,
            interactions.Permissions.MANAGE_EMOJIS_AND_STICKERS,
        )
    )

    # Checks

    async def check_forum_settings(self) -> List[PermissionRisk]:
        return (
            []
            if not self.guild
            else [
                PermissionRisk(
                    RiskLevel.LOW,
                    f"Forum channel {c.name} allows everyone to create threads",
                    "Consider restricting thread creation to specific roles",
                    frozenset({interactions.Permissions.CREATE_POSTS.value}),
                )
                for c in filter(
                    lambda ch: ch.type == interactions.ChannelType.GUILD_FORUM,
                    self.guild.channels,
                )
                if any(
                    o.allow & interactions.Permissions.CREATE_POSTS.value
                    for o in c.permission_overwrites
                    if o.id == self.guild.id
                )
            ]
        )

    async def check_category_inheritance(self) -> List[PermissionRisk]:
        return (
            []
            if not self.guild
            else [
                PermissionRisk(
                    RiskLevel.LOW,
                    f"Channel `{channel.name}` has different permissions from its category",
                    "Consider using category permissions for consistency",
                    frozenset({cat_overwrite.allow, chan_overwrite.allow}),
                )
                for category in filter(
                    lambda c: isinstance(c, interactions.GuildCategory),
                    self.guild.channels,
                )
                for channel in category.channels
                for role_id, cat_overwrite in dict(
                    (o.id, o) for o in category.permission_overwrites
                ).items()
                if (
                    chan_overwrite := dict(
                        (o.id, o) for o in channel.permission_overwrites
                    ).get(role_id)
                )
                and (
                    cat_overwrite.allow != chan_overwrite.allow
                    or cat_overwrite.deny != chan_overwrite.deny
                )
            ]
        )

    async def check_role_hierarchy(self) -> List[PermissionRisk]:
        if not self.guild:
            return []
        roles = sorted(self.guild.roles, key=lambda r: r.position, reverse=True)
        admin_roles = [
            r
            for r in roles
            if r.permissions.value & interactions.Permissions.ADMINISTRATOR.value
        ]
        return [
            *(
                [
                    PermissionRisk(
                        RiskLevel.HIGH,
                        "Administrator roles should be at the top of the hierarchy",
                        "Move administrator roles above all non-administrator roles",
                        frozenset({interactions.Permissions.ADMINISTRATOR.value}),
                    )
                ]
                if admin_roles
                and any(
                    r
                    for r in roles
                    if r.position > admin_roles[0].position
                    and not (
                        r.permissions.value
                        & interactions.Permissions.ADMINISTRATOR.value
                    )
                )
                else []
            ),
            *(
                PermissionRisk(
                    RiskLevel.LOW,
                    f"Role {lower_role.name} has redundant permissions from {role.name}",
                    "Consider removing redundant permissions from lower roles",
                    frozenset({role.permissions.value & lower_role.permissions.value}),
                )
                for i, role in enumerate(roles)
                for lower_role in roles[i + 1 :]
                if (role.permissions.value & lower_role.permissions.value)
                == role.permissions.value
            ),
        ]

    async def check_category_sync(self) -> List[PermissionRisk]:
        return (
            []
            if not self.guild
            else [
                PermissionRisk(
                    RiskLevel.LOW,
                    f"Channel {channel.name} permissions not synced with category {category.name}",
                    "Consider syncing permissions with category for easier management",
                    frozenset(),
                )
                for category in filter(
                    lambda c: isinstance(c, interactions.GuildCategory),
                    self.guild.channels,
                )
                for channel in category.channels
                if not channel.permission_synced
            ]
        )

    async def check_channel_optimizations(self) -> List[PermissionRisk]:
        if not self.guild:
            return []
        return [
            *(
                PermissionRisk(
                    RiskLevel.LOW,
                    f"Announcement channel {channel.name} allows regular messages",
                    "Consider restricting to SEND_MESSAGES to specific roles only",
                    frozenset({interactions.Permissions.SEND_MESSAGES.value}),
                )
                for channel in filter(
                    lambda c: c.type == interactions.ChannelType.GUILD_NEWS,
                    self.guild.channels,
                )
                if any(
                    o.allow & interactions.Permissions.SEND_MESSAGES.value
                    for o in channel.permission_overwrites
                )
            ),
            *(
                PermissionRisk(
                    RiskLevel.INFO,
                    f"Channel {channel.name} has no permission overwrites",
                    "Consider setting explicit permissions for better access control",
                    frozenset(),
                )
                for channel in filter(
                    lambda c: not c.permission_overwrites, self.guild.channels
                )
            ),
        ]

    async def check_dangerous_permissions(self) -> List[PermissionRisk]:
        if not self.guild:
            return []
        return [
            *(
                PermissionRisk(
                    risk.level,
                    f"Role `{role.name}` - {risk.description}",
                    risk.mitigation,
                    risk.affected_permissions,
                )
                for role in self.guild.roles
                for dangerous_combo, risk in self.DANGEROUS_COMBINATIONS.items()
                if all(
                    perm & role.permissions.value == perm for perm in dangerous_combo
                )
            ),
            *(
                PermissionRisk(
                    RiskLevel.HIGH,
                    f"Role `{role.name}` includes permissions that require two-factor authentication.",
                    f"Enable two-factor authentication for users with the following permissions: {', '.join(name for perm in mfa_perms if (mfa_perms := {p for p in self.MFA_REQUIRED_PERMISSIONS if role.permissions.value & p == p}) for name in permission_value_to_names(perm))}",
                    frozenset(mfa_perms),
                )
                for role in self.guild.roles
                if (
                    mfa_perms := {
                        p
                        for p in self.MFA_REQUIRED_PERMISSIONS
                        if role.permissions.value & p == p
                    }
                )
            ),
        ]

    async def update_role_hierarchy(self) -> None:
        if self.guild:
            self.role_hierarchy = {
                pos: RoleLevel(
                    pos, tuple(r for r in self.guild.roles if r.position == pos)
                )
                for pos in {r.position for r in self.guild.roles}
            }

    async def check_channel_overwrites(self) -> List[PermissionRisk]:
        if not self.guild:
            return []
        channels = tuple(
            filter(lambda c: hasattr(c, "permission_overwrites"), self.guild.channels)
        )
        self.channel_overwrites.update(
            {c.id: {o.id: o for o in c.permission_overwrites} for c in channels}
        )
        return [
            *(
                PermissionRisk(
                    RiskLevel.CRITICAL,
                    f"Channel `{c.name}` has <&1150630510696075404> admin permissions",
                    "Remove administrator permission from <&1150630510696075404>",
                    frozenset({interactions.Permissions.ADMINISTRATOR.value}),
                )
                for c in channels
                if (o := self.channel_overwrites[c.id].get(self.guild.id))
                and interactions.Permissions.ADMINISTRATOR.value & o.allow
            ),
            *(
                PermissionRisk(
                    RiskLevel.LOW,
                    f"Channel `{c.name}` has redundant overwrites",
                    f"Remove redundant permissions: {', '.join(permission_value_to_names(overlap))}",
                    frozenset({overlap}),
                )
                for c in channels
                for o in c.permission_overwrites
                if (r := self.guild.get_role(o.id))
                and (overlap := r.permissions.value & o.allow)
            ),
        ]

    @property
    @lru_cache()
    def dangerous_permission_combinations(self) -> dict[int, PermissionRisk]:
        return {p: r for perms, r in self.DANGEROUS_COMBINATIONS.items() for p in perms}

    async def check_special_channels(self) -> List[PermissionRisk]:
        if not self.guild:
            return []
        return [
            *(
                PermissionRisk(
                    RiskLevel.LOW,
                    f"Announcement channel {channel.name} allows regular messages",
                    "Consider restricting to announcements only",
                    frozenset({interactions.Permissions.SEND_MESSAGES.value}),
                )
                for channel in filter(
                    lambda c: c.type == interactions.ChannelType.GUILD_NEWS.value,
                    self.guild.channels,
                )
                if any(
                    o.allow & interactions.Permissions.SEND_MESSAGES.value
                    for o in channel.permission_overwrites
                )
            ),
            *(
                PermissionRisk(
                    RiskLevel.LOW,
                    f"Forum channel {channel.name} allows regular messages",
                    "Consider restricting to forum posts only",
                    frozenset({interactions.Permissions.SEND_MESSAGES.value}),
                )
                for channel in filter(
                    lambda c: c.type == interactions.ChannelType.GUILD_FORUM.value,
                    self.guild.channels,
                )
                if any(
                    o.allow & interactions.Permissions.SEND_MESSAGES.value
                    for o in channel.permission_overwrites
                )
            ),
        ]

    async def check_permission_inheritance(self) -> List[PermissionRisk]:
        return (
            []
            if not self.guild
            else [
                PermissionRisk(
                    RiskLevel.LOW,
                    f"Channel `{child.name}` has redundant permissions",
                    "Remove redundant permission overwrites from child channel",
                    frozenset({cat_overwrite.allow}),
                )
                for channel in filter(
                    lambda c: isinstance(c, interactions.GuildCategory),
                    self.guild.channels,
                )
                for child in channel.channels
                for overwrite_id, cat_overwrite in self.channel_overwrites.get(
                    channel.id, {}
                ).items()
                if (child_overwrites := self.channel_overwrites.get(child.id, {}))
                and overwrite_id in child_overwrites
                and cat_overwrite.allow == child_overwrites[overwrite_id].allow
                and cat_overwrite.deny == child_overwrites[overwrite_id].deny
            ]
        )

    # Views

    @staticmethod
    async def create_embed(
        title: str, description: str = "", color: EmbedColor = EmbedColor.INFO
    ) -> interactions.Embed:
        return interactions.Embed(
            title=title,
            description=description,
            color=color.value,
            timestamp=datetime.now(timezone.utc),
            footer={"text": "鍵政大舞台"},
        )

    @lru_cache(maxsize=1)
    def _get_log_channels(self) -> tuple[int, int, int]:
        return self.log_channel_id, self.log_post_id, self.log_forum_id

    async def send_response(
        self,
        ctx: Optional[
            Union[
                interactions.SlashContext,
                interactions.InteractionContext,
                interactions.ComponentContext,
            ]
        ],
        title: str,
        message: str,
        color: EmbedColor,
        should_log: bool = True,
    ) -> None:
        embed = await self.create_embed(title, message, color)
        if ctx:
            await ctx.send(embed=embed, ephemeral=True)
        if should_log:
            log_ch, log_post, log_forum = self._get_log_channels()
            await self.send_to_text_channel(log_ch, embed)
            await self.send_to_forum_post(log_forum, log_post, embed)

    async def send_to_text_channel(
        self, channel_id: int, embed: interactions.Embed
    ) -> None:
        try:
            if not isinstance(
                channel := await self.bot.fetch_channel(channel_id),
                interactions.GuildText,
            ):
                raise TypeError(f"Channel ID {channel_id} is not a valid text channel.")
            await channel.send(embed=embed)
        except NotFound as nf:
            logger.error(f"Channel with ID {channel_id} not found: {nf!r}")
        except Exception as e:
            logger.error(f"Error sending message to channel {channel_id}: {e!r}")

    async def send_to_forum_post(
        self, forum_id: int, post_id: int, embed: interactions.Embed
    ) -> None:
        try:
            if not isinstance(
                forum := await self.bot.fetch_channel(forum_id), interactions.GuildForum
            ):
                raise TypeError(f"Channel ID {forum_id} is not a valid forum channel.")
            if not isinstance(
                thread := await forum.fetch_post(post_id),
                interactions.GuildPublicThread,
            ):
                raise TypeError(f"Post with ID {post_id} is not a valid thread.")
            await thread.send(embed=embed)
        except NotFound:
            logger.error(f"{forum_id=}, {post_id=} - Forum or post not found")
        except Exception as e:
            logger.error(f"Forum post error [{forum_id=}, {post_id=}]: {e!r}")

    async def send_error(
        self,
        ctx: Optional[
            Union[
                interactions.SlashContext,
                interactions.InteractionContext,
                interactions.ComponentContext,
            ]
        ],
        message: str,
        should_log: bool = False,
    ) -> None:
        await self.send_response(ctx, "Error", message, EmbedColor.ERROR, should_log)

    async def send_success(
        self,
        ctx: Optional[
            Union[
                interactions.SlashContext,
                interactions.InteractionContext,
                interactions.ComponentContext,
            ]
        ],
        message: str,
        should_log: bool = True,
    ) -> None:
        await self.send_response(ctx, "Success", message, EmbedColor.INFO, should_log)

    # Commands

    module_base = interactions.SlashCommand(
        name="permissions", description="Permissions commands"
    )

    @module_base.subcommand(
        "disable", sub_cmd_description="Disable a specific permission for all roles"
    )
    @interactions.slash_option(
        name="type",
        description="The type of permission to disable",
        required=True,
        opt_type=interactions.OptionType.STRING,
        choices=[
            interactions.SlashCommandChoice(name=k, value=v)
            for k, v in {
                "General": "general",
                "Text": "text",
                "Voice": "voice",
                "Advanced": "advanced",
            }.items()
        ],
        argument_name="permission_type",
    )
    @interactions.slash_option(
        name="general",
        description="General server permissions",
        opt_type=interactions.OptionType.STRING,
        choices=[
            interactions.SlashCommandChoice(name=k, value=str(v))
            for k, v in {
                "Administrator": 8,
                "View Audit Log": 128,
                "Manage Server": 32,
                "Manage Roles": 268435456,
                "Manage Channels": 16,
                "Manage Guild": 32,
                "View Guild Insights": 524288,
                "Manage Events": 8589934592,
                "Create Guild Expressions": 8796093022208,
                "View Creator Analytics": 2199023255552,
            }.items()
        ],
        argument_name="general_perms",
    )
    @interactions.slash_option(
        name="text",
        description="Text channel permissions",
        opt_type=interactions.OptionType.STRING,
        choices=[
            interactions.SlashCommandChoice(name=k, value=str(v))
            for k, v in {
                "View Channel": 1024,
                "Send Messages": 2048,
                "Create Posts": 2048,
                "Send TTS Messages": 4096,
                "Manage Messages": 8192,
                "Embed Links": 16384,
                "Attach Files": 32768,
                "Read Message History": 65536,
                "Mention Everyone": 131072,
                "Use External Emojis": 262144,
                "Add Reactions": 64,
                "Use External Stickers": 137438953472,
                "Create Public Threads": 34359738368,
                "Create Private Threads": 68719476736,
                "Send Messages In Threads": 274877906944,
                "Send Voice Messages": 70368744177664,
                "Send Polls": 562949953421312,
            }.items()
        ],
        argument_name="text_perms",
    )
    @interactions.slash_option(
        name="voice",
        description="Voice channel permissions",
        opt_type=interactions.OptionType.STRING,
        choices=[
            interactions.SlashCommandChoice(name=k, value=str(v))
            for k, v in {
                "Connect": 1048576,
                "Speak": 2097152,
                "Stream": 512,
                "Use VAD": 33554432,
                "Priority Speaker": 256,
                "Mute Members": 4194304,
                "Deafen Members": 8388608,
                "Move Members": 16777216,
                "Request To Speak": 4294967296,
                "Start Activities": 549755813888,
                "Use Soundboard": 4398046511104,
                "Use External Sounds": 35184372088832,
            }.items()
        ],
        argument_name="voice_perms",
    )
    @interactions.slash_option(
        name="perms",
        description="Advanced permissions",
        opt_type=interactions.OptionType.STRING,
        choices=[
            interactions.SlashCommandChoice(name=k, value=str(v))
            for k, v in {
                "Create Instant Invite": 1,
                "Kick Members": 2,
                "Ban Members": 4,
                "Change Nickname": 67108864,
                "Manage Nicknames": 134217728,
                "Manage Webhooks": 536870912,
                "Manage Emojis And Stickers": 1073741824,
                "Use Application Commands": 2147483648,
                "Manage Threads": 17179869184,
                "Moderate Members": 1099511627776,
            }.items()
        ],
        argument_name="advanced_perms",
    )
    @interactions.slash_option(
        name="ignore",
        description="Whether to ignore roles with administrator permission",
        opt_type=interactions.OptionType.BOOLEAN,
        argument_name="ignore_admin",
    )
    @interactions.slash_default_member_permission(
        interactions.Permissions.ADMINISTRATOR
    )
    @interactions.max_concurrency(interactions.Buckets.GUILD, 1)
    async def disable_permission(
        self,
        ctx: interactions.SlashContext,
        permission_type: str,
        general_perms: Optional[str] = None,
        text_perms: Optional[str] = None,
        voice_perms: Optional[str] = None,
        advanced_perms: Optional[str] = None,
        ignore_admin: bool = True,
    ) -> None:
        if not (
            ctx.guild
            and ctx.author.guild_permissions & interactions.Permissions.ADMINISTRATOR
        ):
            await self.send_error(
                ctx,
                f"Cannot disable permissions: {'no guild context' if not ctx.guild else 'You need Administrator permission'}",
            )
            return

        permission = None
        if permission_type == "general" and general_perms:
            permission = general_perms
        elif permission_type == "text" and text_perms:
            permission = text_perms
        elif permission_type == "voice" and voice_perms:
            permission = voice_perms
        elif permission_type == "advanced" and advanced_perms:
            permission = advanced_perms

        if not permission:
            await self.send_error(
                ctx,
                f"No permission selected for type: {permission_type}",
            )
            return

        try:
            permission_value = int(permission)
            affected_roles: list[str] = []
            skipped_roles: list[str] = []
            failed_roles: list[str] = []

            roles = (
                role
                for role in ctx.guild.roles
                if not (
                    ignore_admin
                    and role.permissions & interactions.Permissions.ADMINISTRATOR
                )
            )

            for role in roles:
                if not role.permissions.value & permission_value:
                    continue

                try:
                    new_permissions = role.permissions.value & ~permission_value
                    await role.edit(permissions=new_permissions)
                    affected_roles.append(role.name)

                    self.permission_history[role.id].append(
                        PermissionChange(
                            role_id=role.id,
                            old_permissions=role.permissions.value,
                            new_permissions=new_permissions,
                            changed_by=ctx.author.id,
                            timestamp=datetime.now(timezone.utc),
                            reason=f"Bulk permission disable: {permission_value_to_names(permission_value)}",
                        )
                    )
                except Forbidden:
                    failed_roles.append(role.name)
                    logger.warning(f"Missing permissions to modify role: {role.name}")
                    continue
                except Exception as e:
                    logger.error(f"Failed to update role {role.name}: {e}")
                    failed_roles.append(role.name)
                    continue

            response_parts = [
                (
                    f"Disabled permission for roles: {', '.join(affected_roles)}"
                    if affected_roles
                    else None
                ),
                (
                    f"Skipped administrator roles: {', '.join(skipped_roles)}"
                    if skipped_roles and ignore_admin
                    else None
                ),
                (
                    f"Failed to modify roles (insufficient permissions): {', '.join(failed_roles)}"
                    if failed_roles
                    else None
                ),
                (
                    "No roles were affected"
                    if not (affected_roles or skipped_roles or failed_roles)
                    else None
                ),
            ]

            await self.send_success(ctx, "\n".join(filter(None, response_parts)))

        except ValueError:
            await self.send_error(ctx, f"Invalid permission value: {permission}")
        except Exception as e:
            await self.send_error(ctx, f"An error occurred: {str(e)}")

    @module_base.subcommand(
        "template", sub_cmd_description="Apply a permission template"
    )
    @interactions.slash_option(
        name="role",
        description="The role to apply the template to",
        required=True,
        opt_type=interactions.OptionType.ROLE,
    )
    @interactions.slash_option(
        name="template",
        description="The template to apply",
        required=True,
        opt_type=interactions.OptionType.STRING,
        choices=[
            interactions.SlashCommandChoice(name=n, value=v)
            for n, v in (("Moderator", "moderator"), ("Admin", "admin"))
        ],
    )
    @interactions.slash_option(
        name="duration",
        description="Duration in minutes (temporary)",
        opt_type=interactions.OptionType.INTEGER,
        min_value=1,
        max_value=1440,
    )
    async def apply_template_command(
        self,
        ctx: interactions.SlashContext,
        role: interactions.Role,
        template: str,
        duration: Optional[int] = None,
    ) -> None:
        if not ctx.author.guild_permissions & interactions.Permissions.ADMINISTRATOR:
            await self.send_error(
                ctx, "You need Administrator permission to use this command"
            )
            return
        await self.apply_permission_template(ctx, role, template, duration)

    @module_base.subcommand(
        "rollback", sub_cmd_description="Rollback permission changes"
    )
    @interactions.slash_option(
        name="role",
        description="The role to rollback changes for",
        required=True,
        opt_type=interactions.OptionType.ROLE,
    )
    @interactions.slash_option(
        name="steps",
        description="Number of changes to rollback",
        required=True,
        opt_type=interactions.OptionType.INTEGER,
        min_value=1,
        max_value=10,
    )
    async def rollback_command(
        self, ctx: interactions.SlashContext, role: interactions.Role, steps: int = 1
    ) -> None:
        if not ctx.author.guild_permissions & interactions.Permissions.ADMINISTRATOR:
            await self.send_error(
                ctx, "You need Administrator permission to use this command"
            )
            return
        await self.rollback_permission_changes(ctx, role, steps)

    @module_base.subcommand("audit", sub_cmd_description="Audit server permissions")
    @interactions.slash_option(
        name="scope",
        description="Audit scope",
        required=True,
        opt_type=interactions.OptionType.STRING,
        choices=[
            interactions.SlashCommandChoice(name=n, value=v)
            for n, v in (
                ("All", "all"),
                ("Hierarchy", "hierarchy"),
                ("Channels", "channels"),
                ("Overwrites", "overwrites"),
                ("Inheritance", "inheritance"),
                ("Dangerous", "dangerous"),
                ("Special", "special"),
                ("Category Sync", "sync"),
            )
        ],
    )
    async def audit_permissions(
        self, ctx: interactions.SlashContext, scope: str = "all"
    ) -> None:
        if not (
            ctx.author.guild_permissions.value
            & interactions.Permissions.ADMINISTRATOR.value
        ):
            await self.send_error(
                ctx,
                "Administrator permissions are required to perform a permissions audit.",
            )
            return

        await ctx.defer()

        if not (guild := ctx.guild):
            await self.send_error(ctx, "Cannot audit permissions: no guild context")
            return

        self.guild = guild
        await self.update_role_hierarchy()

        risk_functions = {
            name: getattr(self, f"check_{name}")
            for name in (
                "dangerous_permissions",
                "channel_overwrites",
                "permission_inheritance",
                "forum_settings",
                "role_hierarchy",
                "category_inheritance",
                "special_channels",
                "channel_optimizations",
                "category_sync",
            )
        }

        if scope != "all" and scope not in risk_functions:
            await self.send_error(ctx, f"Invalid audit scope: {scope}")
            return

        try:
            risks = [
                risk
                for func in (
                    risk_functions.values()
                    if scope == "all"
                    else [risk_functions[scope]]
                )
                for risk in await func()
            ]
        except Exception as e:
            await self.send_error(ctx, f"Error during audit: {str(e)}")
            return

        risks_by_level = {
            level: [r for r in risks if r.level == level] for level in RiskLevel
        }
        color_map = dict(
            zip(
                RiskLevel,
                (
                    EmbedColor.FATAL,
                    EmbedColor.ERROR,
                    EmbedColor.WARN,
                    EmbedColor.INFO,
                    EmbedColor.INFO,
                ),
            )
        )

        FIELDS_PER_EMBED = 25
        embeds = []
        for level, level_risks in ((l, r) for l, r in risks_by_level.items() if r):
            for i in range(0, len(level_risks), FIELDS_PER_EMBED):
                page_risks = level_risks[i : i + FIELDS_PER_EMBED]
                current_embed = await self.create_embed(
                    title=f"{level.name} Level Risks ({len(level_risks)})"
                    + (
                        f" (Page {i//FIELDS_PER_EMBED + 1})"
                        if len(level_risks) > FIELDS_PER_EMBED
                        else ""
                    ),
                    color=color_map[level],
                )

                for risk in page_risks:
                    description = risk.description[:256] or "No description"
                    mitigation = risk.mitigation[:1024] or "No mitigation steps"
                    affected_perms = (
                        ", ".join(
                            permission_value_to_names(sum(risk.affected_permissions))
                        )[:1024]
                        if risk.affected_permissions
                        else "None"
                    )

                    current_embed.add_field(
                        name=description,
                        value=(
                            f"**Recommended Action:**\n{mitigation}\n"
                            f"**Affected Permissions:**\n{affected_perms}"
                        ),
                    )

                embeds.append(current_embed)

        try:
            if risks and (fix_results := await self.apply_fixes(ctx, risks)):
                await self.send_success(
                    ctx, "Automatic fixes applied:\n- " + "\n- ".join(fix_results)
                )

            if embeds:
                await Paginator.create_from_embeds(self.bot, *embeds, timeout=300).send(
                    ctx
                )
            else:
                await self.send_success(
                    ctx, "No permission risks found.", should_log=False
                )
        except Exception as e:
            await self.send_error(ctx, f"Error sending audit results: {str(e)}")

    @module_base.subcommand(
        "export", sub_cmd_description="Export all permission settings"
    )
    async def export_permissions(self, ctx: interactions.SlashContext) -> None:
        if (
            not ctx.author.guild_permissions.value
            & interactions.Permissions.ADMINISTRATOR.value
        ):
            await self.send_error(
                ctx, "Administrator permissions are required to export permissions."
            )
            return

        await ctx.defer()

        if not (guild := ctx.guild):
            await self.send_error(ctx, "Cannot export permissions: no guild context")
            return

        export_data = {
            "guild_name": guild.name,
            "guild_id": guild.id,
            "export_time": datetime.now(timezone.utc).isoformat(),
            "roles": [
                {
                    "name": role.name,
                    "id": role.id,
                    "position": role.position,
                    "color": f"#{role.color.value:06x}" if role.color else None,
                    "permissions": {
                        "raw_value": role.permissions.value,
                        "allowed": permission_value_to_names(role.permissions.value),
                    },
                    "mentionable": role.mentionable,
                    "hoisted": role.hoist,
                }
                for role in sorted(guild.roles, key=lambda r: -r.position)
            ],
            "channels": [
                {
                    "name": channel.name,
                    "id": channel.id,
                    "type": str(channel.type),
                    "position": getattr(channel, "position", 0),
                    "category_id": getattr(channel, "parent_id", None),
                    **(
                        {
                            "permission_overwrites": [
                                {
                                    "id": overwrite.id,
                                    "type": "role" if overwrite.type == 0 else "member",
                                    "allow": {
                                        "raw_value": overwrite.allow,
                                        "permissions": permission_value_to_names(
                                            overwrite.allow
                                        ),
                                    },
                                    "deny": {
                                        "raw_value": overwrite.deny,
                                        "permissions": permission_value_to_names(
                                            overwrite.deny
                                        ),
                                    },
                                }
                                for overwrite in channel.permission_overwrites
                            ]
                        }
                        if hasattr(channel, "permission_overwrites")
                        else {}
                    ),
                }
                for channel in guild.channels
            ],
        }

        await self.send_success(
            ctx, "Successfully exported all permission settings.", should_log=False
        )
        await ctx.send(
            file=interactions.File(
                StringIO(
                    orjson.dumps(
                        export_data,
                        option=orjson.OPT_INDENT_2 | orjson.OPT_NON_STR_KEYS,
                    ).decode()
                ),
                file_name=f"{guild.name}_permissions_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}.json",
            ),
        )

    # Serve

    async def monitor_role_permission_changes(
        self,
        before: Union[interactions.Role, interactions.PermissionOverwrite],
        after: Union[interactions.Role, interactions.PermissionOverwrite],
    ) -> Optional[PermissionRisk]:
        if not all(isinstance(x, interactions.Role) for x in (before, after)):
            return None

        added_perms = after.permissions.value & ~before.permissions.value
        if not added_perms:
            return None

        return next(
            (
                PermissionRisk(
                    risk.level,
                    f"\n**Security Alert:** Role `{after.name}` received potentially dangerous permissions",
                    "".join(
                        (
                            f"**Added Permissions:**\n- {', '.join(permission_value_to_names(added_perms))}\n",
                            f"**High-Risk Permissions:**\n- {', '.join(permission_value_to_names(added_perms & perm))}\n",
                        )
                    ),
                    frozenset((added_perms & perm,)),
                )
                for perm, risk in self.dangerous_permission_combinations.items()
                if added_perms & perm
            ),
            None,
        )

    async def apply_fixes(
        self, ctx: interactions.SlashContext, risks: List[PermissionRisk]
    ) -> List[str]:
        if not self.guild:
            return ["No guild context available"]

        results = []
        role_cache = {role.name: role for role in self.guild.roles}
        admin_perm = interactions.Permissions.ADMINISTRATOR.value
        guild_perm = interactions.Permissions.MANAGE_GUILD.value
        dangerous_mask = guild_perm | interactions.Permissions.MANAGE_ROLES.value

        for risk in risks:
            try:
                desc = risk.description
                role_name = desc[
                    desc.find("`") + 1 : desc.find("`", desc.find("`") + 1)
                ]
                if not (role := role_cache.get(role_name)):
                    continue

                current_perms = role.permissions.value
                affected = risk.affected_permissions

                if admin_perm in affected:
                    await role.edit(permissions=str(current_perms & ~admin_perm))
                    results.append(
                        f"Removed administrator permission from role {role_name}"
                    )
                elif guild_perm in affected:
                    await role.edit(permissions=str(current_perms & ~dangerous_mask))
                    results.append(
                        f"Removed dangerous permission combination from role {role_name}"
                    )
            except Exception as e:
                error_msg = f"Failed to fix {risk.description}: {str(e)}"
                results.append(error_msg)
                logger.error(error_msg)

        return results

    async def rollback_permission_changes(
        self, ctx: interactions.SlashContext, role: interactions.Role, steps: int = 1
    ) -> None:
        try:
            history = self.permission_history.get(role.id, [])
            if not history or steps > len(history):
                await self.send_error(ctx, "No changes to rollback")
                return

            change = history[~(steps - 1)]
            current_perms = role.permissions.value
            target_perms = change.old_permissions

            await role.edit(permissions=target_perms)

            self.permission_history[role.id].append(
                PermissionChange(
                    role_id=role.id,
                    old_permissions=current_perms,
                    new_permissions=target_perms,
                    changed_by=ctx.author.id,
                    timestamp=datetime.now(timezone.utc),
                    reason=f"Rollback to {change.timestamp.isoformat()}",
                )
            )

            await self.send_success(
                ctx,
                "".join(
                    (
                        "Rolled back permissions for role ",
                        role.name,
                        " to ",
                        change.timestamp.isoformat(),
                    )
                ),
            )

        except Exception as e:
            await self.send_error(ctx, f"Failed to rollback changes: {str(e)}")

    async def apply_permission_template(
        self,
        ctx: interactions.SlashContext,
        role: interactions.Role,
        template_name: str,
        duration: Optional[int] = None,
    ) -> None:
        if not (template := self.permission_templates.get(template_name)):
            await self.send_error(ctx, f"Template `{template_name}` not found")
            return

        old_permissions = role.permissions.value
        new_permissions = template.permissions

        try:
            await role.edit(permissions=new_permissions)

            self.permission_history[role.id].append(
                PermissionChange(
                    role_id=role.id,
                    old_permissions=old_permissions,
                    new_permissions=new_permissions,
                    changed_by=ctx.author.id,
                    timestamp=datetime.now(timezone.utc),
                    reason=f"Applied template: {template_name}",
                )
            )

            if duration:
                expiry = datetime.now(timezone.utc) + timedelta(minutes=duration)
                self.temp_permissions.setdefault(role.id, []).append(
                    (old_permissions, expiry)
                )

            await self.send_success(
                ctx,
                f"Applied template `{template_name}` to role {role.name}"
                f"{' for ' + str(duration) + ' minutes' if duration else ''}",
            )

        except Exception as e:
            await self.send_error(ctx, f"Failed to apply template: {str(e)}")

    # Tasks

    def start_background_tasks(self) -> None:
        tuple(
            map(
                lambda c: asyncio.create_task(c()),
                (self.cleanup_expired_permissions, self.run_scheduled_permission_audit),
            )
        )

    async def cleanup_expired_permissions(self) -> None:
        while True:
            now = datetime.now(timezone.utc)
            expired = [
                (role_id, old_perms, expiry)
                for role_id, temp_perms in self.temp_permissions.items()
                for old_perms, expiry in temp_perms
                if now >= expiry
            ]

            if self.guild is not None:
                for role_id, old_perms, expiry in expired:
                    if role := self.guild.get_role(role_id):
                        await role.edit(permissions=old_perms)
                        self.temp_permissions[role_id] = [
                            x for x in self.temp_permissions[role_id] if x[1] != expiry
                        ]

                        self.permission_history[role_id].append(
                            PermissionChange(
                                role_id=role_id,
                                old_permissions=role.permissions.value,
                                new_permissions=old_perms,
                                changed_by=self.bot.user.id,
                                timestamp=now,
                                reason="Temporary permissions expired",
                            )
                        )

                        if not self.temp_permissions[role_id]:
                            self.temp_permissions.pop(role_id)

            await asyncio.sleep(60)

    async def run_scheduled_permission_audit(self) -> None:
        while True:
            if self.guild:
                risks = []
                for f in (
                    self.check_dangerous_permissions,
                    self.check_channel_overwrites,
                    self.check_permission_inheritance,
                ):
                    risks.extend(await f())

                if risks:
                    risk_messages = tuple(
                        f"**{risk.level.name}**\n{risk.description}\n{risk.mitigation}"
                        for risk in risks[:25]
                    )

                    await self.send_error(
                        None,
                        f"Automated Permission Audit Found {len(risks)} Issues:\n"
                        + "\n".join(risk_messages),
                        should_log=True,
                    )

            await asyncio.sleep(86400)

    @interactions.listen(RoleUpdate)
    async def on_role_update(self, event: RoleUpdate) -> None:
        if not event.after.guild:
            return

        self.guild = event.after.guild
        if risk := await self.monitor_role_permission_changes(
            event.before, event.after
        ):
            await self.send_error(
                None,
                f"Permission change warning `{risk.level.name}`: {risk.description}\n{risk.mitigation}",
                should_log=True,
            )
