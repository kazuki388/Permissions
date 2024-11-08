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
from interactions.client.errors import NotFound
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
def _risk_level_value(level: "RiskLevel") -> int:
    return level.value


class RiskLevel(Enum):
    __slots__ = ()
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFO = auto()

    def __lt__(self, other: "RiskLevel") -> bool:
        return _risk_level_value(self) < _risk_level_value(other)


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
        return (self.value >> 16 & 0xFF, self.value >> 8 & 0xFF, self.value & 0xFF)


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
                {"name": "Changed By", "value": f"<@{self.changed_by}>"},
                {"name": "Reason", "value": self.reason},
                {
                    "name": "Added Permissions",
                    "value": "\n".join(permission_value_to_names(added)),
                },
                {
                    "name": "Removed Permissions",
                    "value": "\n".join(permission_value_to_names(removed)),
                },
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
        self.channel_overwrites: dict[int, dict[int, interactions.Overwrite]] = {}
        self.guild: Optional[interactions.Guild] = None
        self.LOG_CHANNEL_ID: int = 1166627731916734504
        self.LOG_FORUM_ID: int = 1159097493875871784
        self.LOG_POST_ID: int = 1279118293936111707
        self.GUILD_ID: int = 1150630510696075404

        self.permission_templates = {
            "moderator": PermissionTemplate(
                "moderator",
                "Basic moderation permissions",
                sum(
                    p.value
                    for p in (
                        interactions.Permissions.KICK_MEMBERS,
                        interactions.Permissions.BAN_MEMBERS,
                        interactions.Permissions.MANAGE_MESSAGES,
                    )
                ),
            ),
            "admin": PermissionTemplate(
                "admin",
                "Administrative permissions (no ADMINISTRATOR)",
                sum(
                    p.value
                    for p in (
                        interactions.Permissions.MANAGE_GUILD,
                        interactions.Permissions.MANAGE_CHANNELS,
                        interactions.Permissions.MANAGE_ROLES,
                    )
                ),
            ),
        }

        self.permission_templates |= {
            "admin_lite": PermissionTemplate(
                "admin_lite",
                "Administrative permissions without critical ones",
                sum(
                    p.value
                    for p in (
                        interactions.Permissions.MANAGE_MESSAGES,
                        interactions.Permissions.MANAGE_THREADS,
                        interactions.Permissions.MANAGE_CHANNELS,
                        interactions.Permissions.MENTION_EVERYONE,
                    )
                ),
            ),
            "channel_mod": PermissionTemplate(
                "channel_mod",
                "Channel moderation permissions",
                sum(
                    p.value
                    for p in (
                        interactions.Permissions.MANAGE_MESSAGES,
                        interactions.Permissions.MANAGE_THREADS,
                        interactions.Permissions.VIEW_CHANNEL,
                        interactions.Permissions.SEND_MESSAGES,
                    )
                ),
            ),
        }
        self.permission_history: defaultdict[Any, list] = defaultdict(list)
        self.temp_permissions: dict[Any, Any] = {}
        self.permission_stats: defaultdict[Any, int] = defaultdict(int)

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

    async def check_forum_permissions(self) -> List[PermissionRisk]:
        return (
            []
            if not self.guild
            else [
                PermissionRisk(
                    RiskLevel.LOW,
                    f"Forum channel {channel.name} allows everyone to create threads",
                    "Consider restricting thread creation to specific roles",
                    frozenset({interactions.Permissions.CREATE_PUBLIC_THREADS.value}),
                )
                for channel in (
                    c
                    for c in self.guild.channels
                    if c.type == interactions.ChannelType.FORUM
                )
                if any(
                    o.allow & interactions.Permissions.CREATE_PUBLIC_THREADS.value
                    for o in channel.permission_overwrites
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
                for category in (
                    c
                    for c in self.guild.channels
                    if isinstance(c, interactions.GuildCategory)
                )
                for channel in category.channels
                for role_id, cat_overwrite in {
                    o.id: o for o in category.permission_overwrites
                }.items()
                if (
                    chan_overwrite := {
                        o.id: o for o in channel.permission_overwrites
                    }.get(role_id)
                )
                and (
                    cat_overwrite.allow != chan_overwrite.allow
                    or cat_overwrite.deny != chan_overwrite.deny
                )
            ]
        )

    async def validate_role_hierarchy(self) -> List[PermissionRisk]:
        return (
            []
            if not self.guild
            else [
                PermissionRisk(
                    RiskLevel.HIGH,
                    f"Role `{role.name}` with administrator permission has non-admin roles above it",
                    "Move administrator roles to the top of the hierarchy",
                    frozenset({interactions.Permissions.ADMINISTRATOR.value}),
                )
                for role in (r for r in self.guild.roles if r.permissions.administrator)
                if any(
                    not r.permissions.administrator
                    for r in self.guild.roles
                    if r.position > role.position
                )
            ]
        )

    async def check_dangerous_role_combinations(self) -> List[PermissionRisk]:
        if not self.guild:
            return []

        dangerous_risks = [
            PermissionRisk(
                risk.level,
                f"Role `{role.name}` - {risk.description}",
                risk.mitigation,
                risk.affected_permissions,
            )
            for role in self.guild.roles
            for dangerous_combo, risk in self.DANGEROUS_COMBINATIONS.items()
            if all(perm & role.permissions.value == perm for perm in dangerous_combo)
        ]

        mfa_risks = [
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
        ]

        return dangerous_risks + mfa_risks

    async def analyze_role_hierarchy(self) -> None:
        if self.guild:
            self.role_hierarchy = {
                pos: RoleLevel(
                    pos, tuple(r for r in self.guild.roles if r.position == pos)
                )
                for pos in {r.position for r in self.guild.roles}
            }

    async def analyze_channel_overwrites(self) -> List[PermissionRisk]:
        if not self.guild:
            return []

        channels = tuple(
            c for c in self.guild.channels if hasattr(c, "permission_overwrites")
        )
        self.channel_overwrites.update(
            {c.id: {o.id: o for o in c.permission_overwrites} for c in channels}
        )

        admin_risks = [
            PermissionRisk(
                RiskLevel.CRITICAL,
                f"Channel `{c.name}` has <&1150630510696075404> admin permissions",
                "Remove administrator permission from <&1150630510696075404>",
                frozenset({interactions.Permissions.ADMINISTRATOR.value}),
            )
            for c in channels
            if (o := self.channel_overwrites[c.id].get(self.guild.id))
            and interactions.Permissions.ADMINISTRATOR.value & o.allow
        ]

        redundant_risks = [
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
        ]

        return admin_risks + redundant_risks

    @property
    @lru_cache(maxsize=128)
    def dangerous_permission_masks(self) -> dict[int, PermissionRisk]:
        return {p: r for perms, r in self.DANGEROUS_COMBINATIONS.items() for p in perms}

    async def check_special_channel_permissions(self) -> List[PermissionRisk]:
        if not self.guild:
            return []

        announcement_risks = [
            PermissionRisk(
                RiskLevel.LOW,
                f"Announcement channel {channel.name} allows regular messages",
                "Consider restricting to announcements only",
                frozenset({interactions.Permissions.SEND_MESSAGES.value}),
            )
            for channel in (
                c
                for c in self.guild.channels
                if c.type == interactions.ChannelType.ANNOUNCEMENT.value
            )
            if any(
                o.allow & interactions.Permissions.SEND_MESSAGES.value
                for o in channel.permission_overwrites
            )
        ]

        forum_risks = [
            PermissionRisk(
                RiskLevel.LOW,
                f"Forum channel {channel.name} allows regular messages",
                "Consider restricting to forum posts only",
                frozenset({interactions.Permissions.SEND_MESSAGES.value}),
            )
            for channel in (
                c
                for c in self.guild.channels
                if c.type == interactions.ChannelType.FORUM.value
            )
            if any(
                o.allow & interactions.Permissions.SEND_MESSAGES.value
                for o in channel.permission_overwrites
            )
        ]

        return announcement_risks + forum_risks

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
                for channel in (
                    c
                    for c in self.guild.channels
                    if isinstance(c, interactions.GuildCategory)
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

    async def create_embed(
        self, title: str, description: str = "", color: EmbedColor = EmbedColor.INFO
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
        return self.LOG_CHANNEL_ID, self.LOG_POST_ID, self.LOG_FORUM_ID

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
        log_to_channel: bool = True,
    ) -> None:
        embed = await self.create_embed(title, message, color)
        if ctx:
            await ctx.send(embed=embed, ephemeral=True)
        if log_to_channel:
            log_ch, log_post, log_forum = self._get_log_channels()
            await self.send_to_channel(log_ch, embed)
            await self.send_to_forum_post(log_forum, log_post, embed)

    async def send_to_channel(self, channel_id: int, embed: interactions.Embed) -> None:
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
        log_to_channel: bool = False,
    ) -> None:
        await self.send_response(
            ctx, "Error", message, EmbedColor.ERROR, log_to_channel
        )

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
        log_to_channel: bool = True,
    ) -> None:
        await self.send_response(
            ctx, "Success", message, EmbedColor.INFO, log_to_channel
        )

    # Commands

    module_base = interactions.SlashCommand(
        name="permissions", description="Permissions commands"
    )

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
        required=False,
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
        await self.apply_template(ctx, role, template, duration)

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
        await self.rollback_changes(ctx, role, steps)

    @module_base.subcommand("audit", sub_cmd_description="Audit server permissions")
    @interactions.slash_option(
        name="field",
        description="The field to audit",
        required=True,
        opt_type=interactions.OptionType.STRING,
        choices=[
            interactions.SlashCommandChoice(name=n, value=v)
            for n, v in (
                ("Dangerous Combinations", "dangerous"),
                ("Channel Overwrites", "overwrites"),
                ("Permission Inheritance", "inheritance"),
            )
        ],
    )
    async def audit_permissions(
        self, ctx: interactions.SlashContext, field: Optional[str] = None
    ) -> None:
        if not (ctx.author.guild_permissions & interactions.Permissions.ADMINISTRATOR):
            await self.send_error(
                ctx,
                "Administrator permissions are required to perform a permissions audit.",
            )
            return

        await ctx.defer()
        self.guild = await self.bot.fetch_guild(self.GUILD_ID)

        risk_functions = {
            "dangerous": self.check_dangerous_role_combinations,
            "overwrites": self.analyze_channel_overwrites,
            "inheritance": self.check_permission_inheritance,
            "forum": self.check_forum_permissions,
            "hierarchy": self.validate_role_hierarchy,
            "categories": self.check_category_inheritance,
        }

        risks = [
            risk
            for func in ([risk_functions[field]] if field else risk_functions.values())
            for risk in await func()
        ]

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
                    current_embed.add_field(
                        name=risk.description[:256],
                        value=(
                            f"**Recommended Action:**\n{risk.mitigation[:1024]}\n"
                            f"**Affected Permissions:**\n"
                            f"{', '.join(permission_value_to_names(sum(risk.affected_permissions)))[:1024]}"
                        ),
                        inline=False,
                    )

                embeds.append(current_embed)

        if risks and (fix_results := await self.apply_fixes(ctx, risks)):
            await self.send_success(
                ctx, "Automatic fixes applied:\n- " + "\n- ".join(fix_results)
            )

        if embeds:
            await Paginator.create_from_embeds(self.bot, *embeds, timeout=300).send(ctx)
        else:
            await self.send_success(
                ctx, "No permission risks found.", log_to_channel=False
            )

    @module_base.subcommand(
        "export", sub_cmd_description="Export all permission settings"
    )
    async def export_permissions(self, ctx: interactions.SlashContext) -> None:
        if not ctx.author.guild_permissions & interactions.Permissions.ADMINISTRATOR:
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
            ctx, "Successfully exported all permission settings.", log_to_channel=False
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

    async def monitor_permission_changes(
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
                    f"\n**Security Alert:** Role `{after.name}` received potentially dangerous permissions\n",
                    "".join(
                        (
                            f"**Added Permissions:**\n- {', '.join(permission_value_to_names(added_perms))}\n",
                            f"**High-Risk Permissions:**\n- {', '.join(permission_value_to_names(added_perms & perm))}\n",
                        )
                    ),
                    frozenset((added_perms & perm,)),
                )
                for perm, risk in self.dangerous_permission_masks.items()
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

    async def rollback_changes(
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

    async def apply_template(
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
                (self.check_temp_permissions, self.periodic_audit),
            )
        )

    async def check_temp_permissions(self) -> None:
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

    async def periodic_audit(self) -> None:
        while True:
            if self.guild:
                risks = []
                for f in (
                    self.check_dangerous_role_combinations,
                    self.analyze_channel_overwrites,
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
                        log_to_channel=True,
                    )

            await asyncio.sleep(86400)

    @interactions.listen(RoleUpdate)
    async def on_role_update(self, event: RoleUpdate) -> None:
        if not event.after.guild:
            return

        self.guild = event.after.guild
        if risk := await self.monitor_permission_changes(event.before, event.after):
            await self.send_error(
                None,
                f"Permission change warning `{risk.level.name}`: {risk.description}\n{risk.mitigation}",
                log_to_channel=True,
            )
