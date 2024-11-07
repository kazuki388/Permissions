import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum, auto
from functools import lru_cache
from logging.handlers import RotatingFileHandler
from typing import Dict, FrozenSet, List, Optional, Union

import interactions
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


class RiskLevel(Enum):
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFO = auto()


@dataclass(frozen=True, slots=True)
class PermissionRisk:
    level: RiskLevel
    description: str = ""
    mitigation: str = ""
    affected_permissions: FrozenSet[int] = frozenset()


class EmbedColor(Enum):
    OFF = 0x5D5A58
    FATAL = 0xFF4343
    ERROR = 0xE81123
    WARN = 0xFFB900
    INFO = 0x0078D7
    DEBUG = 0x00B7C3
    TRACE = 0x8E8CD8
    ALL = 0x0063B1


@dataclass(frozen=True, slots=True)
class RoleLevel:
    position: int
    roles: tuple[interactions.Role, ...]


def permission_value_to_names(permission_value: int) -> List[str]:
    return [
        permission.name.replace("_", " ").title()
        for permission in interactions.Permissions
        if permission_value & permission.value
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

    DANGEROUS_COMBINATIONS: Dict[frozenset[int], PermissionRisk] = {
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

    MFA_REQUIRED_PERMISSIONS: frozenset[int] = frozenset(
        {
            interactions.Permissions.KICK_MEMBERS.value,
            interactions.Permissions.BAN_MEMBERS.value,
            interactions.Permissions.ADMINISTRATOR.value,
            interactions.Permissions.MANAGE_CHANNELS.value,
            interactions.Permissions.MANAGE_GUILD.value,
            interactions.Permissions.MANAGE_MESSAGES.value,
            interactions.Permissions.MANAGE_ROLES.value,
            interactions.Permissions.MANAGE_WEBHOOKS.value,
            interactions.Permissions.MANAGE_EMOJIS_AND_STICKERS.value,
        }
    )

    async def check_permission_inheritance(self) -> List[PermissionRisk]:
        if not self.guild:
            return []

        risks: List[PermissionRisk] = []
        for channel in self.guild.channels:
            if isinstance(channel, interactions.GuildCategory):
                cat_overwrites = self.channel_overwrites.get(channel.id, {})

                child_risks = (
                    PermissionRisk(
                        RiskLevel.LOW,
                        f"Channel `{child.name}` has redundant permissions",
                        "Remove redundant permission overwrites from child channel",
                        frozenset({cat_overwrite.allow}),
                    )
                    for child in channel.channels
                    for overwrite_id, cat_overwrite in cat_overwrites.items()
                    if (child_overwrites := self.channel_overwrites.get(child.id, {}))
                    and overwrite_id in child_overwrites
                    and cat_overwrite.allow == child_overwrites[overwrite_id].allow
                    and cat_overwrite.deny == child_overwrites[overwrite_id].deny
                )
                risks.extend(child_risks)
        return risks

    async def create_embed(
        self, title: str, description: str = "", color: EmbedColor = EmbedColor.INFO
    ) -> interactions.Embed:
        embed = interactions.Embed(
            title=title,
            description=description,
            color=color.value,
            timestamp=datetime.now(timezone.utc),
        )
        embed.set_footer(text="鍵政大舞台")
        return embed

    @lru_cache(maxsize=1)
    def _get_log_channels(self) -> tuple[int, int, int]:
        return (
            self.LOG_CHANNEL_ID,
            self.LOG_POST_ID,
            self.LOG_FORUM_ID,
        )

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
        embed: interactions.Embed = await self.create_embed(title, message, color)
        if ctx:
            await ctx.send(embed=embed, ephemeral=True)
        if log_to_channel:
            LOG_CHANNEL_ID, LOG_POST_ID, LOG_FORUM_ID = self._get_log_channels()
            await self.send_to_channel(LOG_CHANNEL_ID, embed)
            await self.send_to_forum_post(LOG_FORUM_ID, LOG_POST_ID, embed)

    async def send_to_channel(self, channel_id: int, embed: interactions.Embed) -> None:
        try:
            channel = await self.bot.fetch_channel(channel_id)
            if not isinstance(channel, interactions.GuildText):
                logger.error(f"Channel ID {channel_id} is not a valid text channel.")
                return
            await channel.send(embed=embed)
        except NotFound as nf:
            logger.error(f"Channel with ID {channel_id} not found: {nf!r}")
        except Exception as e:
            logger.error(f"Error sending message to channel {channel_id}: {e!r}")

    async def send_to_forum_post(
        self, forum_id: int, post_id: int, embed: interactions.Embed
    ) -> None:
        try:
            forum = await self.bot.fetch_channel(forum_id)
            if not isinstance(forum, interactions.GuildForum):
                logger.error(f"Channel ID {forum_id} is not a valid forum channel.")
                return

            thread = await forum.fetch_post(post_id)
            if not isinstance(thread, interactions.GuildPublicThread):
                logger.error(f"Post with ID {post_id} is not a valid thread.")
                return

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

    module_base = interactions.SlashCommand(
        name="permissions", description="Permissions commands"
    )

    @module_base.subcommand("audit", sub_cmd_description="Audit server permissions")
    @interactions.slash_option(
        name="field",
        description="The field to audit",
        required=False,
        opt_type=interactions.OptionType.STRING,
        choices=[
            interactions.SlashCommandChoice(
                name="Dangerous Combinations", value="dangerous"
            ),
            interactions.SlashCommandChoice(
                name="Channel Overwrites", value="overwrites"
            ),
            interactions.SlashCommandChoice(
                name="Permission Inheritance", value="inheritance"
            ),
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
        self.guild = ctx.guild

        risk_functions = {
            "dangerous": self.check_dangerous_role_combinations,
            "overwrites": self.analyze_channel_overwrites,
            "inheritance": self.check_permission_inheritance,
        }

        risks = []
        if field:
            risks.extend(await risk_functions[field]())
        else:
            for func in risk_functions.values():
                risks.extend(await func())

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
                chunk = level_risks[i : i + FIELDS_PER_EMBED]
                embed = await self.create_embed(
                    title=f"{level.name} Level Risks ({len(level_risks)})"
                    + (
                        f" (Page {i//FIELDS_PER_EMBED + 1})"
                        if len(level_risks) > FIELDS_PER_EMBED
                        else ""
                    ),
                    color=color_map[level],
                )

                for risk in chunk:
                    embed.add_field(
                        name=risk.description,
                        value=(
                            f"**Recommended Action:**\n{risk.mitigation}\n\n"
                            f"**Affected Permissions:**\n"
                            f"{', '.join(permission_value_to_names(sum(risk.affected_permissions)))}"
                        ),
                        inline=False,
                    )
                embeds.append(embed)

        if risks:
            fix_results = await self.apply_fixes(ctx, risks)
            await self.send_success(
                ctx,
                f"Automatic fixes applied:\n{chr(10).join(fix_results)}",
                log_to_channel=True,
            )

        if embeds:
            await Paginator.create_from_embeds(self.bot, *embeds, timeout=300).send(ctx)
        else:
            await self.send_success(ctx, "No permission risks found.")

    async def check_dangerous_role_combinations(self) -> List[PermissionRisk]:
        if not self.guild:
            return []

        def generate_dangerous_combo_risks(role):
            return (
                PermissionRisk(
                    risk.level,
                    f"Role `{role.name}` - {risk.description}",
                    risk.mitigation,
                    risk.affected_permissions,
                )
                for dangerous_combo, risk in self.DANGEROUS_COMBINATIONS.items()
                if all(
                    perm & role.permissions.value == perm for perm in dangerous_combo
                )
            )

        def generate_mfa_risks(role):
            mfa_perms = {
                perm
                for perm in self.MFA_REQUIRED_PERMISSIONS
                if role.permissions.value & perm == perm
            }

            if not mfa_perms:
                return []

            perm_names = [
                name for perm in mfa_perms for name in permission_value_to_names(perm)
            ]

            return [
                PermissionRisk(
                    RiskLevel.HIGH,
                    f"Role `{role.name}` includes permissions that require two-factor authentication.",
                    f"Enable two-factor authentication for users with the following permissions: {', '.join(perm_names)}",
                    frozenset(mfa_perms),
                )
            ]

        return [
            risk
            for role in self.guild.roles
            for risk in [
                *generate_dangerous_combo_risks(role),
                *generate_mfa_risks(role),
            ]
        ]

    async def analyze_role_hierarchy(self) -> None:
        if not self.guild:
            return

        sorted_roles = sorted(self.guild.roles, key=lambda r: r.position, reverse=True)
        self.role_hierarchy = {
            role.position: RoleLevel(
                position=role.position,
                roles=tuple(r for r in self.guild.roles if r.position == role.position),
            )
            for role in sorted_roles
        }

    async def analyze_channel_overwrites(self) -> List[PermissionRisk]:
        if not self.guild:
            return []

        channels_with_perms = (
            channel
            for channel in self.guild.channels
            if hasattr(channel, "permission_overwrites")
        )

        self.channel_overwrites.update(
            {
                channel.id: {
                    overwrite.id: overwrite
                    for overwrite in channel.permission_overwrites
                }
                for channel in channels_with_perms
            }
        )

        admin_risks = (
            PermissionRisk(
                RiskLevel.CRITICAL,
                f"Channel `{channel.name}` has <&1150630510696075404> admin permissions",
                "Remove administrator permission from <&1150630510696075404>",
                frozenset({interactions.Permissions.ADMINISTRATOR.value}),
            )
            for channel in channels_with_perms
            if (
                admin_overwrite := self.channel_overwrites[channel.id].get(
                    self.guild.id
                )
            )
            and interactions.Permissions.ADMINISTRATOR.value & admin_overwrite.allow
        )

        overwrite_risks = (
            PermissionRisk(
                RiskLevel.LOW,
                f"Channel `{channel.name}` has redundant overwrites",
                f"Remove redundant permissions: {', '.join(permission_value_to_names(overlapping))}",
                frozenset({overlapping}),
            )
            for channel in channels_with_perms
            for overwrite in channel.permission_overwrites
            if (role := self.guild.get_role(overwrite.id))
            and (overlapping := role.permissions.value & overwrite.allow)
        )

        return list(admin_risks) + list(overwrite_risks)

    @property
    @lru_cache(maxsize=128)
    def dangerous_permission_masks(self) -> dict[int, PermissionRisk]:
        return {
            perm: risk
            for perms, risk in self.DANGEROUS_COMBINATIONS.items()
            for perm in perms
        }

    async def monitor_permission_changes(
        self,
        before: Union[interactions.Role, interactions.PermissionOverwrite],
        after: Union[interactions.Role, interactions.PermissionOverwrite],
    ) -> Optional[PermissionRisk]:
        if not isinstance(before, interactions.Role) or not isinstance(
            after, interactions.Role
        ):
            return None

        added_perms = after.permissions.value & ~before.permissions.value
        if not added_perms:
            return None

        return next(
            (
                PermissionRisk(
                    risk.level,
                    f"\n**Security Alert:** Role `{after.name}` received potentially dangerous permissions\n",
                    (
                        f"**Added Permissions:**\n- {', '.join(permission_value_to_names(added_perms))}\n"
                        f"**High-Risk Permissions:**\n- {', '.join(permission_value_to_names(added_perms & perm))}\n"
                        f"**Recommended Action:**\nReview these permission changes and ensure they are necessary for the role's function."
                    ),
                    frozenset({added_perms & perm}),
                )
                for perm, risk in self.dangerous_permission_masks.items()
                if added_perms & perm
            ),
            None,
        )

    @interactions.listen(RoleUpdate)
    async def on_role_update(self, event: RoleUpdate) -> None:
        if not event.after.guild:
            return

        self.guild = event.after.guild
        if risk := await self.monitor_permission_changes(event.before, event.after):
            await self.send_error(
                None,
                f"Permission change warning [{risk.level.name}]: {risk.description}\n{risk.mitigation}",
                log_to_channel=True,
            )

    async def apply_fixes(
        self, ctx: interactions.SlashContext, risks: List[PermissionRisk]
    ) -> List[str]:
        if not self.guild:
            return ["No guild context available"]

        results: List[str] = []
        role_cache = {role.name: role for role in self.guild.roles}

        for risk in risks:
            try:
                role_name = risk.description[
                    risk.description.find("`")
                    + 1 : risk.description.find("`", risk.description.find("`") + 1)
                ]
                if not (role := role_cache.get(role_name)):
                    continue

                current_perms = role.permissions.value
                if (
                    interactions.Permissions.ADMINISTRATOR.value
                    in risk.affected_permissions
                ):
                    new_perms = (
                        current_perms & ~interactions.Permissions.ADMINISTRATOR.value
                    )
                    await role.modify(permissions=new_perms)
                    results.append(
                        f"Removed administrator permission from role {role_name}"
                    )

                elif (
                    interactions.Permissions.MANAGE_GUILD.value
                    in risk.affected_permissions
                ):
                    dangerous_mask = (
                        interactions.Permissions.MANAGE_GUILD.value
                        | interactions.Permissions.MANAGE_ROLES.value
                    )
                    new_perms = current_perms & ~dangerous_mask
                    await role.modify(permissions=new_perms)
                    results.append(
                        f"Removed dangerous permission combination from role {role_name}"
                    )

            except Exception as e:
                error_msg = f"Failed to fix {risk.description}: {str(e)}"
                results.append(error_msg)
                logger.error(error_msg)

        return results
