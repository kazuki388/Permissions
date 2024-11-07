# Permissions

The **Permissions** module provides comprehensive server permission management and auditing capabilities. It helps server administrators identify and mitigate security risks related to Discord role permissions and channel overwrites.

## Features

- Audit dangerous permission combinations
- Monitor permission inheritance across channels
- Analyze channel permission overwrites
- Detect redundant permission settings
- Track role hierarchy and permission changes
- Automatically fix common permission issues
- Log permission changes and security alerts
- Enforce two-factor authentication requirements
- Generate detailed audit reports
- Support for paginated audit results

## Usage

The module automatically:

- Monitors role permission changes
- Detects potentially dangerous permission modifications
- Logs security alerts to designated channels
- Tracks permission inheritance across categories
- Identifies redundant permission settings

The module monitors the following permission combinations:

- Administrator permissions
- Guild and role management combinations
- Two-factor authentication requirements
- Channel permission overwrites
- Permission inheritance patterns

### Slash Commands

- `/permissions audit`: Perform a comprehensive permissions audit
  - Options: `field` (choice, optional) - Select specific audit type:
    - `Dangerous Combinations`: Check for risky permission combinations
    - `Channel Overwrites`: Analyze channel-specific permissions
    - `Permission Inheritance`: Review permission inheritance patterns

## Configuration

Key configuration options in `main.py`:

- `LOG_CHANNEL_ID`: Channel for logging permission changes
- `LOG_FORUM_ID`: Forum for detailed audit logs
- `LOG_POST_ID`: Specific post for tracking changes
- `GUILD_ID`: Discord server ID
- `DANGEROUS_COMBINATIONS`: Defined risky permission sets
- `MFA_REQUIRED_PERMISSIONS`: Permissions requiring 2FA
- `FIELDS_PER_EMBED`: Number of fields per audit report page
