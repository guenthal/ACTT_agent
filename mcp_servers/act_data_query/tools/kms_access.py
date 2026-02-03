"""
MCP tool for querying IAM entities with KMS permissions.

This module provides the get_kms_privileged_entities tool for finding
all IAM users, roles, and groups with KMS administrative or encryption permissions.
"""

import logging
import re
import sys
from typing import Any, Literal

# Configure logging to stderr (NEVER use print in MCP STDIO servers!)
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)

from mcp_servers.act_data_query.server import get_iam_data, mcp

# Define KMS action categories
# Note: kms:* is handled separately as a full wildcard
KMS_ADMIN_ACTIONS = {
    "kms:CreateKey",
    "kms:ScheduleKeyDeletion",
    "kms:CancelKeyDeletion",
    "kms:DeleteAlias",
    "kms:DeleteImportedKeyMaterial",
    "kms:DisableKey",
    "kms:DisableKeyRotation",
    "kms:EnableKey",
    "kms:EnableKeyRotation",
    "kms:PutKeyPolicy",
    "kms:UpdateKeyDescription",
    "kms:UpdatePrimaryRegion",
    "kms:CreateGrant",
    "kms:RetireGrant",
    "kms:RevokeGrant",
    "kms:TagResource",
    "kms:UntagResource",
    "kms:CreateAlias",
    "kms:UpdateAlias",
}

KMS_ENCRYPT_DECRYPT_ACTIONS = {
    "kms:Encrypt",
    "kms:Decrypt",
    "kms:ReEncrypt*",
    "kms:ReEncryptFrom",
    "kms:ReEncryptTo",
    "kms:GenerateDataKey",
    "kms:GenerateDataKey*",
    "kms:GenerateDataKeyWithoutPlaintext",
    "kms:GenerateDataKeyPair",
    "kms:GenerateDataKeyPairWithoutPlaintext",
}

KMS_READ_ONLY_ACTIONS = {
    "kms:DescribeKey",
    "kms:GetKeyPolicy",
    "kms:GetKeyRotationStatus",
    "kms:GetPublicKey",
    "kms:ListKeys",
    "kms:ListAliases",
    "kms:ListKeyPolicies",
    "kms:ListResourceTags",
    "kms:ListGrants",
    "kms:ListRetirableGrants",
    "kms:Describe*",
    "kms:Get*",
    "kms:List*",
}

PermissionLevel = Literal["admin", "encrypt_decrypt", "read_only", "all"]


def _matches_action(action: str, target_actions: set[str]) -> bool:
    """
    Check if an action matches any target action, supporting wildcards.

    Args:
        action: The IAM action to check (e.g., "kms:Decrypt", "kms:*").
        target_actions: Set of target actions to match against.

    Returns:
        True if the action matches any target action.
    """
    action_lower = action.lower()

    # Direct match
    if action_lower in {a.lower() for a in target_actions}:
        return True

    # Wildcard kms:* matches everything
    if action_lower == "kms:*":
        return True

    # Check if action is a wildcard pattern that matches any target
    if "*" in action:
        # Convert wildcard pattern to regex
        pattern = action_lower.replace("*", ".*")
        for target in target_actions:
            if re.match(f"^{pattern}$", target.lower()):
                return True

    # Check if any target is a wildcard pattern that matches the action
    for target in target_actions:
        if "*" in target:
            pattern = target.lower().replace("*", ".*")
            if re.match(f"^{pattern}$", action_lower):
                return True

    return False


def _categorize_kms_actions(actions: list[str]) -> dict[str, list[str]]:
    """
    Categorize a list of KMS actions into permission levels.

    Args:
        actions: List of IAM actions (e.g., ["kms:Decrypt", "kms:CreateKey"]).

    Returns:
        Dictionary mapping permission levels to lists of matching actions.
    """
    categorized: dict[str, list[str]] = {
        "admin": [],
        "encrypt_decrypt": [],
        "read_only": [],
    }

    for action in actions:
        if not action.lower().startswith("kms:"):
            continue

        if action.lower() in ("*", "kms:*"):
            # Full wildcard grants everything
            categorized["admin"].append(action)
            categorized["encrypt_decrypt"].append(action)
            categorized["read_only"].append(action)
        elif _matches_action(action, KMS_ADMIN_ACTIONS):
            categorized["admin"].append(action)
        elif _matches_action(action, KMS_ENCRYPT_DECRYPT_ACTIONS):
            categorized["encrypt_decrypt"].append(action)
        elif _matches_action(action, KMS_READ_ONLY_ACTIONS):
            categorized["read_only"].append(action)

    return categorized


def _extract_kms_actions_from_statement(statement: dict[str, Any]) -> list[str]:
    """
    Extract KMS actions from a policy statement.

    Args:
        statement: IAM policy statement dictionary.

    Returns:
        List of KMS actions if the statement allows them, empty list otherwise.
    """
    # Only process Allow statements
    if statement.get("Effect") != "Allow":
        return []

    actions = statement.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]

    kms_actions = []
    for action in actions:
        if action == "*" or action.lower().startswith("kms:"):
            kms_actions.append(action)

    return kms_actions


def _extract_kms_permissions_from_policy_document(
    policy_doc: dict[str, Any],
) -> dict[str, Any]:
    """
    Extract KMS permissions from a policy document.

    Args:
        policy_doc: IAM policy document dictionary.

    Returns:
        Dictionary containing categorized KMS actions and resources.
    """
    all_actions: list[str] = []
    resources: list[str] = []
    conditions: list[dict[str, Any]] = []

    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        kms_actions = _extract_kms_actions_from_statement(statement)
        if kms_actions:
            all_actions.extend(kms_actions)

            # Collect resources
            stmt_resources = statement.get("Resource", [])
            if isinstance(stmt_resources, str):
                stmt_resources = [stmt_resources]
            resources.extend(stmt_resources)

            # Collect conditions
            if "Condition" in statement:
                conditions.append(statement["Condition"])

    if not all_actions:
        return {}

    return {
        "actions": list(set(all_actions)),
        "categorized_actions": _categorize_kms_actions(all_actions),
        "resources": list(set(resources)),
        "conditions": conditions if conditions else None,
    }


def _get_managed_policy_document(policy_arn: str, iam_data: dict[str, Any]) -> dict[str, Any] | None:
    """
    Get the policy document for a managed policy by ARN.

    Args:
        policy_arn: The ARN of the managed policy.
        iam_data: The loaded IAM data.

    Returns:
        The policy document dictionary, or None if not found.
    """
    # Check customer managed policies in the data
    for policy in iam_data.get("Policies", []):
        if policy.get("Arn") == policy_arn:
            # Get the default version's document
            for version in policy.get("PolicyVersionList", []):
                if version.get("IsDefaultVersion"):
                    return version.get("Document", {})

    # For AWS managed policies, we don't have the full document
    # Return None to indicate we can't analyze it further
    return None


def _process_user(user: dict[str, Any], iam_data: dict[str, Any]) -> dict[str, Any] | None:
    """
    Process a user and extract their KMS permissions.

    Args:
        user: User detail dictionary from IAM data.
        iam_data: The full IAM data for resolving references.

    Returns:
        Dictionary with user KMS permissions, or None if no KMS permissions.
    """
    permissions: list[dict[str, Any]] = []

    # Check inline policies
    for policy in user.get("UserPolicyList", []):
        policy_doc = policy.get("PolicyDocument", {})
        kms_perms = _extract_kms_permissions_from_policy_document(policy_doc)
        if kms_perms:
            permissions.append({
                "source": "inline_policy",
                "policy_name": policy.get("PolicyName"),
                **kms_perms,
            })

    # Check attached managed policies
    for attached in user.get("AttachedManagedPolicies", []):
        policy_doc = _get_managed_policy_document(attached.get("PolicyArn"), iam_data)
        if policy_doc:
            kms_perms = _extract_kms_permissions_from_policy_document(policy_doc)
            if kms_perms:
                permissions.append({
                    "source": "attached_managed_policy",
                    "policy_name": attached.get("PolicyName"),
                    "policy_arn": attached.get("PolicyArn"),
                    **kms_perms,
                })
        elif attached.get("PolicyArn", "").startswith("arn:aws:iam::aws:policy/"):
            # AWS managed policy - note that we can't fully analyze it
            # AdministratorAccess includes kms:*
            if attached.get("PolicyName") == "AdministratorAccess":
                permissions.append({
                    "source": "attached_managed_policy",
                    "policy_name": attached.get("PolicyName"),
                    "policy_arn": attached.get("PolicyArn"),
                    "actions": ["*"],
                    "categorized_actions": {
                        "admin": ["*"],
                        "encrypt_decrypt": ["*"],
                        "read_only": ["*"],
                    },
                    "resources": ["*"],
                    "note": "AWS managed policy - includes full KMS access",
                })
            elif attached.get("PolicyName") == "PowerUserAccess":
                # PowerUserAccess does NOT include IAM or Organizations
                # but includes most other services including KMS
                permissions.append({
                    "source": "attached_managed_policy",
                    "policy_name": attached.get("PolicyName"),
                    "policy_arn": attached.get("PolicyArn"),
                    "actions": ["kms:*"],
                    "categorized_actions": {
                        "admin": ["kms:*"],
                        "encrypt_decrypt": ["kms:*"],
                        "read_only": ["kms:*"],
                    },
                    "resources": ["*"],
                    "note": "AWS managed policy - includes full KMS access except key policy management",
                })
            elif attached.get("PolicyName") == "ReadOnlyAccess":
                # ReadOnlyAccess includes kms:Describe*, kms:Get*, kms:List*
                permissions.append({
                    "source": "attached_managed_policy",
                    "policy_name": attached.get("PolicyName"),
                    "policy_arn": attached.get("PolicyArn"),
                    "actions": ["kms:Describe*", "kms:Get*", "kms:List*"],
                    "categorized_actions": {
                        "admin": [],
                        "encrypt_decrypt": [],
                        "read_only": ["kms:Describe*", "kms:Get*", "kms:List*"],
                    },
                    "resources": ["*"],
                    "note": "AWS managed policy - includes KMS read-only access",
                })

    # Check group memberships
    for group_name in user.get("GroupList", []):
        group_perms = _get_group_kms_permissions(group_name, iam_data)
        if group_perms:
            permissions.append({
                "source": "group_membership",
                "group_name": group_name,
                "group_permissions": group_perms,
            })

    if not permissions:
        return None

    return {
        "entity_type": "user",
        "entity_name": user.get("UserName"),
        "entity_arn": user.get("Arn"),
        "path": user.get("Path"),
        "permissions": permissions,
    }


def _get_group_kms_permissions(group_name: str, iam_data: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Get KMS permissions for a group.

    Args:
        group_name: Name of the group.
        iam_data: The full IAM data.

    Returns:
        List of permission dictionaries for the group.
    """
    permissions: list[dict[str, Any]] = []

    for group in iam_data.get("GroupDetailList", []):
        if group.get("GroupName") != group_name:
            continue

        # Check inline policies
        for policy in group.get("GroupPolicyList", []):
            policy_doc = policy.get("PolicyDocument", {})
            kms_perms = _extract_kms_permissions_from_policy_document(policy_doc)
            if kms_perms:
                permissions.append({
                    "source": "group_inline_policy",
                    "policy_name": policy.get("PolicyName"),
                    **kms_perms,
                })

        # Check attached managed policies
        for attached in group.get("AttachedManagedPolicies", []):
            policy_doc = _get_managed_policy_document(attached.get("PolicyArn"), iam_data)
            if policy_doc:
                kms_perms = _extract_kms_permissions_from_policy_document(policy_doc)
                if kms_perms:
                    permissions.append({
                        "source": "group_attached_policy",
                        "policy_name": attached.get("PolicyName"),
                        "policy_arn": attached.get("PolicyArn"),
                        **kms_perms,
                    })
            elif attached.get("PolicyArn", "").startswith("arn:aws:iam::aws:policy/"):
                # Handle known AWS managed policies
                if attached.get("PolicyName") == "AdministratorAccess":
                    permissions.append({
                        "source": "group_attached_policy",
                        "policy_name": attached.get("PolicyName"),
                        "policy_arn": attached.get("PolicyArn"),
                        "actions": ["*"],
                        "categorized_actions": {
                            "admin": ["*"],
                            "encrypt_decrypt": ["*"],
                            "read_only": ["*"],
                        },
                        "resources": ["*"],
                        "note": "AWS managed policy - includes full KMS access",
                    })
                elif attached.get("PolicyName") == "ReadOnlyAccess":
                    permissions.append({
                        "source": "group_attached_policy",
                        "policy_name": attached.get("PolicyName"),
                        "policy_arn": attached.get("PolicyArn"),
                        "actions": ["kms:Describe*", "kms:Get*", "kms:List*"],
                        "categorized_actions": {
                            "admin": [],
                            "encrypt_decrypt": [],
                            "read_only": ["kms:Describe*", "kms:Get*", "kms:List*"],
                        },
                        "resources": ["*"],
                        "note": "AWS managed policy - includes KMS read-only access",
                    })

        break

    return permissions


def _process_group(group: dict[str, Any], iam_data: dict[str, Any]) -> dict[str, Any] | None:
    """
    Process a group and extract its KMS permissions.

    Args:
        group: Group detail dictionary from IAM data.
        iam_data: The full IAM data for resolving references.

    Returns:
        Dictionary with group KMS permissions, or None if no KMS permissions.
    """
    permissions = _get_group_kms_permissions(group.get("GroupName"), iam_data)

    if not permissions:
        return None

    # Find users in this group
    members = []
    for user in iam_data.get("UserDetailList", []):
        if group.get("GroupName") in user.get("GroupList", []):
            members.append(user.get("UserName"))

    return {
        "entity_type": "group",
        "entity_name": group.get("GroupName"),
        "entity_arn": group.get("Arn"),
        "path": group.get("Path"),
        "members": members,
        "permissions": permissions,
    }


def _process_role(role: dict[str, Any], iam_data: dict[str, Any]) -> dict[str, Any] | None:
    """
    Process a role and extract its KMS permissions.

    Args:
        role: Role detail dictionary from IAM data.
        iam_data: The full IAM data for resolving references.

    Returns:
        Dictionary with role KMS permissions, or None if no KMS permissions.
    """
    permissions: list[dict[str, Any]] = []

    # Check inline policies
    for policy in role.get("RolePolicyList", []):
        policy_doc = policy.get("PolicyDocument", {})
        kms_perms = _extract_kms_permissions_from_policy_document(policy_doc)
        if kms_perms:
            permissions.append({
                "source": "inline_policy",
                "policy_name": policy.get("PolicyName"),
                **kms_perms,
            })

    # Check attached managed policies
    for attached in role.get("AttachedManagedPolicies", []):
        policy_doc = _get_managed_policy_document(attached.get("PolicyArn"), iam_data)
        if policy_doc:
            kms_perms = _extract_kms_permissions_from_policy_document(policy_doc)
            if kms_perms:
                permissions.append({
                    "source": "attached_managed_policy",
                    "policy_name": attached.get("PolicyName"),
                    "policy_arn": attached.get("PolicyArn"),
                    **kms_perms,
                })
        elif attached.get("PolicyArn", "").startswith("arn:aws:iam::aws:policy/"):
            # Handle known AWS managed policies
            if attached.get("PolicyName") == "AdministratorAccess":
                permissions.append({
                    "source": "attached_managed_policy",
                    "policy_name": attached.get("PolicyName"),
                    "policy_arn": attached.get("PolicyArn"),
                    "actions": ["*"],
                    "categorized_actions": {
                        "admin": ["*"],
                        "encrypt_decrypt": ["*"],
                        "read_only": ["*"],
                    },
                    "resources": ["*"],
                    "note": "AWS managed policy - includes full KMS access",
                })

    if not permissions:
        return None

    # Extract trust policy info
    trust_policy = role.get("AssumeRolePolicyDocument", {})
    trust_principals = []
    for stmt in trust_policy.get("Statement", []):
        if stmt.get("Effect") == "Allow":
            principal = stmt.get("Principal", {})
            if isinstance(principal, str):
                trust_principals.append(principal)
            elif isinstance(principal, dict):
                for key, value in principal.items():
                    if isinstance(value, list):
                        trust_principals.extend(value)
                    else:
                        trust_principals.append(value)

    return {
        "entity_type": "role",
        "entity_name": role.get("RoleName"),
        "entity_arn": role.get("Arn"),
        "path": role.get("Path"),
        "trust_principals": trust_principals,
        "last_used": role.get("RoleLastUsed", {}).get("LastUsedDate"),
        "permissions": permissions,
    }


def _filter_by_permission_level(
    entity: dict[str, Any], permission_level: PermissionLevel
) -> dict[str, Any] | None:
    """
    Filter an entity's permissions by the requested permission level.

    Args:
        entity: Entity dictionary with permissions.
        permission_level: The permission level to filter by.

    Returns:
        Filtered entity dictionary, or None if no matching permissions.
    """
    if permission_level == "all":
        return entity

    filtered_permissions = []
    for perm in entity.get("permissions", []):
        # Handle group_membership specially
        if perm.get("source") == "group_membership":
            filtered_group_perms = []
            for group_perm in perm.get("group_permissions", []):
                categorized = group_perm.get("categorized_actions", {})
                if categorized.get(permission_level):
                    filtered_group_perms.append(group_perm)
            if filtered_group_perms:
                filtered_permissions.append({
                    **perm,
                    "group_permissions": filtered_group_perms,
                })
        else:
            categorized = perm.get("categorized_actions", {})
            if categorized.get(permission_level):
                filtered_permissions.append(perm)

    if not filtered_permissions:
        return None

    return {
        **entity,
        "permissions": filtered_permissions,
    }


@mcp.tool()
def get_kms_privileged_entities(
    permission_level: PermissionLevel = "all",
) -> dict[str, Any]:
    """
    Find all IAM users, roles, and groups with KMS administrative or encryption permissions.

    This tool analyzes the loaded IAM authorization data to identify entities with
    KMS permissions, categorizing them by permission level.

    Args:
        permission_level: Filter results by permission level.
            - "admin": Entities with KMS administrative permissions (create/delete keys,
              manage policies, etc.)
            - "encrypt_decrypt": Entities with encryption/decryption permissions
            - "read_only": Entities with read-only KMS permissions (list, describe, get)
            - "all": Return all entities with any KMS permissions (default)

    Returns:
        Dictionary containing:
            - summary: Count of entities by type and permission level
            - users: List of users with KMS permissions
            - groups: List of groups with KMS permissions
            - roles: List of roles with KMS permissions
            - permission_level_filter: The filter that was applied
    """
    logger.info(f"Querying KMS privileged entities with permission_level={permission_level}")

    try:
        iam_data = get_iam_data()
    except RuntimeError as e:
        logger.error(f"Failed to get IAM data: {e}")
        return {"error": str(e)}

    users: list[dict[str, Any]] = []
    groups: list[dict[str, Any]] = []
    roles: list[dict[str, Any]] = []

    # Process users
    for user in iam_data.get("UserDetailList", []):
        result = _process_user(user, iam_data)
        if result:
            filtered = _filter_by_permission_level(result, permission_level)
            if filtered:
                users.append(filtered)

    # Process groups
    for group in iam_data.get("GroupDetailList", []):
        result = _process_group(group, iam_data)
        if result:
            filtered = _filter_by_permission_level(result, permission_level)
            if filtered:
                groups.append(filtered)

    # Process roles
    for role in iam_data.get("RoleDetailList", []):
        result = _process_role(role, iam_data)
        if result:
            filtered = _filter_by_permission_level(result, permission_level)
            if filtered:
                roles.append(filtered)

    # Build summary
    summary = {
        "total_users_with_kms_access": len(users),
        "total_groups_with_kms_access": len(groups),
        "total_roles_with_kms_access": len(roles),
        "total_entities": len(users) + len(groups) + len(roles),
    }

    logger.info(
        f"Found {summary['total_entities']} entities with KMS access "
        f"(filter: {permission_level})"
    )

    return {
        "permission_level_filter": permission_level,
        "summary": summary,
        "users": users,
        "groups": groups,
        "roles": roles,
    }
