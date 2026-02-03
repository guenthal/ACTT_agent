"""Tests for the KMS access query tool."""

import pytest

from mcp_servers.act_data_query.tools.kms_access import (
    get_kms_privileged_entities,
    _categorize_kms_actions,
    _matches_action,
)


def call_tool(tool, **kwargs):
    """Helper to call an MCP tool function, handling the FunctionTool wrapper."""
    # FastMCP wraps functions with @mcp.tool() decorator
    # The underlying function is accessible via .fn attribute
    if hasattr(tool, "fn"):
        return tool.fn(**kwargs)
    return tool(**kwargs)


class TestMatchesAction:
    """Tests for action matching with wildcards."""

    def test_exact_match(self):
        """Test exact action matching."""
        assert _matches_action("kms:Decrypt", {"kms:Decrypt"})
        assert not _matches_action("kms:Encrypt", {"kms:Decrypt"})

    def test_wildcard_star_matches_all(self):
        """Test that kms:* matches all KMS actions."""
        target_actions = {"kms:CreateKey", "kms:Decrypt"}
        assert _matches_action("kms:*", target_actions)

    def test_partial_wildcard(self):
        """Test partial wildcard matching."""
        assert _matches_action("kms:ReEncrypt*", {"kms:ReEncryptFrom"})
        assert _matches_action("kms:Generate*", {"kms:GenerateDataKey"})

    def test_case_insensitive(self):
        """Test case insensitive matching."""
        assert _matches_action("KMS:Decrypt", {"kms:decrypt"})


class TestCategorizeKmsActions:
    """Tests for KMS action categorization."""

    def test_admin_actions(self):
        """Test categorization of admin actions."""
        actions = ["kms:CreateKey", "kms:ScheduleKeyDeletion"]
        result = _categorize_kms_actions(actions)
        assert "kms:CreateKey" in result["admin"]
        assert "kms:ScheduleKeyDeletion" in result["admin"]
        assert not result["encrypt_decrypt"]

    def test_encrypt_decrypt_actions(self):
        """Test categorization of encrypt/decrypt actions."""
        actions = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"]
        result = _categorize_kms_actions(actions)
        assert "kms:Encrypt" in result["encrypt_decrypt"]
        assert "kms:Decrypt" in result["encrypt_decrypt"]
        assert "kms:GenerateDataKey" in result["encrypt_decrypt"]
        assert not result["admin"]

    def test_read_only_actions(self):
        """Test categorization of read-only actions."""
        actions = ["kms:DescribeKey", "kms:ListKeys", "kms:GetKeyPolicy"]
        result = _categorize_kms_actions(actions)
        assert "kms:DescribeKey" in result["read_only"]
        assert "kms:ListKeys" in result["read_only"]
        assert not result["admin"]
        assert not result["encrypt_decrypt"]

    def test_full_wildcard_categorizes_all(self):
        """Test that kms:* is categorized as all permission levels."""
        result = _categorize_kms_actions(["kms:*"])
        assert "kms:*" in result["admin"]
        assert "kms:*" in result["encrypt_decrypt"]
        assert "kms:*" in result["read_only"]

    def test_non_kms_actions_ignored(self):
        """Test that non-KMS actions are ignored."""
        result = _categorize_kms_actions(["s3:GetObject", "ec2:DescribeInstances"])
        assert not result["admin"]
        assert not result["encrypt_decrypt"]
        assert not result["read_only"]


class TestGetKmsPrivilegedEntities:
    """Tests for the main tool function."""

    def test_returns_expected_structure(self):
        """Test that the tool returns the expected structure."""
        result = call_tool(get_kms_privileged_entities)
        assert "summary" in result
        assert "users" in result
        assert "groups" in result
        assert "roles" in result
        assert "permission_level_filter" in result

    def test_summary_counts(self):
        """Test that summary contains valid counts."""
        result = call_tool(get_kms_privileged_entities)
        summary = result["summary"]
        assert summary["total_users_with_kms_access"] >= 0
        assert summary["total_groups_with_kms_access"] >= 0
        assert summary["total_roles_with_kms_access"] >= 0
        assert summary["total_entities"] == (
            summary["total_users_with_kms_access"]
            + summary["total_groups_with_kms_access"]
            + summary["total_roles_with_kms_access"]
        )

    def test_filter_by_admin(self):
        """Test filtering by admin permission level."""
        result = call_tool(get_kms_privileged_entities, permission_level="admin")
        assert result["permission_level_filter"] == "admin"
        # All entities should have admin permissions
        for user in result["users"]:
            has_admin = False
            for perm in user["permissions"]:
                if perm.get("source") == "group_membership":
                    for gp in perm.get("group_permissions", []):
                        if gp.get("categorized_actions", {}).get("admin"):
                            has_admin = True
                            break
                elif perm.get("categorized_actions", {}).get("admin"):
                    has_admin = True
                    break
            assert has_admin, f"User {user['entity_name']} has no admin permissions"

    def test_filter_by_encrypt_decrypt(self):
        """Test filtering by encrypt_decrypt permission level."""
        result = call_tool(get_kms_privileged_entities, permission_level="encrypt_decrypt")
        assert result["permission_level_filter"] == "encrypt_decrypt"

    def test_filter_by_read_only(self):
        """Test filtering by read_only permission level."""
        result = call_tool(get_kms_privileged_entities, permission_level="read_only")
        assert result["permission_level_filter"] == "read_only"

    def test_admin_user_detected(self):
        """Test that admin-jsmith is detected with KMS admin permissions."""
        result = call_tool(get_kms_privileged_entities, permission_level="admin")
        user_names = [u["entity_name"] for u in result["users"]]
        assert "admin-jsmith" in user_names

    def test_lambda_role_detected(self):
        """Test that Lambda-DataProcessor-Role with kms:* is detected."""
        result = call_tool(get_kms_privileged_entities, permission_level="admin")
        role_names = [r["entity_name"] for r in result["roles"]]
        assert "Lambda-DataProcessor-Role" in role_names

    def test_groups_include_members(self):
        """Test that groups include member information."""
        result = call_tool(get_kms_privileged_entities)
        for group in result["groups"]:
            assert "members" in group

    def test_roles_include_trust_principals(self):
        """Test that roles include trust principal information."""
        result = call_tool(get_kms_privileged_entities)
        for role in result["roles"]:
            assert "trust_principals" in role
