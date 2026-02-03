# MCP Server Test Results

**Test Date:** 2026-02-03
**Server:** ACT Data Query Server
**FastMCP Version:** 2.14.4

## Summary

The MCP server was tested using the MCP client library to simulate Inspector-style tool calls. All tests passed successfully.

### Available Tools

- `get_kms_privileged_entities` - Find all IAM users, roles, and groups with KMS permissions

## Test Results

### Test 1: All KMS Permissions (No Parameters)

**Parameters:** None (defaults to `permission_level="all"`)

**Results:**
| Metric | Count |
|--------|-------|
| Users with KMS access | 7 |
| Groups with KMS access | 4 |
| Roles with KMS access | 9 |
| **Total entities** | **20** |

**Sample Users:** admin-jsmith, dev-mjohnson, analyst-kwilliams
**Sample Roles:** EC2-Instance-Role, Lambda-DataProcessor-Role, CrossAccount-Audit-Role

---

### Test 2: Admin Permissions Only

**Parameters:** `{"permission_level": "admin"}`

**Results:**
| Metric | Count |
|--------|-------|
| Users with admin access | 3 |
| Groups with admin access | 2 |
| Roles with admin access | 5 |
| **Total entities** | **10** |

**Users with Admin:**
- admin-jsmith
- security-admin-tbrown
- ops-engineer-rlee

**Roles with Admin:**
- Lambda-DataProcessor-Role (inline kms:* - overly permissive)
- CrossAccount-KMS-Admin-Role
- SAML-Federated-Admin-Role
- BusinessHours-KMS-Role
- Emergency-Break-Glass-Role

---

### Test 3: Encrypt/Decrypt Permissions

**Parameters:** `{"permission_level": "encrypt_decrypt"}`

**Results:**
| Metric | Count |
|--------|-------|
| Users with encrypt/decrypt | 6 |
| Groups with encrypt/decrypt | 2 |
| Roles with encrypt/decrypt | 6 |
| **Total entities** | **14** |

**Sample Entities:** admin-jsmith, dev-mjohnson, EC2-Instance-Role, Lambda-DataProcessor-Role

---

### Test 4: Read-Only Permissions

**Parameters:** `{"permission_level": "read_only"}`

**Results:**
| Metric | Count |
|--------|-------|
| Users with read-only | 4 |
| Groups with read-only | 3 |
| Roles with read-only | 7 |
| **Total entities** | **14** |

**Sample Entities:** admin-jsmith, analyst-kwilliams, Lambda-DataProcessor-Role, CrossAccount-Audit-Role

---

## Sample Detailed Output

### User: admin-jsmith

```json
{
  "entity_type": "user",
  "entity_name": "admin-jsmith",
  "entity_arn": "arn:aws:iam::123456789012:user/admin-jsmith",
  "path": "/",
  "permissions": [
    {
      "source": "inline_policy",
      "policy_name": "InlineKMSAdminPolicy",
      "actions": ["kms:*"],
      "categorized_actions": {
        "admin": ["kms:*"],
        "encrypt_decrypt": ["kms:*"],
        "read_only": ["kms:*"]
      },
      "resources": ["*"]
    },
    {
      "source": "attached_managed_policy",
      "policy_name": "AdministratorAccess",
      "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
      "actions": ["*"],
      "note": "AWS managed policy - includes full KMS access"
    },
    {
      "source": "group_membership",
      "group_name": "Admins",
      "group_permissions": [
        {
          "source": "group_attached_policy",
          "policy_name": "AdministratorAccess",
          "actions": ["*"],
          "note": "AWS managed policy - includes full KMS access"
        }
      ]
    }
  ]
}
```

### Role: Lambda-DataProcessor-Role

```json
{
  "entity_type": "role",
  "entity_name": "Lambda-DataProcessor-Role",
  "entity_arn": "arn:aws:iam::123456789012:role/service-role/Lambda-DataProcessor-Role",
  "path": "/service-role/",
  "trust_principals": ["lambda.amazonaws.com"],
  "last_used": "2024-01-21T08:45:00Z",
  "permissions": [
    {
      "source": "inline_policy",
      "policy_name": "LambdaExcessiveKMSPolicy",
      "actions": ["kms:*"],
      "categorized_actions": {
        "admin": ["kms:*"],
        "encrypt_decrypt": ["kms:*"],
        "read_only": ["kms:*"]
      },
      "resources": ["*"]
    }
  ]
}
```

## Issues Found

No issues were found during testing. The tool correctly:

1. Identifies all IAM entities (users, groups, roles) with KMS permissions
2. Parses inline policies for KMS actions
3. Parses attached managed policies (both customer and AWS-managed)
4. Tracks group membership inheritance for users
5. Categorizes permissions into admin/encrypt_decrypt/read_only levels
6. Filters results by permission level when requested
7. Includes trust principals for roles
8. Includes group members for groups
9. Returns structured JSON suitable for audit reporting

## Audit Findings from Test Data

The tool identified several notable findings in the sample IAM data:

1. **Overly Permissive Lambda Role:** `Lambda-DataProcessor-Role` has `kms:*` on all resources
2. **Multiple Admin Paths:** `admin-jsmith` has admin access through 3 different paths (inline policy, attached policy, and group membership)
3. **Cross-Account KMS Admin:** `CrossAccount-KMS-Admin-Role` can be assumed by external accounts and has KMS admin permissions

## Conclusion

The MCP server and `get_kms_privileged_entities` tool work as expected and are ready for use in auditing AWS IAM KMS permissions.
