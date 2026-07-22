merge into error_catalog e using (
 select 'TMS-1001' c, 'User account not found or unavailable.' u,
 'APP_USERS lookup failed / row deleted or missing.' d, null k from dual union all
 select 'TMS-1002', 'You are not authorized to perform this action.',
 'Permission/role/admin-mode guard rejected the caller.', null from dual union all
 select 'TMS-1003', 'Password must be at least %1 characters long.',
 'Policy A-07 length check.', null from dual union all
 select 'TMS-1004', 'Password must contain at least 3 of: lower, upper, digit, symbol.',
 'Policy A-07 character-class check.', null from dual union all
 select 'TMS-1005', 'Password must not match your e-mail address.',
 'Policy A-07 local-part check.', null from dual union all
 select 'TMS-1006', 'This link is invalid, already used, or expired. Request a new one.',
 'PASSWORD_RESETS token claim failed (missing/used/expired/wrong purpose).', null from dual 
union all
 select 'TMS-1007', 'Your current password is incorrect.',
 'change_password old-password verification failed.', null from dual union all
 select 'TMS-2001', 'This e-mail address cannot be used (invalid or already registered).',
 'Format failure or APP_USERS_UK1 duplicate within realm.', 'APP_USERS_UK1' from dual union all
 select 'TMS-2002', 'You have reached your licensed seat limit (%1). Deactivate a user or add seats.',
 'ACTIVE+INVITED count >= TENANTS.SEATS_PURCHASED.', null from dual union all
 select 'TMS-2003', 'You cannot deactivate your own account.',
 'Self-deactivation guard in pkg_users.', null from dual union all
 select 'TMS-2004', 'USDOT number %1 is already registered to an active company.',
 'Live-tenant USDOT duplicate (pre-check or TENANTS_UK1).', 'TENANTS_UK1' from dual union all
 select 'TMS-2005', 'Unknown or inactive role: %1.',
 'ROLES lookup failed in pkg_roles/pkg_permissions.', null from dual union all
 select 'TMS-2006', 'Role %1 cannot be assigned to a user of type %2.',
 'Realm-match rule (TDS 5.1) violated.', null from dual union all
 select 'TMS-2007', 'Status change from %1 to %2 is not allowed.',
 'Tenant status machine rejected the transition.', null from dual union all
 select 'TMS-3001', 'Unknown configuration key: %1.',
 'SYSTEM_CONFIG/TENANT.* key missing; keys are created by migration.', null from dual union all
 select 'TMS-3002', 'Configuration value for %1 is not a valid %2.',
 'Type validation failed on read or write.', null from dual union all
 select 'TMS-3003', 'Configuration key %1 cannot be overridden per tenant.',
 'IS_TENANT_OVERRIDABLE_YN = N and not TENANT.* namespaced.', null from dual union all
 select 'TMS-9999', 'An unexpected error occurred. Reference: %1.',
 'Generic wrapper raised by pkg_error.handle_unexpected.', null from dual
) v on (e.error_code = v.c)
when matched then update set user_message = v.u, developer_message = v.d,
 constraint_name = v.k
when not matched then insert (error_code, user_message, developer_message, constraint_name)
values (v.c, v.u, v.d, v.k);
