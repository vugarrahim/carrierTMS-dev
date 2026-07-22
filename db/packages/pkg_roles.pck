create or replace package pkg_roles as
  -- ==========================================================================
  -- Package: PKG_ROLES (TDS 8.2)
  -- Purpose: Role catalog reads and role assignment with realm matching.
  -- ==========================================================================
  function get_role_id(p_code in varchar2) return number; -- raises TMS-2005
  function role_exists(p_code in varchar2) return boolean;
  procedure grant_role(p_user_id    in number,
                       p_role_code  in varchar2,
                       p_expires_at in timestamp with time zone default null);
  procedure revoke_role(p_user_id in number, p_role_code in varchar2);
  -- Colon-separated active role codes (for application item G_ROLES).
  function get_user_roles(p_user_id in number) return varchar2;
end pkg_roles;
/
create or replace package body pkg_roles as
  function get_role_id(p_code in varchar2) return number is
    l_id roles.role_id%type;
  begin
    select role_id
      into l_id
      from roles
     where role_code = upper(p_code)
       and is_active_yn = 'Y'
       and tenant_id is null; -- Phase 2: system roles only
    return l_id;
  exception
    when no_data_found then
      pkg_error.raise_business('TMS-2005', upper(p_code));
  end;
  function role_exists(p_code in varchar2) return boolean is
    l_dummy number;
  begin
    l_dummy := get_role_id(p_code);
    return true;
  exception
    when others then
      return false;
  end;
  -- Realm rule (TDS 5.1 / USER_ROLES note): a role may only be granted to a
  -- user of the matching realm. Cross-table -> enforced here, not declaratively.
  procedure assert_realm_match(p_user_id   in number,
                               p_role_code in varchar2) is
    l_user_type app_users.user_type%type;
    l_realm     roles.realm%type;
  begin
    select user_type
      into l_user_type
      from app_users
     where user_id = p_user_id;
    select realm
      into l_realm
      from roles
     where role_code = upper(p_role_code)
       and tenant_id is null;
    if (l_realm = 'PLATFORM' and l_user_type <> 'PLATFORM') or
       (l_realm = 'TENANT' and l_user_type not in ('STAFF', 'DRIVER')) or
       (l_realm = 'EXTERNAL' and l_user_type <> 'PORTAL') then
      pkg_error.raise_business('TMS-2006', upper(p_role_code), l_user_type);
    end if;
  exception
    when no_data_found then
      pkg_error.raise_business('TMS-1001');
  end;
  procedure assert_can_manage(p_user_id in number) is
  begin
    -- Own-tenant admins or operators; VPD already scopes the user row itself.
    if not (pkg_security.has_permission('TENANT.MANAGE_USERS') or
        sys_context('app_ctx', 'admin_mode') = 'Y') then
      pkg_error.raise_business('TMS-1002');
    end if;
  end;
  procedure grant_role(p_user_id    in number,
                       p_role_code  in varchar2,
                       p_expires_at in timestamp with time zone default null) is
    l_role_id roles.role_id%type := get_role_id(p_role_code);
    l_tenant  app_users.tenant_id%type;
  begin
    assert_can_manage(p_user_id);
    assert_realm_match(p_user_id, p_role_code);
    select tenant_id
      into l_tenant
      from app_users
     where user_id = p_user_id;
    merge into user_roles ur
    using (select p_user_id u, l_role_id r from dual) s
    on (ur.user_id = s.u and ur.role_id = s.r)
    when matched then
      update
         set expires_at  = p_expires_at,
             updated_at  = systimestamp,
             updated_by  = pkg_security.get_user_id,
             row_version = row_version + 1
    when not matched then
      insert
        (tenant_id, user_id, role_id, granted_by, expires_at)
      values
        (l_tenant, s.u, s.r, pkg_security.get_user_id, p_expires_at);
    pkg_audit.log_action('USER',
                         p_user_id,
                         'ROLE_GRANT',
                         upper(p_role_code));
    pkg_security.invalidate_authz_cache;
  exception
    when others then
      if sqlcode = pkg_error.c_business_errnum then
        raise;
      end if;
      pkg_error.handle_unexpected('pkg_roles.grant_role');
  end;
  procedure revoke_role(p_user_id in number, p_role_code in varchar2) is
  begin
    assert_can_manage(p_user_id);
    delete from user_roles
     where user_id = p_user_id
       and role_id = get_role_id(p_role_code);
    if sql%rowcount > 0 then
      pkg_audit.log_action('USER',
                           p_user_id,
                           'ROLE_REVOKE',
                           upper(p_role_code));
      pkg_security.invalidate_authz_cache;
    end if;
  exception
    when others then
      if sqlcode = pkg_error.c_business_errnum then
        raise;
      end if;
      pkg_error.handle_unexpected('pkg_roles.revoke_role');
  end;
  function get_user_roles(p_user_id in number) return varchar2 is
    l_list varchar2(4000);
  begin
    select listagg(role_code, ':') within group(order by role_code)
      into l_list
      from v_user_roles_expanded
     where user_id = p_user_id
       and is_expired_yn = 'N';
    return l_list;
  end;
end pkg_roles;
/
