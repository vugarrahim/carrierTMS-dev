create or replace package pkg_permissions as
  -- ==========================================================================
  -- Package: PKG_PERMISSIONS (TDS 8.2)
  -- Purpose: Permission catalog reads + role-bundle maintenance. Bundle edits
  -- are operator actions (ADMIN.MANAGE_SYSTEM_CONFIG realm) in
  -- Phase 2; the catalog itself is seeded by migration only.
  -- ==========================================================================
  function permission_exists(p_code in varchar2) return boolean;
  function get_permission_id(p_code in varchar2) return number;
  procedure grant_to_role(p_role_code       in varchar2,
                          p_permission_code in varchar2);
  procedure revoke_from_role(p_role_code       in varchar2,
                             p_permission_code in varchar2);
end pkg_permissions;
/
create or replace package body pkg_permissions as
  function get_permission_id(p_code in varchar2) return number is
    l_id permissions.permission_id%type;
  begin
    select permission_id
      into l_id
      from permissions
     where permission_code = upper(p_code)
       and is_active_yn = 'Y';
    return l_id;
  exception
    when no_data_found then
      return null;
  end;
  function permission_exists(p_code in varchar2) return boolean is
  begin
    return get_permission_id(p_code) is not null;
  end;
  procedure assert_operator is
  begin
    -- Bundle maintenance is platform-operator work in Phase 2.
    if not (pkg_security.has_role('SYS_ADMIN') or
        sys_context('app_ctx', 'admin_mode') = 'Y') then
      pkg_error.raise_business('TMS-1002');
    end if;
  end;
  procedure grant_to_role(p_role_code       in varchar2,
                          p_permission_code in varchar2) is
    l_role_id roles.role_id%type;
    l_perm_id permissions.permission_id%type := get_permission_id(p_permission_code);
  begin
    assert_operator;
    l_role_id := pkg_roles.get_role_id(p_role_code); -- raises TMS-2005 if unknown
    if l_perm_id is null then
      pkg_error.raise_business('TMS-2005', p_permission_code);
    end if;
    merge into role_permissions rp
    using (select l_role_id r, l_perm_id p from dual) s
    on (rp.role_id = s.r and rp.permission_id = s.p)
    when not matched then
      insert
        (role_id, permission_id, granted_by)
      values
        (s.r, s.p, pkg_security.get_user_id);
    if sql%rowcount > 0 then
      pkg_audit.log_action('ROLE',
                           l_role_id,
                           'ROLE_GRANT',
                           upper(p_role_code) || ' += ' ||
                           upper(p_permission_code));
      pkg_security.invalidate_authz_cache;
    end if;
  exception
    when others then
      if sqlcode = pkg_error.c_business_errnum then
        raise;
      end if;
      pkg_error.handle_unexpected('pkg_permissions.grant_to_role');
  end;
  procedure revoke_from_role(p_role_code       in varchar2,
                             p_permission_code in varchar2) is
    l_role_id roles.role_id%type;
  begin
    assert_operator;
    l_role_id := pkg_roles.get_role_id(p_role_code);
    delete from role_permissions
     where role_id = l_role_id
       and permission_id = get_permission_id(p_permission_code);
    if sql%rowcount > 0 then
      pkg_audit.log_action('ROLE',
                           l_role_id,
                           'ROLE_REVOKE',
                           upper(p_role_code) || ' -= ' ||
                           upper(p_permission_code));
      pkg_security.invalidate_authz_cache;
    end if;
  exception
    when others then
      if sqlcode = pkg_error.c_business_errnum then
        raise;
      end if;
      pkg_error.handle_unexpected('pkg_permissions.revoke_from_role');
  end;
end pkg_permissions;
/
