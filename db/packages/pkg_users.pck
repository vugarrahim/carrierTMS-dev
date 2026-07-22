create or replace package pkg_users as
  -- ==========================================================================
  -- Package: PKG_USERS (TDS 8.2, 4.3)
  -- Purpose: User administration: invite, profile, lock/unlock,
  -- deactivate/reactivate, admin reset. Sole writer of APP_USERS
  -- except password columns (PKG_SECURITY) and login counters
  -- (PKG_AUTH).
  -- ==========================================================================
  -- Creates INVITED user + roles + invitation token + queued e-mail.
  -- p_tenant_id defaults to session tenant; operators pass it explicitly.
  function invite_user(p_email      in varchar2,
                       p_first_name in varchar2,
                       p_last_name  in varchar2,
                       p_role_codes in varchar2, -- colon-separated
                       p_tenant_id  in number default null,
                       p_user_type  in varchar2 default 'STAFF')
    return number;
  procedure update_profile(p_user_id    in number,
                           p_first_name in varchar2,
                           p_last_name  in varchar2,
                           p_phone      in varchar2,
                           p_timezone   in varchar2,
                           p_locale     in varchar2);
  procedure lock_user(p_user_id in number, p_reason in varchar2);
  procedure unlock_user(p_user_id in number);
  procedure deactivate_user(p_user_id in number);
  procedure reactivate_user(p_user_id in number);
  -- Issues a RESET token + e-mail; never mails a password (rule A-08 family).
  procedure admin_reset_password(p_user_id in number);
  function count_active_users(p_tenant_id in number) return number;
  function is_seat_available(p_tenant_id in number) return boolean;
  -- Shared by invite/reset: builds token, stores hash, queues the link mail.
  procedure issue_token(p_user_id     in number,
                        p_purpose     in varchar2, -- RESET | INVITE
                        p_created_via in varchar2 default 'ADMIN');
end pkg_users;
/
create or replace package body pkg_users as
  procedure assert_can_manage is
  begin
    if not (pkg_security.has_permission('TENANT.MANAGE_USERS') or
        sys_context('app_ctx', 'admin_mode') = 'Y') then
      pkg_error.raise_business('TMS-1002');
    end if;
  end;
  function count_active_users(p_tenant_id in number) return number is
    l_n number;
  begin
    select count(*)
      into l_n
      from app_users
     where tenant_id = p_tenant_id
       and status = 'ACTIVE'
       and deleted_yn = 'N';
    return l_n;
  end;
  function count_reserved(p_tenant_id in number) return number is
    l_n number;
  begin
    select count(*)
      into l_n
      from app_users
     where tenant_id = p_tenant_id
       and status in ('ACTIVE', 'INVITED')
       and deleted_yn = 'N';
    return l_n;
  end;
  function is_seat_available(p_tenant_id in number) return boolean is
    l_seats tenants.seats_purchased%type;
  begin
    select seats_purchased
      into l_seats
      from tenants
     where tenant_id = p_tenant_id;
    -- INVITED users reserve a seat too: an invite that can never activate
    -- is a support ticket waiting to happen.
    return count_reserved(p_tenant_id) < l_seats;
  end;
  function get_seats(p_tenant_id in number) return varchar2 is
    l_seats tenants.seats_purchased%type;
  begin
    select seats_purchased
      into l_seats
      from tenants
     where tenant_id = p_tenant_id;
    return to_char(l_seats);
  end;
  procedure issue_token(p_user_id     in number,
                        p_purpose     in varchar2,
                        p_created_via in varchar2 default 'ADMIN') is
    l_raw     varchar2(64) := pkg_security.random_token;
    l_minutes pls_integer;
    l_email   app_users.email%type;
    l_base    varchar2(500) := pkg_config.get_text('APP.BASE_URL');
    l_link    varchar2(700);
  begin
    select email into l_email from app_users where user_id = p_user_id;
    l_minutes := case p_purpose
                   when 'INVITE' then
                    7 * 24 * 60
                   else
                    pkg_config.get_number('AUTH.RESET_TOKEN_MINUTES')
                 end;
    insert into password_resets
      (tenant_id,
       user_id,
       purpose,
       token_hash,
       expires_at,
       created_via,
       requested_ip)
    values
      (pkg_security.get_tenant_id,
       p_user_id,
       p_purpose,
       pkg_security.hash_token(l_raw),
       systimestamp + numtodsinterval(l_minutes, 'MINUTE'),
       p_created_via,
       sys_context('app_ctx', 'ip_address'));
    -- Deep link into the public reset/accept page (page 9996, Chapter 10).
    l_link := l_base || '/r/100/9996?p9996_token=' || l_raw;
    -- Minimal template; the notification-template engine replaces this
    -- rendering in the next project phase (TDS 8.2 PKG_EMAIL extensions).
    declare
      l_ignore number;
    begin
      l_ignore := pkg_email.queue_mail(p_to        => l_email,
                                       p_subject   => case p_purpose
                                                        when 'INVITE' then
                                                         'You are invited to Carrier TMS'
                                                        else
                                                         'Carrier TMS password reset'
                                                      end,
                                       p_body_html => to_clob('<p>Use the link below. It can be used once and expires.</p>' ||
                                                              '<p><a href="' ||
                                                              l_link || '">' ||
                                                              l_link ||
                                                              '</a></p>'),
                                       p_template  => 'AUTH_' || p_purpose);
    end;
    -- NOTE: l_raw goes out of scope here and is never stored (TDS 6.6).
  end;
  function invite_user(p_email      in varchar2,
                       p_first_name in varchar2,
                       p_last_name  in varchar2,
                       p_role_codes in varchar2,
                       p_tenant_id  in number default null,
                       p_user_type  in varchar2 default 'STAFF')
    return number is
    l_tenant  number := nvl(p_tenant_id, pkg_security.get_tenant_id);
    l_email   varchar2(320) := pkg_util.normalize_email(p_email);
    l_user_id app_users.user_id%type;
  begin
    assert_can_manage;
    if not pkg_util.is_valid_email(l_email) then
      pkg_error.raise_business('TMS-2001', p_email);
    end if;
    if p_user_type in ('STAFF', 'DRIVER') and
       not is_seat_available(l_tenant) then
      pkg_error.raise_business('TMS-2002', get_seats(l_tenant));
    end if;
    insert into app_users
      (tenant_id, email, first_name, last_name, user_type, status)
    values
      (l_tenant,
       l_email,
       trim(p_first_name),
       trim(p_last_name),
       p_user_type,
       'INVITED')
    returning user_id into l_user_id;
    for r in (select column_value code
                from table(apex_string.split(p_role_codes, ':'))) loop
      pkg_roles.grant_role(l_user_id, r.code);
    end loop;
    issue_token(l_user_id, 'INVITE', 'ADMIN');
    pkg_audit.log_action('USER', l_user_id, 'INSERT', l_email);
    return l_user_id;
  exception
    when dup_val_on_index then
      -- APP_USERS_UK1 race
      pkg_error.raise_business('TMS-2001', l_email);
    when others then
      if sqlcode = pkg_error.c_business_errnum then
        raise;
      end if;
      pkg_error.handle_unexpected('pkg_users.invite_user');
  end;
  procedure update_profile(p_user_id    in number,
                           p_first_name in varchar2,
                           p_last_name  in varchar2,
                           p_phone      in varchar2,
                           p_timezone   in varchar2,
                           p_locale     in varchar2) is
    l_old   app_users%rowtype;
    l_phone varchar2(20);
  begin
    -- Self-service or managers (dynamic authorization as data condition).
    if p_user_id <> pkg_security.get_user_id then
      assert_can_manage;
    end if;
    select * into l_old from app_users where user_id = p_user_id;
    l_phone := case
                 when p_phone is null then
                  null
                 else
                  pkg_util.normalize_phone_e164(p_phone)
               end;
    if p_phone is not null and l_phone is null then
      pkg_error.raise_business('TMS-2001', p_phone); -- reuse invalid-format code
    end if;
    update app_users
       set first_name  = trim(p_first_name),
           last_name   = trim(p_last_name),
           phone       = l_phone,
           timezone    = p_timezone,
           locale      = nvl(p_locale, locale),
           updated_at  = systimestamp,
           updated_by  = pkg_security.get_user_id,
           row_version = row_version + 1
     where user_id = p_user_id;
    pkg_audit.chg_init;
    pkg_audit.chg_add('FIRST_NAME', l_old.first_name, trim(p_first_name));
    pkg_audit.chg_add('LAST_NAME', l_old.last_name, trim(p_last_name));
    pkg_audit.chg_add('PHONE', l_old.phone, l_phone);
    pkg_audit.chg_add('TIMEZONE', l_old.timezone, p_timezone);
    pkg_audit.log_changes('USER', p_user_id, 'UPDATE', l_old.email);
  exception
    when no_data_found then
      pkg_error.raise_business('TMS-1001');
    when others then
      if sqlcode = pkg_error.c_business_errnum then
        raise;
      end if;
      pkg_error.handle_unexpected('pkg_users.update_profile');
  end;
  procedure lock_user(p_user_id in number, p_reason in varchar2) is
  begin
    assert_can_manage;
    update app_users
       set is_locked_yn = 'Y',
           locked_at    = systimestamp,
           lock_reason  = substr(nvl(p_reason, 'ADMIN'), 1, 200),
           updated_at   = systimestamp,
           updated_by   = pkg_security.get_user_id,
           row_version  = row_version + 1
     where user_id = p_user_id
       and is_locked_yn = 'N';
    if sql%rowcount > 0 then
      pkg_audit.log_action('USER', p_user_id, 'LOCK', p_reason);
    end if;
  end;
  procedure unlock_user(p_user_id in number) is
  begin
    if not (pkg_security.has_permission('SECURITY.UNLOCK_USERS') or
        sys_context('app_ctx', 'admin_mode') = 'Y') then
      pkg_error.raise_business('TMS-1002');
    end if;
    update app_users
       set is_locked_yn       = 'N',
           locked_at          = null,
           lock_reason        = null,
           failed_login_count = 0,
           updated_at         = systimestamp,
           updated_by         = pkg_security.get_user_id,
           row_version        = row_version + 1
     where user_id = p_user_id
       and is_locked_yn = 'Y';
    if sql%rowcount > 0 then
      pkg_audit.log_action('USER', p_user_id, 'UNLOCK');
    end if;
  end;
  procedure deactivate_user(p_user_id in number) is
  begin
    assert_can_manage;
    if p_user_id = pkg_security.get_user_id then
      pkg_error.raise_business('TMS-2003');
    end if;
    update app_users
       set status         = 'DEACTIVATED',
           deactivated_at = systimestamp,
           updated_at     = systimestamp,
           updated_by     = pkg_security.get_user_id,
           row_version    = row_version + 1
     where user_id = p_user_id
       and status in ('ACTIVE', 'INVITED');
    if sql%rowcount = 0 then
      pkg_error.raise_business('TMS-1001');
    end if;
    pkg_audit.log_action('USER', p_user_id, 'DEACTIVATE');
    -- Lockout is already effective: the sentry rejects DEACTIVATED users on
    -- their next request (TDS 13.3).
    -- Session chapter adds here: pkg_session.kill_user_sessions(p_user_id,'DEACTIVATION');
  exception
    when others then
      if sqlcode = pkg_error.c_business_errnum then
        raise;
      end if;
      pkg_error.handle_unexpected('pkg_users.deactivate_user');
  end;
  procedure reactivate_user(p_user_id in number) is
    l_tenant app_users.tenant_id%type;
  begin
    assert_can_manage;
    select tenant_id
      into l_tenant
      from app_users
     where user_id = p_user_id;
    if not is_seat_available(l_tenant) then
      pkg_error.raise_business('TMS-2002', get_seats(l_tenant));
    end if;
    update app_users
       set status         = 'ACTIVE',
           deactivated_at = null,
           updated_at     = systimestamp,
           updated_by     = pkg_security.get_user_id,
           row_version    = row_version + 1
     where user_id = p_user_id
       and status = 'DEACTIVATED';
    if sql%rowcount > 0 then
      pkg_audit.log_action('USER', p_user_id, 'REACTIVATE');
    end if;
  exception
    when no_data_found then
      pkg_error.raise_business('TMS-1001');
    when others then
      if sqlcode = pkg_error.c_business_errnum then
        raise;
      end if;
      pkg_error.handle_unexpected('pkg_users.reactivate_user');
  end;
  procedure admin_reset_password(p_user_id in number) is
  begin
    assert_can_manage;
    update app_users
       set must_change_password_yn = 'Y',
           updated_at              = systimestamp,
           updated_by              = pkg_security.get_user_id,
           row_version             = row_version + 1
     where user_id = p_user_id;
    issue_token(p_user_id, 'RESET', 'ADMIN');
    pkg_audit.log_action('USER', p_user_id, 'ADMIN_PWD_RESET');
  end;
end pkg_users;
/
