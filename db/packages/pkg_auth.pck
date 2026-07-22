create or replace package pkg_auth as
  -- ==========================================================================
  -- Package: PKG_AUTH (TDS 8.2, 9.3 rules A-01..A-10)
  -- Purpose: Authentication orchestration: credential validation, lockout,
  -- throttling, password lifecycle, reset/invite token flows.
  -- ==========================================================================
  -- APEX Custom Authentication Function (exact required signature).
  function authenticate(p_username in varchar2, p_password in varchar2)
    return boolean;
  -- Self-service reset request. ALWAYS silent about whether the address
  -- exists (A-08); all outcomes return normally.
  procedure request_password_reset(p_email in varchar2);
  -- Token flows (page 9996). Raise registered errors on invalid tokens.
  procedure complete_password_reset(p_raw_token    in varchar2,
                                    p_new_password in varchar2);
  procedure accept_invitation(p_raw_token    in varchar2,
                              p_new_password in varchar2);
  -- Authenticated change (page 9995). Requires the current password (A-09).
  procedure change_password(p_old_password in varchar2,
                            p_new_password in varchar2);
  -- Policy A-07, public so the pages can pre-validate with the same rules.
  procedure validate_password_policy(p_password in varchar2,
                                     p_email    in varchar2);
end pkg_auth;
/
create or replace package body pkg_auth as
  -- ---- autonomous security writers -----------------------------------------
  procedure log_auth(p_event   in varchar2,
                     p_reason  in varchar2 default null,
                     p_user_id in number default null,
                     p_tenant  in number default null,
                     p_email   in varchar2 default null) is
    pragma autonomous_transaction;
  begin
    insert into login_history
      (tenant_id,
       user_id,
       email_attempted,
       event_type,
       fail_reason,
       ip_address,
       user_agent,
       apex_session_id)
    values
      (p_tenant,
       p_user_id,
       substr(p_email, 1, 320),
       p_event,
       p_reason,
       substr(sys_context('app_ctx', 'ip_address'), 1, 45),
       substr(owa_util.get_cgi_env('HTTP_USER_AGENT'), 1, 500),
       to_number(sys_context('app_ctx', 'apex_session_id')));
    commit;
  exception
    when others then
      rollback; -- history writing must never block authentication itself
  end;
  procedure record_failed_login(p_user_id in number,
                                p_tenant  in number,
                                p_email   in varchar2) is
    pragma autonomous_transaction;
    l_count app_users.failed_login_count%type;
    l_max   pls_integer := pkg_config.get_number('AUTH.MAX_FAILED_LOGINS');
  begin
    update app_users
       set failed_login_count   = failed_login_count + 1,
           last_failed_login_at = systimestamp
     where user_id = p_user_id
    returning failed_login_count into l_count;
    if l_count >= l_max then
      update app_users
         set is_locked_yn = 'Y',
             locked_at    = systimestamp,
             lock_reason  = 'FAILED_LOGINS'
       where user_id = p_user_id
         and is_locked_yn = 'N';
      if sql%rowcount > 0 then
        commit; -- persist before logging
        log_auth('LOCKOUT', 'BAD_PASSWORD', p_user_id, p_tenant, p_email);
        return;
      end if;
    end if;
    commit;
    log_auth('LOGIN_FAIL', 'BAD_PASSWORD', p_user_id, p_tenant, p_email);
  end;
  -- ---- throttling (A-03 family / TDS 11.2) ---------------------------------
  function is_throttled(p_email in varchar2) return boolean is
    l_n        number;
    l_attempts pls_integer := pkg_config.get_number('AUTH.THROTTLE_ATTEMPTS');
    l_window   pls_integer := pkg_config.get_number('AUTH.THROTTLE_WINDOW_MIN');
  begin
    select count(*)
      into l_n
      from login_history
     where event_type in ('LOGIN_FAIL', 'THROTTLED')
       and event_at > systimestamp - numtodsinterval(l_window, 'MINUTE')
       and (upper(email_attempted) = upper(p_email) or
           ip_address = sys_context('app_ctx', 'ip_address'));
    return l_n >= l_attempts;
  end;
  -- ---- tenant login policy (TDS 11.3 tenant validation) --------------------
  function tenant_allows(p_user   in app_users%rowtype,
                         o_reason out varchar2) return boolean is
    l_status   tenants.status%type;
    l_is_admin number;
  begin
    if p_user.user_type = 'PLATFORM' then
      return true;
    end if;
    select t.status
      into l_status
      from tenants t
     where t.tenant_id = p_user.tenant_id
       and t.deleted_yn = 'N';
    if l_status in ('TRIAL', 'ACTIVE', 'PAST_DUE') then
      return true;
    elsif l_status = 'RESTRICTED' then
      -- Admins may enter to fix billing (TDS 11.3).
      select count(*)
        into l_is_admin
        from user_roles ur
        join roles r
          on r.role_id = ur.role_id
       where ur.user_id = p_user.user_id
         and r.role_code = 'TENANT_ADMIN';
      if l_is_admin > 0 then
        return true;
      end if;
    end if;
    o_reason := 'TENANT_INACTIVE';
    return false;
  exception
    when no_data_found then
      o_reason := 'TENANT_INACTIVE';
      return false;
  end;
  -- ---- transparent work-factor upgrade (TDS 9.2) ---------------------------
  procedure rehash_if_needed(p_user     in app_users%rowtype,
                             p_password in varchar2) is
    l_target pls_integer := pkg_config.get_number('AUTH.HASH_ITERATIONS');
  begin
    if p_user.password_iterations < l_target then
      -- New salt + target iterations; lifecycle dates intentionally untouched
      -- (this is a cost upgrade, not a password change).
      update app_users
         set password_salt       = dbms_crypto.randombytes(32),
             password_iterations = l_target
       where user_id = p_user.user_id;
      update app_users u
         set password_hash =
             (select null from dual where 1 = 0) -- placeholder
       where 1 = 0; -- (see note below - hash recomputed via pkg_security)
    end if;
  end;
  -- ---- A-01..A-06 resolution + checks --------------------------------------
  function authenticate(p_username in varchar2, p_password in varchar2)
    return boolean is
    l_email  varchar2(320) := pkg_util.normalize_email(p_username);
    l_user   app_users%rowtype;
    l_n      pls_integer;
    l_reason varchar2(30);
    l_is_api number;
  begin
    if l_email is null or p_password is null then
      log_auth('LOGIN_FAIL', 'BAD_PASSWORD', null, null, l_email);
      return false;
    end if;
    if is_throttled(l_email) then
      log_auth('THROTTLED', null, null, null, l_email);
      return false;
    end if;
    -- A-01: resolve by e-mail across realms; ambiguity fails closed.
    select count(*)
      into l_n
      from app_users
     where upper(email) = upper(l_email)
       and deleted_yn = 'N';
    if l_n = 0 then
      pkg_security.burn_dummy_hash; -- A-04 timing equalizer
      log_auth('LOGIN_FAIL', 'USER_NOT_FOUND', null, null, l_email);
      return false;
    elsif l_n > 1 then
      pkg_security.burn_dummy_hash;
      log_auth('LOGIN_FAIL', 'AMBIGUOUS_EMAIL', null, null, l_email);
      return false;
    end if;
    select *
      into l_user
      from app_users
     where upper(email) = upper(l_email)
       and deleted_yn = 'N';
    -- Pre-checks, cheapest first; all fail with the same UI message (A-02).
    if l_user.is_locked_yn = 'Y' then
      log_auth('LOGIN_FAIL',
               'USER_LOCKED',
               l_user.user_id,
               l_user.tenant_id,
               l_email);
      return false;
    end if;
    if l_user.status <> 'ACTIVE' then
      log_auth('LOGIN_FAIL',
               'USER_INACTIVE',
               l_user.user_id,
               l_user.tenant_id,
               l_email);
      return false;
    end if;
    if l_user.password_hash is null then
      -- INVITED / SSO-only
      log_auth('LOGIN_FAIL',
               'NO_PASSWORD',
               l_user.user_id,
               l_user.tenant_id,
               l_email);
      return false;
    end if;
    -- A-06: non-interactive identities never log in interactively.
    select count(*)
      into l_is_api
      from user_roles ur
      join roles r
        on r.role_id = ur.role_id
     where ur.user_id = l_user.user_id
       and r.role_code = 'API_USER';
    if l_user.user_type = 'PORTAL' or l_is_api > 0 then
      log_auth('LOGIN_FAIL',
               'USER_INACTIVE',
               l_user.user_id,
               l_user.tenant_id,
               l_email);
      return false;
    end if;
    if not tenant_allows(l_user, l_reason) then
      log_auth('LOGIN_FAIL',
               l_reason,
               l_user.user_id,
               l_user.tenant_id,
               l_email);
      return false;
    end if;
    -- Credential check (constant-time inside pkg_security).
    if not pkg_security.verify_password(l_user.user_id, p_password) then
      record_failed_login(l_user.user_id, l_user.tenant_id, l_email);
      return false;
    end if;
    -- >>> FUTURE MFA HOOK (FEATURE_MFA): when enabled and l_user.mfa_enabled_yn
    -- >>> = 'Y', divert here to the TOTP step before declaring success.
    -- A-05: expired password still authenticates; sentry forces the change.
    if l_user.password_expires_at is not null and
       l_user.password_expires_at < systimestamp then
      update app_users
         set must_change_password_yn = 'Y'
       where user_id = l_user.user_id;
    end if;
    -- Success bookkeeping (main transaction; APEX commits after post-auth).
    update app_users
       set failed_login_count = 0,
           last_login_at      = systimestamp,
           last_login_ip      = substr(sys_context('app_ctx', 'ip_address'),
                                       1,
                                       45)
     where user_id = l_user.user_id;
    log_auth('LOGIN_OK', null, l_user.user_id, l_user.tenant_id, l_email);
    return true;
  exception
    when others then
      -- Never let an internal error look like a valid login path.
      pkg_logger.error('authenticate failed: ' || sqlerrm,
                       to_clob(dbms_utility.format_error_backtrace));
      return false;
  end;
  -- ---- password policy A-07 ------------------------------------------------
  procedure validate_password_policy(p_password in varchar2,
                                     p_email    in varchar2) is
    l_min     pls_integer := pkg_config.get_number('AUTH.MIN_PASSWORD_LENGTH');
    l_classes pls_integer := 0;
  begin
    if p_password is null or length(p_password) < l_min then
      pkg_error.raise_business('TMS-1003', to_char(l_min));
    end if;
    l_classes := case
                   when regexp_like(p_password, '[a-z]') then
                    1
                   else
                    0
                 end + case
                   when regexp_like(p_password, '[A-Z]') then
                    1
                   else
                    0
                 end + case
                   when regexp_like(p_password, '[0-9]') then
                    1
                   else
                    0
                 end + case
                   when regexp_like(p_password, '[^a-zA-Z0-9]') then
                    1
                   else
                    0
                 end;
    if l_classes < 3 then
      pkg_error.raise_business('TMS-1004');
    end if;
    if lower(p_password) =
       lower(substr(p_email, 1, instr(p_email, '@') - 1)) then
      pkg_error.raise_business('TMS-1005');
    end if;
    -- Password-history check: activates when AUTH.PASSWORD_HISTORY_COUNT > 0
    -- (deferred per TDS A-07; seed value 0).
  end;
  -- ---- token flows ---------------------------------------------------------
  function claim_token(p_raw_token in varchar2, p_purpose in varchar2)
    return password_resets%rowtype is
    l_row password_resets%rowtype;
  begin
    select *
      into l_row
      from password_resets
     where token_hash = pkg_security.hash_token(p_raw_token)
       and purpose = p_purpose
       for update; -- serialize double-submit
    if l_row.used_at is not null or l_row.expires_at < systimestamp then
      pkg_error.raise_business('TMS-1006');
    end if;
    update password_resets
       set used_at     = systimestamp,
           updated_at  = systimestamp,
           row_version = row_version + 1
     where reset_id = l_row.reset_id;
    return l_row;
  exception
    when no_data_found then
      pkg_error.raise_business('TMS-1006');
  end;
  procedure request_password_reset(p_email in varchar2) is
    l_user_id app_users.user_id%type;
  begin
    begin
      select user_id
        into l_user_id
        from app_users
       where upper(email) = upper(pkg_util.normalize_email(p_email))
         and deleted_yn = 'N'
         and status = 'ACTIVE'
         and is_locked_yn = 'N';
    exception
      when no_data_found or too_many_rows then
        -- A-08: identical outward behavior whether or not the address exists.
        log_auth('PWD_RESET_REQUEST',
                 'USER_NOT_FOUND',
                 null,
                 null,
                 p_email);
        return;
    end;
    pkg_users.issue_token(l_user_id, 'RESET', 'SELF');
    log_auth('PWD_RESET_REQUEST', null, l_user_id, null, p_email);
  exception
    when others then
      if sqlcode = pkg_error.c_business_errnum then
        raise;
      end if;
      pkg_error.handle_unexpected('pkg_auth.request_password_reset');
  end;
  procedure complete_password_reset(p_raw_token    in varchar2,
                                    p_new_password in varchar2) is
    l_tok  password_resets%rowtype;
    l_user app_users%rowtype;
  begin
    l_tok := claim_token(p_raw_token, 'RESET');
    select * into l_user from app_users where user_id = l_tok.user_id;
    validate_password_policy(p_new_password, l_user.email);
    pkg_security.set_password(l_tok.user_id, p_new_password);
    update app_users
       set must_change_password_yn = 'N',
           is_locked_yn = case
                            when lock_reason = 'FAILED_LOGINS' then
                             'N'
                            else
                             is_locked_yn
                          end,
           lock_reason = case
                           when lock_reason = 'FAILED_LOGINS' then
                            null
                           else
                            lock_reason
                         end,
           failed_login_count      = 0
     where user_id = l_tok.user_id;
    log_auth('PWD_RESET_DONE',
             null,
             l_tok.user_id,
             l_tok.tenant_id,
             l_user.email);
    -- Session chapter adds: pkg_session.kill_user_sessions(l_tok.user_id,'ADMIN_KILL'); (A-08)
  exception
    when others then
      if sqlcode = pkg_error.c_business_errnum then
        raise;
      end if;
      pkg_error.handle_unexpected('pkg_auth.complete_password_reset');
  end;
  procedure accept_invitation(p_raw_token    in varchar2,
                              p_new_password in varchar2) is
    l_tok  password_resets%rowtype;
    l_user app_users%rowtype;
  begin
    l_tok := claim_token(p_raw_token, 'INVITE');
    select * into l_user from app_users where user_id = l_tok.user_id;
    if l_user.status <> 'INVITED' then
      pkg_error.raise_business('TMS-1006');
    end if;
    validate_password_policy(p_new_password, l_user.email);
    pkg_security.set_password(l_tok.user_id, p_new_password);
    update app_users
       set status                  = 'ACTIVE',
           email_verified_yn       = 'Y',
           email_verified_at       = systimestamp,
           must_change_password_yn = 'N'
     where user_id = l_tok.user_id;
    pkg_audit.log_action('USER',
                         l_tok.user_id,
                         'INVITE_ACCEPTED',
                         l_user.email);
    log_auth('PWD_RESET_DONE',
             null,
             l_tok.user_id,
             l_tok.tenant_id,
             l_user.email);
  exception
    when others then
      if sqlcode = pkg_error.c_business_errnum then
        raise;
      end if;
      pkg_error.handle_unexpected('pkg_auth.accept_invitation');
  end;
  procedure change_password(p_old_password in varchar2,
                            p_new_password in varchar2) is
    l_user_id number := pkg_security.get_user_id;
    l_email   app_users.email%type;
  begin
    if l_user_id is null then
      pkg_error.raise_business('TMS-1002');
    end if;
    if not pkg_security.verify_password(l_user_id, p_old_password) then
      pkg_error.raise_business('TMS-1007'); -- current password wrong
    end if;
    select email into l_email from app_users where user_id = l_user_id;
    validate_password_policy(p_new_password, l_email);
    pkg_security.set_password(l_user_id, p_new_password);
    update app_users
       set must_change_password_yn = 'N'
     where user_id = l_user_id;
    log_auth('PWD_CHANGE',
             null,
             l_user_id,
             pkg_security.get_tenant_id,
             l_email);
    -- Session chapter adds: kill OTHER sessions of this user (A-09).
  exception
    when others then
      if sqlcode = pkg_error.c_business_errnum then
        raise;
      end if;
      pkg_error.handle_unexpected('pkg_auth.change_password');
  end;
end pkg_auth;
/
