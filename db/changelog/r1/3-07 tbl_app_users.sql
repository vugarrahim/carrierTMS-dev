create table app_users ( 
  user_id                 number(18) generated always as identity not null, 
  user_guid               raw(16)      default sys_guid()    not null, 
  tenant_id               number(18), 
  email                   varchar2(320)                      not null, 
  first_name              varchar2(100)                      not null, 
  last_name               varchar2(100)                      not null, 
  display_name            varchar2(200), 
  phone                   varchar2(20), 
  user_type               varchar2(20) default 'STAFF'       not null, 
  status                  varchar2(20) default 'INVITED'     not null, 
  is_locked_yn            varchar2(1)  default 'N'           not null, 
  locked_at               timestamp with time zone, 
  lock_reason             varchar2(200), 
  failed_login_count      number(3)    default 0             not null, 
  last_failed_login_at    timestamp with time zone, 
  password_hash           varchar2(500), 
  password_salt           raw(32), 
  password_iterations     number(7), 
  password_changed_at     timestamp with time zone, 
  password_expires_at     timestamp with time zone, 
  must_change_password_yn varchar2(1)  default 'Y'           not null, 
  email_verified_yn       varchar2(1)  default 'N'           not null, 
  email_verified_at       timestamp with time zone, 
  mfa_enabled_yn          varchar2(1)  default 'N'           not null, 
  mfa_secret              varchar2(200), 
  last_login_at           timestamp with time zone, 
  last_login_ip           varchar2(45), 
  timezone                varchar2(64), 
  locale                  varchar2(10) default 'en-US'       not null, 
  avatar_attachment_id    number(18), 
  deactivated_at          timestamp with time zone, 
  deleted_yn              varchar2(1)  default 'N'           not null, 
  deleted_at              timestamp with time zone, 
  deleted_by              number(18), 
  created_at   timestamp with time zone default systimestamp not null, 
  created_by   number(18) 
               default coalesce(to_number(sys_context('app_ctx','user_id')), -1) 
                                                             not null, 
  updated_at   timestamp with time zone, 
  updated_by   number(18), 
  row_version  number(9)    default 1                        not null, 
  constraint app_users_pk  primary key (user_id), 
  constraint app_users_uk2 unique (user_guid), 
  constraint app_users_fk1_tenants foreign key (tenant_id) 
             references tenants (tenant_id), 
  constraint app_users_ck1 check (user_type in ('STAFF','DRIVER','PLATFORM','PORTAL')), 
  constraint app_users_ck2 check (status in ('INVITED','ACTIVE','DEACTIVATED','EXPIRED')), 
  constraint app_users_ck3 check (is_locked_yn in ('Y','N')), 
  constraint app_users_ck4 check (must_change_password_yn in ('Y','N')), 
  constraint app_users_ck5 check (email_verified_yn in ('Y','N')), 
  constraint app_users_ck6 check (mfa_enabled_yn in ('Y','N')), 
  constraint app_users_ck7 check (deleted_yn in ('Y','N')), 
  constraint app_users_ck8 check (failed_login_count >= 0), 
  -- Realm rule (TDS 4.2): only PLATFORM users may have no tenant. 
  constraint app_users_ck9 check (tenant_id is not null or user_type = 'PLATFORM'), 
  constraint app_users_ck10 check (deleted_yn = 'N' 
                                   or (deleted_at is not null and deleted_by is not null)) 
); 
  -- UK1: e-mail unique per realm, among non-deleted users only (TDS 4.2). -- NVL(tenant_id,0) folds all platform users into realm 0. 
create unique index app_users_uk1 on app_users ( 
  case when deleted_yn = 'N' then nvl(tenant_id, 0) end, 
  case when deleted_yn = 'N' then upper(email)      end 
); 
  
create index app_users_ix1 on app_users (tenant_id, status); 
create index app_users_ix2 on app_users (password_expires_at); 
  
comment on table  app_users is 
  'Application identity store (TDS 4.2). Custom authentication only; never APEX workspace users. Writes 
only via PKG_USERS / PKG_AUTH.'; 
comment on column app_users.tenant_id           is 'Owning tenant; NULL only for PLATFORM realm (CK9). 
Reinterpreted as default tenant if multi-tenant-per-user ships (TDS 3.3).'; 
comment on column app_users.email               is 'Login identifier; compared case-insensitively via 
UK1 expression.'; 
comment on column app_users.is_locked_yn        is 'Security lock, independent of STATUS: locked user 
still counts a seat; unlock restores prior behavior exactly (TDS 4.2).'; 
comment on column app_users.password_hash       is 'PBKDF2-HMAC-SHA512 output, hex. Written only by 
PKG_SECURITY.'; 
comment on column app_users.password_salt       is 'Per-user 32-byte random salt.'; 
comment on column app_users.password_iterations is 'Per-user work factor: allows raising cost later; 
old hashes verified then transparently re-hashed at next login (TDS 9.2).'; 
comment on column app_users.mfa_secret          is 'AES-encrypted TOTP secret (key in vault). NULL 
until MFA enrollment. Never audited/logged.'; 
comment on column app_users.last_login_ip       is 'Convenience copy of the latest LOGIN_HISTORY row.';
