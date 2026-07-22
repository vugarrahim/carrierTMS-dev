create table login_history (
 login_id number(18) generated always as identity not null,
 tenant_id number(18),
 user_id number(18),
 email_attempted varchar2(320),
 event_type varchar2(30) not null,
 fail_reason varchar2(30),
 ip_address varchar2(45),
 user_agent varchar2(500),
 apex_session_id number(18),
 event_at timestamp with time zone default systimestamp not null,
 created_by number(18)
 default coalesce(to_number(sys_context('app_ctx','user_id')), -1) not null,
 constraint login_history_pk primary key (login_id),
 constraint login_history_ck1 check (event_type in
 ('LOGIN_OK','LOGIN_FAIL','LOCKOUT','UNLOCK','LOGOUT',
 'PWD_RESET_REQUEST','PWD_RESET_DONE','PWD_CHANGE',
 'SESSION_EXPIRED','FORCED_LOGOUT','THROTTLED','MFA_FAIL')),
 constraint login_history_ck2 check (fail_reason is null or fail_reason in
 ('BAD_PASSWORD','USER_NOT_FOUND','USER_LOCKED','USER_INACTIVE',
 'TENANT_INACTIVE','PASSWORD_EXPIRED','AMBIGUOUS_EMAIL','NO_PASSWORD'))
);
create index login_history_ix1 on login_history (user_id, event_at);
create index login_history_ix2 on login_history (event_at);
create index login_history_ix3 on login_history (tenant_id, event_at);
comment on table login_history is
 'Authentication journal (TDS 6.5). Append-only, no FKs (rows outlive users; inserts occur pre-auth 
via autonomous txn). UI never reveals FAIL_REASON (rule A-02).';
create table password_resets (
 reset_id number(18) generated always as identity not null,
 tenant_id number(18),
 user_id number(18) not null,
 purpose varchar2(15) default 'RESET' not null,
 token_hash varchar2(128) not null,
 expires_at timestamp with time zone not null,
 used_at timestamp with time zone,
 requested_ip varchar2(45),
 created_via varchar2(15) default 'SELF' not null,
 created_at timestamp with time zone default systimestamp not null,
 created_by number(18)
 default coalesce(to_number(sys_context('app_ctx','user_id')), -1) not null,
 updated_at timestamp with time zone,
 updated_by number(18),
 row_version number(9) default 1 not null,
 constraint password_resets_pk primary key (reset_id),
 constraint password_resets_uk1 unique (token_hash),
 constraint password_resets_fk1_app_users foreign key (user_id)
 references app_users (user_id),
 constraint password_resets_ck1 check (purpose in ('RESET','INVITE','EMAIL_VERIFY')),
 constraint password_resets_ck2 check (created_via in ('SELF','ADMIN','SYSTEM')),
 constraint password_resets_ck3 check (used_at is null or used_at >= created_at)
);
create index password_resets_ix1 on password_resets (user_id, purpose, expires_at);
comment on table password_resets is
 'Single-use expiring tokens for reset/invite/verify (TDS 6.6). Only SHA-256 hash stored; raw token 
exists only in the e-mailed link.';
create table app_sessions (
 session_id number(18) generated always as identity not null,
 session_guid raw(16) default sys_guid() not null,
 tenant_id number(18),
 user_id number(18) not null,
 apex_session_id number(18) not null,
 status varchar2(15) default 'ACTIVE' not null,
 login_at timestamp with time zone default systimestamp not null,
 last_activity_at timestamp with time zone default systimestamp not null,
 ended_at timestamp with time zone,
 end_reason varchar2(20),
 ip_address varchar2(45),
 user_agent varchar2(500),
 device_type varchar2(15),
 created_at timestamp with time zone default systimestamp not null,
 created_by number(18)
 default coalesce(to_number(sys_context('app_ctx','user_id')), -1) not null,
 updated_at timestamp with time zone,
 updated_by number(18),
 row_version number(9) default 1 not null,
 constraint app_sessions_pk primary key (session_id),
 constraint app_sessions_uk1 unique (apex_session_id),
 constraint app_sessions_uk2 unique (session_guid),
 constraint app_sessions_fk1_app_users foreign key (user_id)
 references app_users (user_id),
 constraint app_sessions_ck1 check (status in
 ('ACTIVE','LOGGED_OUT','EXPIRED','KILLED')),
 constraint app_sessions_ck2 check (end_reason is null or end_reason in
 ('LOGOUT','IDLE_TIMEOUT','MAX_LIFE','ADMIN_KILL','DEACTIVATION','NEW_LOGIN')),
 constraint app_sessions_ck3 check (device_type is null or device_type in
 ('DESKTOP','MOBILE','TABLET','API')),
 constraint app_sessions_ck4 check
 ((status = 'ACTIVE' and ended_at is null and end_reason is null)
 or (status <> 'ACTIVE' and ended_at is not null and end_reason is not null))
);
create index app_sessions_ix1 on app_sessions (user_id, status);
create index app_sessions_ix2 on app_sessions (status, last_activity_at);
comment on table app_sessions is
 'Business shadow of APEX sessions (TDS 12.1): concurrency policy, logout-everywhere, session listing, 
audit. APEX stays the technical authority.';
