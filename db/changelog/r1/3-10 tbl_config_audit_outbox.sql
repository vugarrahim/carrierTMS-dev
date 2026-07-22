create table tenant_config (
 tenant_config_id number(18) generated always as identity not null,
 tenant_id number(18)
 default to_number(sys_context('app_ctx','tenant_id')) not null,
 config_code varchar2(60) not null,
 config_value varchar2(4000) not null,
 created_at timestamp with time zone default systimestamp not null,
 created_by number(18)
 default coalesce(to_number(sys_context('app_ctx','user_id')), -1) not null,
 updated_at timestamp with time zone,
 updated_by number(18),
 row_version number(9) default 1 not null,
 constraint tenant_config_pk primary key (tenant_config_id),
 constraint tenant_config_uk1 unique (tenant_id, config_code),
 constraint tenant_config_fk1_tenants foreign key (tenant_id)
 references tenants (tenant_id)
);
comment on table tenant_config is
 'Tenant overrides of overridable SYSTEM_CONFIG keys + TENANT.* keys (TDS 6.9). Overridability 
validated by PKG_CONFIG (cross-table rule).';
create table audit_log (
 audit_id number(18) generated always as identity not null,
 tenant_id number(18),
 user_id number(18),
 action_code varchar2(40) not null,
 entity_code varchar2(30) not null,
 entity_id number(18),
 entity_label varchar2(200),
 field_changes json,
 context_info json,
 occurred_at timestamp with time zone default systimestamp not null,
 created_by number(18)
 default coalesce(to_number(sys_context('app_ctx','user_id')), -1) not null,
 constraint audit_log_pk primary key (audit_id),
 constraint audit_log_ck1 check (action_code = upper(action_code))
);
create index audit_log_ix1 on audit_log (tenant_id, entity_code, entity_id, occurred_at);
create index audit_log_ix2 on audit_log (occurred_at);
comment on table audit_log is
 'Business audit journal (TDS 13). Written ONLY by PKG_AUDIT inside the business transaction. Append￾only; sensitive fields masked as *** by the tracked-column registry. Partition-ready on OCCURRED_AT 
(convert online if volume warrants).';
create table email_outbox (
 outbox_id number(18) generated always as identity not null,
 tenant_id number(18),
 to_addr varchar2(320) not null,
 subject_text varchar2(500) not null,
 body_html clob not null,
 template_code varchar2(60),
 status varchar2(10) default 'QUEUED' not null,
 attempts number(3) default 0 not null,
 last_error varchar2(1000),
 sent_at timestamp with time zone,
 created_at timestamp with time zone default systimestamp not null,
 created_by number(18)
 default coalesce(to_number(sys_context('app_ctx','user_id')), -1) not null,
 updated_at timestamp with time zone,
 updated_by number(18),
 row_version number(9) default 1 not null,
 constraint email_outbox_pk primary key (outbox_id),
 constraint email_outbox_ck1 check (status in ('QUEUED','SENT','FAILED')),
 constraint email_outbox_ck2 check (attempts >= 0)
);
create index email_outbox_ix1 on email_outbox (status, created_at);
comment on table email_outbox is
 'Outbound e-mail journal (PKG_EMAIL): render once, queue via APEX_MAIL, retry FAILED via 
JOB_EMAIL_RETRY. Bodies never contain secrets or raw tokens... except the reset link itself, which is 
why outbox rows purge on the same schedule as PASSWORD_RESETS.';
create table notifications (
 notification_id number(18) generated always as identity not null,
 tenant_id number(18),
 user_id number(18) not null,
 event_code varchar2(60) not null,
 title_text varchar2(200) not null,
 body_text varchar2(1000),
 link_target varchar2(500),
 status varchar2(10) default 'UNREAD' not null,
 read_at timestamp with time zone,
 created_at timestamp with time zone default systimestamp not null,
 created_by number(18)
 default coalesce(to_number(sys_context('app_ctx','user_id')), -1) not null,
 updated_at timestamp with time zone,
 updated_by number(18),
 row_version number(9) default 1 not null,
 constraint notifications_pk primary key (notification_id),
 constraint notifications_fk1_app_users foreign key (user_id)
 references app_users (user_id),
 constraint notifications_ck1 check (status in ('UNREAD','READ')),
 constraint notifications_ck2 check
 ((status = 'UNREAD' and read_at is null) or (status = 'READ' and read_at is not null))
);
create index notifications_ix1 on notifications (user_id, status);
comment on table notifications is
 'In-app inbox, Phase-2 minimal shape (TDS 8.2 PKG_NOTIFICATION). Expands to the full Phase-1 
notification catalog in the next project phase without structural change.';
