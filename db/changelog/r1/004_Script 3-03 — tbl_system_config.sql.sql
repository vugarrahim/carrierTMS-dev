Script 3-03 — tbl_system_config.sql (run as TMS_APP)
-- ============================================================================
-- Script:   3-03 tbl_system_config.sql
-- Purpose:  Platform-wide typed configuration registry (TDS section 6.8).
-- Run as:   TMS_APP        Rerun: NO
-- ============================================================================
create table system_config (
  config_id                 number(18) generated always as identity not null,
  config_code               varchar2(60)                       not null,
  config_value              varchar2(4000)                     not null,
  data_type                 varchar2(10)  default 'TEXT'       not null,
  description               varchar2(500)                      not null,
  is_tenant_overridable_yn  varchar2(1)   default 'N'          not null,
  is_sensitive_yn           varchar2(1)   default 'N'          not null,
  created_at   timestamp with time zone default systimestamp   not null,
  created_by   number(18)
               default coalesce(to_number(sys_context('app_ctx','user_id')), -1)
                                                               not null,
  updated_at   timestamp with time zone,
  updated_by   number(18),
  row_version  number(9)    default 1                          not null,
  constraint system_config_pk  primary key (config_id),
  constraint system_config_uk1 unique (config_code),
  constraint system_config_ck1 check (data_type in ('TEXT','NUMBER','FLAG','JSON')),
  constraint system_config_ck2 check (is_tenant_overridable_yn in ('Y','N')),
  constraint system_config_ck3 check (is_sensitive_yn in ('Y','N'))
);
 
comment on table  system_config is
  'Platform configuration registry. Read via PKG_CONFIG only (typed, cached). Secrets are NEVER stored here (TDS 16.5).';
comment on column system_config.config_code is 'Dot-namespaced key, e.g. AUTH.MAX_FAILED_LOGINS.';
comment on column system_config.data_type   is 'TEXT/NUMBER/FLAG/JSON - PKG_CONFIG validates writes and converts reads.';
comment on column system_config.is_tenant_overridable_yn is 'Y = TENANT_CONFIG may override this key.';
comment on column system_config.is_sensitive_yn is 'Y = value masked in UI/exports (still not for secrets).';