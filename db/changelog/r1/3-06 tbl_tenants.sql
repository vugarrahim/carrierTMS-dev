  create table tenants ( 
  tenant_id            number(18) generated always as identity not null, 
  tenant_guid          raw(16)      default sys_guid()     not null, 
  tenant_code          varchar2(20)                        not null, 
  company_name         varchar2(200)                       not null, 
  dba_name             varchar2(200), 
  usdot_number         varchar2(8), 
  mc_number            varchar2(8), 
  status               varchar2(20) default 'TRIAL'        not null, 
  current_plan_code    varchar2(30) default 'TRIAL'        not null, 
  trial_ends_at        timestamp with time zone, 
  seats_purchased      number(6)    default 1              not null, 
  verification_status  varchar2(20) default 'UNVERIFIED'   not null, 
  address_line1        varchar2(200), 
  city                 varchar2(100), 
  state_code           varchar2(3), 
  zip                  varchar2(10), 
  phone                varchar2(20), 
  billing_email        varchar2(320), 
  timezone             varchar2(64) default 'America/Chicago' not null, 
  logo_attachment_id   number(18),                         -- FK added in Phase 3 (attachments) 
  deleted_yn           varchar2(1)  default 'N'            not null, 
  deleted_at           timestamp with time zone, 
  deleted_by           number(18), 
  terminated_at        timestamp with time zone, 
  created_at   timestamp with time zone default systimestamp not null, 
  created_by   number(18) 
               default coalesce(to_number(sys_context('app_ctx','user_id')), -1) 
                                                           not null, 
  updated_at   timestamp with time zone, 
  updated_by   number(18), 
  row_version  number(9)    default 1                      not null, 
  constraint tenants_pk  primary key (tenant_id), 
  constraint tenants_uk2 unique (tenant_guid), 
  constraint tenants_uk3 unique (tenant_code), 
  constraint tenants_fk1_states foreign key (state_code) references states (state_code), 
  constraint tenants_ck1 check (status in 
    ('TRIAL','ACTIVE','PAST_DUE','SUSPENDED','RESTRICTED','TERMINATED')), 
  constraint tenants_ck2 check (verification_status in 
    ('UNVERIFIED','PENDING_REVIEW','VERIFIED','LAPSED','REVOKED')), 
  constraint tenants_ck3 check (deleted_yn in ('Y','N')), 
  constraint tenants_ck4 check (usdot_number is null 
                                or regexp_like(usdot_number, '^[0-9]{1,8}$')), 
  constraint tenants_ck5 check (status <> 'TRIAL' or trial_ends_at is not null), 
  constraint tenants_ck6 check (seats_purchased >= 1), 
  constraint tenants_ck7 check (deleted_yn = 'N' 
                                or (deleted_at is not null and deleted_by is not null)) 
); 
  -- UK1: USDOT unique among live, non-terminated tenants (TDS 3.2). -- CASE hides terminated/deleted rows from the index -> key becomes reusable. 
create unique index tenants_uk1 on tenants ( 
  case when status <> 'TERMINATED' and deleted_yn = 'N' then usdot_number end 
); 
  
create index tenants_ix1 on tenants (status); 
create index tenants_ix2 on tenants (upper(company_name)); 
  
comment on table  tenants is 
  'Tenant (carrier company) master. Isolation root: every tenant-scoped table FKs here. Writes only via 
PKG_TENANTS. Status machine per TDS Phase-1 9.2.'; 
comment on column tenants.tenant_guid       is 'External/API identifier. Never expose TENANT_ID in 
URLs.'; 
comment on column tenants.tenant_code       is 'Short human code for support/exports (unique).'; 
comment on column tenants.current_plan_code is 'Denormalized plan snapshot for hot-path entitlement 
checks; sole writer PKG_TENANTS (TDS 3.2 design note).'; 
comment on column tenants.seats_purchased   is 'Licensed seat snapshot; reconciled nightly against 
subscriptions.'; 
comment on column tenants.terminated_at     is 'Start of contractual data-retention window before 
purge.'; 
comment on column tenants.deleted_yn        is 'Soft delete flag; operational views filter N.';
