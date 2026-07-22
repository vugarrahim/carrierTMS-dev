create or replace package pkg_error as
 -- ==========================================================================
 -- Package: PKG_ERROR
 -- Purpose: Error framework (TDS 14): registered business errors, unexpected
 -- error handling with reference IDs, APEX error handling function.
 -- Errors: business errors raise ORA-20100 with text 'TMS-nnnn: <message>'
 -- unexpected errors raise ORA-20999 with a reference id.
 -- ==========================================================================
 c_business_errnum constant pls_integer := -20100;
 c_generic_errnum constant pls_integer := -20999;
 -- Raise a registered business error; %1..%3 in USER_MESSAGE are replaced.
 procedure raise_business (p_code in varchar2,
 p1 in varchar2 default null,
 p2 in varchar2 default null,
 p3 in varchar2 default null);
 -- Outermost WHEN OTHERS handler for every public procedure: logs full
 -- detail, re-raises generic error carrying the APP_LOG reference id.
 procedure handle_unexpected (p_module in varchar2);
 -- Registered user message for a code (used by UI helpers / tests).
 function get_user_message (p_code in varchar2) return varchar2;
 -- Translate any (sqlcode, sqlerrm) into a user-safe display string:
 -- TMS-coded messages pass through; named-constraint violations map via
 -- ERROR_CATALOG.CONSTRAINT_NAME; everything else -> generic text.
 function to_friendly (p_sqlcode in number,
 p_sqlerrm in varchar2) return varchar2;
 -- APEX Error Handling Function (application definition; set in App 100/900).
 function apex_error_handler (p_error in apex_error.t_error)
 return apex_error.t_error_result;
end pkg_error;
/
create or replace package body pkg_error as
 function fetch_catalog (p_code in varchar2) return error_catalog%rowtype is
 l_row error_catalog%rowtype;
 begin
 select * into l_row from error_catalog where error_code = p_code;
 return l_row;
 exception when no_data_found then
 l_row.error_code := null;
 return l_row;
 end;
 function substitute (p_msg in varchar2, p1 in varchar2,
 p2 in varchar2, p3 in varchar2) return varchar2 is
 begin
 return replace(replace(replace(p_msg, '%1', p1), '%2', p2), '%3', p3);
 end;
 procedure raise_business (p_code in varchar2,
 p1 in varchar2 default null,
 p2 in varchar2 default null,
 p3 in varchar2 default null) is
 l_row error_catalog%rowtype := fetch_catalog(p_code);
 l_msg varchar2(600);
 begin
 if l_row.error_code is null then
 -- Unregistered code = a developer bug worth knowing about, but the user
 -- still gets a sane message.
 pkg_logger.warn('Unregistered error code raised: ' || p_code);
 l_msg := 'Operation could not be completed.';
 else
 l_msg := substitute(l_row.user_message, p1, p2, p3);
 end if;
 raise_application_error(c_business_errnum, p_code || ': ' || l_msg);
 end;
 procedure handle_unexpected (p_module in varchar2) is
 l_ref number;
 begin
 l_ref := pkg_logger.error_ref(
 p_message => 'Unexpected error in ' || p_module || ': ' || sqlerrm,
 p_detail => to_clob(
 'error_stack: ' || dbms_utility.format_error_stack || chr(10)
 || 'error_backtrace: ' || dbms_utility.format_error_backtrace || chr(10)
 || 'call_stack: ' || dbms_utility.format_call_stack));
 raise_application_error(c_generic_errnum,
 'TMS-9999: An unexpected error occurred. Reference: ' || nvl(to_char(l_ref),'n/a'));
 end;
 function get_user_message (p_code in varchar2) return varchar2 is
 l_row error_catalog%rowtype := fetch_catalog(p_code);
 begin
 return nvl(l_row.user_message, 'Operation could not be completed.');
 end;
 function to_friendly (p_sqlcode in number,
 p_sqlerrm in varchar2) return varchar2 is
 l_constraint varchar2(128);
 l_msg error_catalog.user_message%type;
 begin
 -- 1) Our own raised errors already carry the safe text after 'TMS-nnnn: '.
 if regexp_like(p_sqlerrm, 'TMS-[0-9]{4}: ') then
 return regexp_substr(p_sqlerrm, 'TMS-[0-9]{4}: .*$');
 end if;
 -- 2) Constraint violations that escaped package validation (races):
 -- ORA-00001 unique, ORA-02290 check, ORA-02291/02292 FK.
 if p_sqlcode in (-1, -2290, -2291, -2292) then
 l_constraint := regexp_substr(p_sqlerrm, '\.([A-Z0-9_#$]+)\)', 1, 1, null, 1);
 if l_constraint is not null then
 begin
 select user_message into l_msg
 from error_catalog where constraint_name = l_constraint;
 return l_msg;
 exception when no_data_found then null;
 end;
 end if;
 end if;
 -- 3) Everything else: never show ORA text to users.
 return 'An unexpected error occurred. Please try again or contact support.';
 end;
 function apex_error_handler (p_error in apex_error.t_error)
 return apex_error.t_error_result is
 l_result apex_error.t_error_result;
 l_ref number;
 begin
 l_result := apex_error.init_error_result(p_error => p_error);
 if p_error.is_internal_error then
 -- APEX-internal (404s, session errors): keep APEX behavior, hide details.
 if not p_error.is_common_runtime_error then
 l_ref := pkg_logger.error_ref('APEX internal error: '
 || p_error.message, to_clob(p_error.error_backtrace));
 l_result.message := 'An unexpected error occurred. Reference: '
 || nvl(to_char(l_ref), 'n/a');
 l_result.additional_info := null;
 end if;
 else
 -- Database/process errors: translate; log only the unexpected ones
 -- (handle_unexpected already logged errors that came through packages).
 l_result.message := to_friendly(p_error.ora_sqlcode, p_error.message); 
 if not regexp_like(p_error.message, 'TMS-[0-9]{4}: ') then
 l_ref := pkg_logger.error_ref('Unhandled page error: ' || p_error.message,
 to_clob(p_error.error_backtrace));
 end if;
 l_result.display_location := apex_error.c_inline_in_notification;
 end if;
 return l_result;
 end;
end pkg_error;
/
