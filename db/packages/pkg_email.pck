create or replace package pkg_email as
  -- ==========================================================================
  -- Package: PKG_EMAIL (minimal Phase-2 form, TDS 8.2)
  -- Purpose: Sole writer of EMAIL_OUTBOX. Queues mail; dispatch to SMTP is
  -- performed by JOB_EMAIL_RETRY (added with the auth chapter).
  -- ==========================================================================
  function queue_mail(p_to        in varchar2,
                      p_subject   in varchar2,
                      p_body_html in clob,
                      p_template  in varchar2 default null) return number;
end pkg_email;
/
create or replace package body pkg_email as
  function queue_mail(p_to        in varchar2,
                      p_subject   in varchar2,
                      p_body_html in clob,
                      p_template  in varchar2 default null) return number is
    l_id email_outbox.outbox_id%type;
  begin
    if not pkg_util.is_valid_email(p_to) then
      pkg_error.raise_business('TMS-2001', p_to); -- reuse: invalid/unusable address
    end if;
    insert into email_outbox
      (tenant_id, to_addr, subject_text, body_html, template_code)
    values
      (pkg_security.get_tenant_id,
       lower(trim(p_to)),
       substr(p_subject, 1, 500),
       p_body_html,
       p_template)
    returning outbox_id into l_id;
    return l_id;
  end;
end pkg_email;
/
