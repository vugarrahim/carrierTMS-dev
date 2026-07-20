-- Script: 003_create_indexes.sql
-- Purpose: Create indexes for performance
-- Date: 2026-07-20
-- Author: Your Name

ALTER SESSION SET CURRENT_SCHEMA=TMS_APP;

-- Indexes on TMS_USERS
CREATE INDEX idx_tms_users_username ON tms_users(username);
CREATE INDEX idx_tms_users_email ON tms_users(email);

-- Indexes on TMS_JOBS
CREATE INDEX idx_tms_jobs_status ON tms_jobs(job_status);
CREATE INDEX idx_tms_jobs_created ON tms_jobs(created_date);

-- Indexes on TMS_SHIPMENTS
CREATE INDEX idx_tms_shipments_job_id ON tms_shipments(job_id);
CREATE INDEX idx_tms_shipments_date ON tms_shipments(shipment_date);

COMMIT;

PROMPT Indexes created successfully.