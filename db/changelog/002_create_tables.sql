-- Script: 002_create_tables.sql
-- Purpose: Create core TMS tables
-- Date: 2026-07-20
-- Author: Your Name

-- Connect as TMS_APP
ALTER SESSION SET CURRENT_SCHEMA=TMS_APP;

-- Table: TMS_USERS (Developer/admin accounts)
CREATE TABLE tms_users (
   user_id            NUMBER PRIMARY KEY,
   username           VARCHAR2(255) NOT NULL UNIQUE,
   email              VARCHAR2(255) NOT NULL,
   full_name          VARCHAR2(255),
   role               VARCHAR2(50) NOT NULL CHECK (role IN ('ADMIN', 'DEVELOPER')),
   created_date       TIMESTAMP DEFAULT SYSDATE,
   modified_date      TIMESTAMP DEFAULT SYSDATE,
   is_active          NUMBER(1) DEFAULT 1
);

-- Table: TMS_JOBS (Carrier TMS Jobs)
CREATE TABLE tms_jobs (
   job_id             NUMBER PRIMARY KEY,
   job_number         VARCHAR2(50) NOT NULL UNIQUE,
   customer_id        VARCHAR2(50),
   origin             VARCHAR2(255),
   destination        VARCHAR2(255),
   job_status         VARCHAR2(50) DEFAULT 'NEW',
   created_date       TIMESTAMP DEFAULT SYSDATE,
   modified_date      TIMESTAMP DEFAULT SYSDATE
);

-- Table: TMS_SHIPMENTS (Shipment details)
CREATE TABLE tms_shipments (
   shipment_id        NUMBER PRIMARY KEY,
   job_id             NUMBER NOT NULL,
   shipment_number    VARCHAR2(50),
   shipment_date      DATE,
   created_date       TIMESTAMP DEFAULT SYSDATE,
   FOREIGN KEY (job_id) REFERENCES tms_jobs(job_id)
);

COMMIT;

PROMPT Tables created successfully.