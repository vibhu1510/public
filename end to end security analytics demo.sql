/* ========================================================================
   SPLUNK OFFLOAD PIPELINE IN SNOWFLAKE (SNOWPIPE ONLY)
   ------------------------------------------------------------------------
   Goal:
   1) Generate synthetic Splunk-like JSON logs
   2) Put JSON files on an INTERNAL STAGE
   3) Ingest into Snowflake using SNOWPIPE (PIPE + REFRESH)
   4) Store raw semi-structured data in VARIANT (schema-on-read)
   5) Transform into curated structured table (schema-on-write)
   6) Run analytics + Snowflake Cortex AI functions:
        - AI_SUMMARIZE_AGG (summarize 10k+ log events)
        - AI_CLASSIFY      (classify events into threat categories)

   ======================================================================== */


/* ------------------------------------------------------------------------
   0) OPTIONAL: Choose role
   ------------------------------------------------------------------------
   Use your highest role available in trial.
   If ACCOUNTADMIN exists, use it. If not, use your current role.
------------------------------------------------------------------------- */
-- USE ROLE ACCOUNTADMIN;


/* ------------------------------------------------------------------------
   1) CORE SETUP: Warehouse, Database, Schemas, Stage, File Format
   ------------------------------------------------------------------------
   We create:
   - Warehouse: LAB_WH (compute)
   - Database: SPLUNK_OFFLOAD_LAB
   - Schemas: RAW, CURATED
   - Internal stage: RAW.SPLUNK_STAGE (where files will be stored)
   - JSON file format: RAW.JSON_FF
------------------------------------------------------------------------- */

CREATE OR REPLACE WAREHOUSE LAB_WH
  WAREHOUSE_SIZE = XSMALL
  AUTO_SUSPEND = 60
  AUTO_RESUME = TRUE;

CREATE OR REPLACE DATABASE SPLUNK_OFFLOAD_LAB;
CREATE OR REPLACE SCHEMA SPLUNK_OFFLOAD_LAB.RAW;
CREATE OR REPLACE SCHEMA SPLUNK_OFFLOAD_LAB.CURATED;

USE WAREHOUSE LAB_WH;
USE DATABASE SPLUNK_OFFLOAD_LAB;

CREATE OR REPLACE STAGE RAW.SPLUNK_STAGE;

CREATE OR REPLACE FILE FORMAT RAW.JSON_FF
  TYPE = JSON
  STRIP_OUTER_ARRAY = TRUE;


/* ------------------------------------------------------------------------
   2) GENERATE SYNTHETIC SPLUNK-LIKE EVENTS (STRUCTURED SOURCE TABLE)
   ------------------------------------------------------------------------
   Splunk-style event structure (simplified):
     {
       "time": <epoch seconds>,
       "index": "security|app|infra|audit",
       "sourcetype": "aws:cloudtrail|nginx:access|kube:container|vpc:flow|edr:telemetry",
       "host": "host-12",
       "source": "/var/log/nginx/access.log",
       "event": "Failed login: invalid password",
       "fields": {
         "src_ip": "...",
         "user": "...",
         "action": "...",
         "http_status": 401,
         "uri": "/login",
         "bytes_out": 1234,
         "latency_ms": 456,
         "severity": "high|medium|low"
       }
     }

   We first generate rows in a normal table to keep generation easy and clear.
------------------------------------------------------------------------- */

USE SCHEMA RAW;

CREATE OR REPLACE TABLE RAW.SPLUNK_SYNTH_SRC (
  time_epoch    NUMBER(20,3),
  index_name    STRING,
  sourcetype    STRING,
  host          STRING,
  source        STRING,
  event         STRING,
  src_ip        STRING,
  user_name     STRING,
  action        STRING,
  http_status   NUMBER(10,0),
  uri           STRING,
  bytes_out     NUMBER(10,0),
  latency_ms    NUMBER(10,0),
  severity      STRING
);

-- Generate ~12,000 events over the last 24 hours with realistic distributions.
INSERT INTO RAW.SPLUNK_SYNTH_SRC
SELECT
  (DATE_PART(EPOCH_SECOND, DATEADD('second', -UNIFORM(0, 86400, RANDOM()), CURRENT_TIMESTAMP()))
    + UNIFORM(0,999,RANDOM())/1000.0)::NUMBER(20,3) AS time_epoch,
  DECODE(UNIFORM(1,4,RANDOM()),1,'security',2,'app',3,'infra','audit') AS index_name,
  DECODE(UNIFORM(1,5,RANDOM()),1,'aws:cloudtrail',2,'kube:container',3,'nginx:access',4,'edr:telemetry','vpc:flow') AS sourcetype,
  'host-'||UNIFORM(1,60,RANDOM()) AS host,
  DECODE(UNIFORM(1,4,RANDOM()),1,'/var/log/auth.log',2,'/var/log/nginx/access.log',3,'cloudtrail','vpcflow') AS source,
  DECODE(
    UNIFORM(1,10,RANDOM()),
    1,'Failed login: invalid password',
    2,'MFA challenge failed',
    3,'Blocked request: WAF rule matched',
    4,'Suspicious IP reputation hit',
    5,'Excessive requests detected (possible bot)',
    6,'Successful login',
    7,'Token issued',
    8,'Admin privilege change',
    9,'Payment flagged by rules',
    'Normal request'
  ) AS event,
  UNIFORM(1,255,RANDOM())||'.'||UNIFORM(0,255,RANDOM())||'.'||UNIFORM(0,255,RANDOM())||'.'||UNIFORM(1,254,RANDOM()) AS src_ip,
  'user' || UNIFORM(1,800,RANDOM()) AS user_name,
  DECODE(UNIFORM(1,7,RANDOM()),1,'login',2,'mfa',3,'api_call',4,'admin_change',5,'payment',6,'logout','token') AS action,
  DECODE(UNIFORM(1,10,RANDOM()),1,401,2,403,3,429,200) AS http_status,
  DECODE(UNIFORM(1,6,RANDOM()),1,'/login',2,'/mfa',3,'/checkout',4,'/admin',5,'/api/v1/orders','/api/v1/profile') AS uri,
  UNIFORM(200,50000,RANDOM()) AS bytes_out,
  UNIFORM(5,6000,RANDOM()) AS latency_ms,
  DECODE(UNIFORM(1,10,RANDOM()),1,'high',2,'high',3,'medium','low') AS severity
FROM TABLE(GENERATOR(ROWCOUNT => 12000));


/* ------------------------------------------------------------------------
   3) CONVERT TO JSON + WRITE FILES TO INTERNAL STAGE
   ------------------------------------------------------------------------
   We convert each row into a JSON object using OBJECT_CONSTRUCT, then export
   those JSON objects to internal stage files with COPY INTO @stage.
------------------------------------------------------------------------- */

CREATE OR REPLACE VIEW RAW.SPLUNK_SYNTH_JSON_V AS
SELECT
  OBJECT_CONSTRUCT(
    'time', time_epoch,
    'index', index_name,
    'sourcetype', sourcetype,
    'host', host,
    'source', source,
    'event', event,
    'fields', OBJECT_CONSTRUCT(
      'src_ip', src_ip,
      'user', user_name,
      'action', action,
      'http_status', http_status,
      'uri', uri,
      'bytes_out', bytes_out,
      'latency_ms', latency_ms,
      'severity', severity
    )
  ) AS splunk_event
FROM RAW.SPLUNK_SYNTH_SRC;

-- Export JSON objects into multiple JSON files in the internal stage path.
-- OVERWRITE=TRUE to keep the demo repeatable.
COPY INTO @RAW.SPLUNK_STAGE/splunk_json/
FROM (SELECT splunk_event FROM RAW.SPLUNK_SYNTH_JSON_V)
FILE_FORMAT = (TYPE = JSON)
OVERWRITE = TRUE;

-- Verify the files exist on the stage.
LIST @RAW.SPLUNK_STAGE/splunk_json/;


/* ------------------------------------------------------------------------
   4) CREATE RAW LANDING TABLE (VARIANT)
   ------------------------------------------------------------------------
   RAW table uses VARIANT to store semi-structured Splunk events directly
   (schema-on-read). We also store metadata about which file/row it came from.
------------------------------------------------------------------------- */

CREATE OR REPLACE TABLE RAW.SPLUNK_RAW (
  ingest_ts  TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
  filename   STRING,
  row_number NUMBER,
  raw        VARIANT
);


/* ------------------------------------------------------------------------
   5) SNOWPIPE (PIPE + REFRESH) TO INGEST FROM INTERNAL STAGE
   ------------------------------------------------------------------------
   - CREATE PIPE: defines the COPY INTO statement Snowpipe will execute.
   - REFRESH: forces Snowpipe to scan the stage and load new files.
   - SYSTEM$PIPE_STATUS: quick status check.
------------------------------------------------------------------------- */

CREATE OR REPLACE PIPE RAW.SPLUNK_PIPE AS
COPY INTO RAW.SPLUNK_RAW (filename, row_number, raw)
FROM (
  SELECT
    METADATA$FILENAME,
    METADATA$FILE_ROW_NUMBER,
    $1
  FROM @RAW.SPLUNK_STAGE/splunk_json/
)
FILE_FORMAT = RAW.JSON_FF;

-- Simulate ingestion (since internal stage does not use cloud event notifications)
ALTER PIPE RAW.SPLUNK_PIPE REFRESH;

-- See pipe status 
SELECT SYSTEM$PIPE_STATUS('RAW.SPLUNK_PIPE');


/* ------------------------------------------------------------------------
   6) QUICK RAW VALIDATION QUERIES (VARIANT EXPLORATION)
   ------------------------------------------------------------------------
   These show how easy it is to query semi-structured JSON without first
   defining a rigid schema.
------------------------------------------------------------------------- */

-- Row count ingested
SELECT COUNT(*) AS raw_rows FROM RAW.SPLUNK_RAW;    --wait for few secs

-- Distribution of sourcetypes (directly from VARIANT)
SELECT raw:sourcetype::string AS sourcetype, COUNT(*) AS cnt
FROM RAW.SPLUNK_RAW
GROUP BY 1
ORDER BY cnt DESC;

-- Peek at a few raw JSON events
SELECT filename, row_number, raw
FROM RAW.SPLUNK_RAW
QUALIFY ROW_NUMBER() OVER (ORDER BY ingest_ts DESC) <= 5;


/* ------------------------------------------------------------------------
   7) TRANSFORM: RAW VARIANT → CURATED STRUCTURED TABLE
   ------------------------------------------------------------------------
   Curated table is optimized for analytics, dashboards, and BI.
   This is where you normalize/standardize fields and types.
------------------------------------------------------------------------- */

USE SCHEMA CURATED;

CREATE OR REPLACE TABLE CURATED.SPLUNK_EVENTS (
  event_ts     TIMESTAMP_NTZ,
  index_name   STRING,
  sourcetype   STRING,
  host         STRING,
  source       STRING,
  event        STRING,
  src_ip       STRING,
  user_name    STRING,
  action       STRING,
  http_status  NUMBER(10,0),
  uri          STRING,
  bytes_out    NUMBER(10,0),
  latency_ms   NUMBER(10,0),
  severity     STRING
);

-- Load curated from RAW table by extracting JSON paths
INSERT INTO CURATED.SPLUNK_EVENTS
SELECT
  TO_TIMESTAMP_NTZ(raw:time::number)        AS event_ts,
  raw:index::string                         AS index_name,
  raw:sourcetype::string                    AS sourcetype,
  raw:host::string                          AS host,
  raw:source::string                        AS source,
  raw:event::string                         AS event,
  raw:fields:src_ip::string                 AS src_ip,
  raw:fields:user::string                   AS user_name,
  raw:fields:action::string                 AS action,
  raw:fields:http_status::number            AS http_status,
  raw:fields:uri::string                    AS uri,
  raw:fields:bytes_out::number              AS bytes_out,
  raw:fields:latency_ms::number             AS latency_ms,
  raw:fields:severity::string               AS severity
FROM SPLUNK_OFFLOAD_LAB.RAW.SPLUNK_RAW;

-- Curated validation
SELECT COUNT(*) AS curated_rows FROM CURATED.SPLUNK_EVENTS;


/* ------------------------------------------------------------------------
   8) ANALYTICS QUERIES (SPLUNK-LIKE USE CASES)
   ------------------------------------------------------------------------
   These are "SOC-friendly" queries you can narrate as:
   "In Splunk this is expensive for long retention. In Snowflake we can keep
    months/years and still run these fast, plus join with other data later."
------------------------------------------------------------------------- */

-- 8.1 Suspicious HTTP status codes trend (401/403/429)
SELECT
  DATE_TRUNC('hour', event_ts) AS hr,
  http_status,
  COUNT(*) AS cnt
FROM CURATED.SPLUNK_EVENTS
WHERE http_status IN (401,403,429)
GROUP BY 1,2
ORDER BY hr DESC, cnt DESC;

-- 8.2 Top noisy source IPs (potential scanners/bots)
SELECT src_ip, COUNT(*) AS events
FROM CURATED.SPLUNK_EVENTS
GROUP BY 1
ORDER BY events DESC
LIMIT 20;



-- 8.4 Latency p95 by sourcetype (ops + security can both use this)
SELECT
  sourcetype,
  APPROX_PERCENTILE(latency_ms, 0.95) AS p95_latency_ms
FROM CURATED.SPLUNK_EVENTS
GROUP BY 1
ORDER BY p95_latency_ms DESC;


/* ------------------------------------------------------------------------
   9) SNOWFLAKE CORTEX AI FUNCTIONS ON LOG DATA
   ------------------------------------------------------------------------
   Two demos:
   A) AI_SUMMARIZE_AGG: summarize thousands of log messages into a digest.
   B) AI_CLASSIFY: classify each event into threat categories.
------------------------------------------------------------------------- */

-- 9A) Summarize the entire dataset (10k+ events) into an incident narrative
-- Great for IR handoff / daily exec summary / "what happened last night?"
SELECT AI_SUMMARIZE_AGG(
  CONCAT(
    '[', TO_VARCHAR(event_ts), '] ',
    sourcetype, ' ',
    'status=', TO_VARCHAR(http_status), ' ',
    'user=', user_name, ' ',
    'ip=', src_ip, ' ',
    event
  )
) AS incident_summary
FROM CURATED.SPLUNK_EVENTS;

-- 9B) Summarize by sourcetype (useful to highlight where the noise is)
SELECT
  sourcetype,
  AI_SUMMARIZE_AGG(event) AS summary
FROM CURATED.SPLUNK_EVENTS
GROUP BY 1
ORDER BY 1;

-- 9C) Classify each event into a SOC-friendly category set
-- We classify using the message + context fields like status/uri/sourcetype.
WITH scored AS (
  SELECT
    event_ts, sourcetype, host, src_ip, user_name, http_status, uri, event,
    AI_CLASSIFY(
      CONCAT(
        event,
        ' | status=', TO_VARCHAR(http_status),
        ' | uri=', uri,
        ' | sourcetype=', sourcetype,
        ' | action=', action,
        ' | severity=', severity
      ),
      ['benign','credential_attack','mfa_failure','bot_or_rate_abuse','waf_block','admin_risk','payment_fraud']
    ) AS cls
  FROM CURATED.SPLUNK_EVENTS
)
SELECT
  event_ts, sourcetype, host, http_status, uri, event,
  cls:labels[0]::string AS top_label
FROM scored
ORDER BY event_ts DESC
LIMIT 50;

-- 9D) Threat mix distribution (counts per top label)
WITH scored AS (
  SELECT
    AI_CLASSIFY(
      CONCAT(
        event,
        ' | status=', TO_VARCHAR(http_status),
        ' | uri=', uri,
        ' | sourcetype=', sourcetype,
        ' | action=', action,
        ' | severity=', severity
      ),
      ['benign','credential_attack','mfa_failure','bot_or_rate_abuse','waf_block','admin_risk','payment_fraud']
    ) AS cls
  FROM CURATED.SPLUNK_EVENTS
)
SELECT
  cls:labels[0]::string AS label,
  COUNT(*)              AS cnt
FROM scored
GROUP BY 1
ORDER BY cnt DESC;



--cleanup

```sql
/* ========================================================================
   CLEANUP SCRIPT — SPLUNK OFFLOAD PIPELINE (SNOWPIPE ONLY)
   ------------------------------------------------------------------------
   This removes everything created by the pipeline script, in safe order:
   1) Stop/drop Snowpipe
   2) Drop tables/views/file format/stage
   3) Drop schemas + database
   4) Drop warehouse

   Note:
   - If you used a different DB/WH name, update them below.
   ======================================================================== */

-- Use a high-privilege role if available
USE ROLE ACCOUNTADMIN;

-- Ensure we’re not using the DB we’re about to drop
-- USE DATABASE SNOWFLAKE;
-- USE SCHEMA PUBLIC;

---------------------------------------------------------------------------
-- 1) Drop the pipe first (it depends on stage/table/file format)
---------------------------------------------------------------------------
DROP PIPE IF EXISTS SPLUNK_OFFLOAD_LAB.RAW.SPLUNK_PIPE;

---------------------------------------------------------------------------
-- 2) Drop curated objects
---------------------------------------------------------------------------
DROP TABLE IF EXISTS SPLUNK_OFFLOAD_LAB.CURATED.SPLUNK_EVENTS;

---------------------------------------------------------------------------
-- 3) Drop raw objects (landing + generator assets)
---------------------------------------------------------------------------
DROP TABLE IF EXISTS SPLUNK_OFFLOAD_LAB.RAW.SPLUNK_RAW;
DROP VIEW  IF EXISTS SPLUNK_OFFLOAD_LAB.RAW.SPLUNK_SYNTH_JSON_V;
DROP TABLE IF EXISTS SPLUNK_OFFLOAD_LAB.RAW.SPLUNK_SYNTH_SRC;

---------------------------------------------------------------------------
-- 4) Drop stage + file format
---------------------------------------------------------------------------
DROP STAGE       IF EXISTS SPLUNK_OFFLOAD_LAB.RAW.SPLUNK_STAGE;
DROP FILE FORMAT IF EXISTS SPLUNK_OFFLOAD_LAB.RAW.JSON_FF;

---------------------------------------------------------------------------
-- 5) Drop schemas (optional; dropping DB will drop them anyway)
---------------------------------------------------------------------------
DROP SCHEMA IF EXISTS SPLUNK_OFFLOAD_LAB.CURATED;
DROP SCHEMA IF EXISTS SPLUNK_OFFLOAD_LAB.RAW;

---------------------------------------------------------------------------
-- 6) Drop database
---------------------------------------------------------------------------
DROP DATABASE IF EXISTS SPLUNK_OFFLOAD_LAB;

---------------------------------------------------------------------------
-- 7) Drop warehouse
---------------------------------------------------------------------------
DROP WAREHOUSE IF EXISTS LAB_WH;

/* ========================================================================
   END CLEANUP
   ======================================================================== */
```
