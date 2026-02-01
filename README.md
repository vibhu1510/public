

# AI-Assisted Security Analytics Demo (Snowflake)

This repo contains an **end-to-end security analytics demo** showcasing how AI can be used to help builders move from raw logs → insights → decisions.

## What this demo shows
- Synthetic Splunk-style JSON log generation
- File-based ingestion using Snowpipe
- Schema-on-read with VARIANT
- Schema-on-write transformations
- AI-assisted analytics using Snowflake Cortex:
  - `AI_SUMMARIZE_AGG` to summarize thousands of events
  - `AI_CLASSIFY` to categorize threats

## Why I built this
Builders often struggle to extract signal from noisy, semi-structured logs.
This demo shows how AI can:
- Reduce cognitive load
- Surface patterns faster
- Turn raw data into human-readable insights

## How to use
1. Open the SQL file
2. Run sections top-to-bottom
3. Pause at AI steps to inspect outputs

📄 Main file:
[end to end security analytics demo.sql](./end%20to%20end%20security%20analytics%20demo.sql)

## Who this is for
- Builders experimenting with AI-assisted workflows
- No-code / low-code users working with messy data
- Anyone curious how AI fits into real analytics pipelines
