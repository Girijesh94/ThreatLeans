# ThreatLeans

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

React, TypeScript, and Python FastAPI, as authorized by the implementation plan.
PostgreSQL for shared deployment; SQLite for portable local development.
LangGraph orchestration, BM25 and optional BGE dense retrieval, optional Qdrant.

## Users

SOC analysts researching vulnerabilities, exploitation status, ATT&CK techniques, and mitigation guidance.
SOC administrators managing data sources, accounts, review items, and optional model providers.
The user explicitly requested focus on a shared SOC deployment.

## Product Purpose

An analyst asks a question, retrieves public security evidence, inspects claim verification, and follows cited sources.
The completed application must remain usable without paid AI access or an installed local language model.

## Positioning

Claim-level source provenance and explicit uncertainty, with hybrid retrieval and resilient optional model routing.

## Operating Context

A shared browser workspace served from an organization-managed computer or server.
Data sources include NVD, CVE Program, CISA KEV, MITRE ATT&CK, and OWASP.
Administrators choose optional team-wide AI providers; individual analysts need no provider account.

## Capabilities and Constraints

Search, verified evidence answers, comparisons, source freshness, query history, human review, provider status, and audit events.
No speculative exploitation claims or invented CVE-to-technique mappings.
The implementation plan is at output/VigilRAG_Complete_Build_Plan.md.
No private SOC logs or customer assets were supplied. Public records must carry genuine source dates and origin links.

## Brand Commitments

The exact application name is ThreatLeans.
Use clear operational language and actionable explanations of missing evidence.
The user rejected the earlier static mockups and requested actual 3D animation using Paper liquid-logo, liquid-glass-js, React Three Fiber, and ShaderGradient. The shipping introduction uses their graphics integrations; operational evidence remains readable HTML.

## Evidence on Hand

The project proposal and detailed 30-page implementation plan.
Public authoritative source data must be acquired and provenance retained during implementation.

## Product Principles

Critical facts come from recorded evidence.
Unknown information remains unknown.
Access to saved queries and administration is authorized server-side.
Provider failover cannot weaken evidence or privacy rules.
