---
name: ThreatLeans
description: A source-bound threat intelligence workspace for a shared SOC
colors:
  graphite: "#20232b"
  ink: "#20252a"
  public-text: "#efeee9"
  workspace-paper: "#f6f5f1"
  bronze: "#76533c"
  ring-bronze: "#d4b294"
  supported: "#396650"
  muted: "#656a6c"
  rule: "#dddfda"
typography:
  display:
    fontFamily: "Space Grotesk Variable, sans-serif"
    fontSize: "clamp(56px, 5.45vw, 88px)"
    fontWeight: 500
    lineHeight: 1.04
    letterSpacing: "-0.04em"
  headline:
    fontFamily: "Space Grotesk Variable, sans-serif"
    fontSize: "33px"
    fontWeight: 500
    lineHeight: 1.2
  body:
    fontFamily: "IBM Plex Sans, sans-serif"
    fontSize: "15px"
    fontWeight: 400
    lineHeight: 1.65
  label:
    fontFamily: "IBM Plex Sans, sans-serif"
    fontSize: "12px"
    fontWeight: 500
rounded:
  control: "5px"
  glass: "24px"
spacing:
  tight: "8px"
  control: "15px"
  panel: "22px"
  section: "100px"
components:
  button-primary:
    backgroundColor: "{colors.ink}"
    textColor: "#ffffff"
    rounded: "{rounded.control}"
    padding: "9px 15px"
  status-supported:
    textColor: "{colors.supported}"
---

# Design System: ThreatLeans

## Overview

**Creative North Star: "Evidence in Focus"**

The public introduction uses real optical materials to make evidence feel tangible: interlocking metal rings, a constrained refractive plate, a liquid monogram and a restrained ambient shader. The four graphics libraries named by the user are integrated in the live scene. The earlier static mockups were rejected and supply no design authority.

Once an analyst enters, pale surfaces, compact labels and source ledgers keep attention on the record. The animated scene remains outside the work area. Key characteristics: graphite and bronze on the introduction; pale paper and dark ink in the SOC; large plain-language headings; narrow, traceable citations; visible uncertainty.

## Colors

Graphite `#20232b` carries the public field. Public text is `#efeee9`, with metallic bronze highlights in the scene and the primary public button. The operational workspace uses `#f6f5f1` and ink `#20252a`, rules `#dddfda`, and muted labels `#656a6c`. Supported status is green `#396650`; amber-brown status indicates review or uncertainty without implying a probability.

**The Evidence Rule.** Color indicates source or workflow state; it never replaces the status text or a citation.

## Typography

Space Grotesk Variable is the self-hosted display face; IBM Plex Sans is the self-hosted reading and control face. The public hero is set between 56 and 88 px, weight 500, line-height 1.04 and tracking no tighter than `-0.04em`. App page headings are around 33 px, while answer headings are around 24 px. Evidence paragraphs and controls use 12–15 px IBM Plex Sans with generous line height. Sources, timestamps, provenance hashes and tabular figures stay in clear text; hashes and JSON use code formatting only where needed.

## Layout

The public hero is a two-column statement and scene on wide screens. The source strip leads to a live source example, then a sequential explanation and closing action. At 760 px and below the hero stacks, the action remains above the scene, and the source strip becomes two columns. The analyst app has a fixed 230 px navigation rail, a wide question surface and an answer/evidence split. At 1100 px the rail contracts to 200 px; at 760 px it becomes a mobile drawer and the evidence pane follows the answer. Operational content uses 18–38 px page padding, with readable line lengths and overflow containers for tables.

## Elevation & Depth

The public scene earns dimensional depth from actual Three.js lighting and materials. The adapted glass shader and a subtle shadow are confined to the small plate. The operational application primarily separates regions with light tonal changes and single-pixel rules; it does not use floating cards for every datum.

## Shapes

Controls use a 5 px radius. Public primary actions are square. The decorative glass plate has a 24 px radius and an angled rectangular silhouette. The logo is an authored geometric SVG used by both the static wordmark and Paper LiquidMetal mask. Evidence references are compact squared chips rather than decorative badges.

## Components

**Primary action.** Dark ink with white text in the workspace; light warm material with dark ink on the introduction. Height and focus remain usable by keyboard. Disabled actions retain a visible but subdued state.

**Question surface.** A single large textarea above explicit answer-mode, live-check and consent controls. The result appears on the same page, with source citations as working buttons.

**Evidence ledger.** Source tabs select the original record; title, source URL, observation time, excerpt, structured fields and SHA-256 provenance stay inspectable. Long JSON is scrollable without stretching the page.

**Review and status.** The status label contains text and a small dot. The review decision is a separate workflow state and never rewrites evidence verification.

**Mobile navigation.** A drawer replaces the rail below 760 px. Navigation uses real buttons, labels and keyboard focus.

**Material scene.** R3F rings respond to the selected public evidence example. ShaderGradient stays behind the scene; the LiquidMetal mask and glass plate remain decorative. The whole scene is lazy-loaded and paused by user control, reduced-motion preference, offscreen state or hidden document.

## Do's and Don'ts

### Do:

- Do keep the source and observation time near every public example.
- Do keep optional AI interpretation visually separate from source-bound findings.
- Do offer pause, readable static fallback and a functioning SOC without the 3D scene.

### Don't:

- Don't reuse the rejected case-desk raster mockups as UI assets.
- Don't use 3D graphics behind analyst questions, evidence text or controls.
- Don't color a source-backed finding as proven exposure or attribution.
