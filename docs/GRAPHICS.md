# Graphics integration

The four user-selected repositories are software projects, not upstream Codex skill packages. Four project-authored integration skills are checked into `skills/` and installed in the current user's Codex skills directory. They carry explicit provenance and passed the skill validator.

| Requested project | Shipping integration |
| --- | --- |
| paper-design/liquid-logo | The separate `@paper-design/shaders-react` LiquidMetal component animates the authored ThreatLeans SVG mark. The example application itself is not bundled. |
| dashersw/liquid-glass-js | MIT Container source and styles are vendored from revision `78cb6ccb0b9987bb60a88b14ccbd13a9e6e8ab2a`, with teardown and decorative-only snapshot handling. |
| pmndrs/react-three-fiber | React Three Fiber 9 renders the metallic ring assembly using actual Three.js geometry, lights and materials. |
| ruucm/shadergradient | ShaderGradient renders the ambient material wash with local 3D lighting. No remote environment map is requested. |

Exact package versions and integrity hashes are in `frontend/package-lock.json`. Bundled package license texts are served at `/vendor/NOTICES.txt`. The referenced liquid-logo application has a PolyForm Shield license; the separate installed Paper shader packages include their own Apache-2.0 notices. Do not substitute one license for the other.

## Lifecycle and accessibility

The graphics scene is loaded separately from the operational application. The approximately 310 KB compressed scene bundle contains the GPU libraries; the main application does not wait for it. Renderer pixel ratios are capped. Reduced-motion preferences set the initial paused state, and a visible pause control stops animation. Leaving the viewport or hiding the document unmounts the decorative renderers. Signing in releases the scene; analyst tasks use ordinary HTML and do not require GPU effects. A render error shows the static mark and readable fallback.

The glass adapter refracts an explicit generated decorative color surface. It does not capture the page, analyst questions, credentials, or evidence. Its scroll listener and WebGL context are disposed on unmount. The actual Container source is checked in; rebuilding does not require running `scripts/integrate_graphics.py` or retrieving its temporary upstream files.

## Verification limits

The desktop and mobile layouts are browser-checked, with keyboard operation and source-backed investigations. Performance budgets are design limits, not measured guarantees on every device. Three.js emits a deprecation warning for the Clock API used by its current renderer dependencies. This does not stop rendering. No raster mockups are shipped as product UI.
