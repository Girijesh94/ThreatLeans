---
name: react-three-fiber
description: Build React 19 scenes with React Three Fiber.
---

# Integration guidance

This is a project-authored integration skill, not a skill supplied by the upstream repository.

Source: https://github.com/pmndrs/react-three-fiber

Use @react-three/fiber v9 for React 19. Keep renderer hooks inside Canvas. Dispose geometry/materials, cap DPR, pause offscreen and when the document is hidden, respect reduced motion and provide a non-WebGL fallback. Lazy-load the scene so the application does not wait for graphics.
