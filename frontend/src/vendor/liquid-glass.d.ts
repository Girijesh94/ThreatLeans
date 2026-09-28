declare class Container {
  static pageSnapshot: HTMLCanvasElement | null
  constructor(options?: {borderRadius?: number; type?: string; tintOpacity?: number})
  element: HTMLDivElement
  canvas: HTMLCanvasElement
  updateSizeFromDOM(): void
  destroy(): void
}
export default Container
