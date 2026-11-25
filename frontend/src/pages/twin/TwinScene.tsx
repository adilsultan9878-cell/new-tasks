/**
 * Three.js view of the Digital Twin. Loaded lazily so the 3D engine never weighs on other pages.
 *
 * Floor coordinates (metres, origin at the back-left corner) map to world X/Z; Y is up.
 * Encoding: marker colour = device status, marker height = Security Brain risk, pulsing ring = open
 * alerts (colour = worst severity), red beacon = open incident, small spheres = sensors (red when
 * out of range), cones = cameras, dashed lines = devices on the same network segment.
 */
import { useEffect, useLayoutEffect, useRef } from 'react'
import * as THREE from 'three'
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js'

import type { Twin } from '@/lib/types'

import { markerHeight, SEVERITY_COLOR, statusColor, type Placement } from './layout'

export interface TwinSceneProps {
  twin: Twin
  placements: Record<string, Placement>
  selectedId: string | null
  editMode: boolean
  reducedMotion: boolean
  onSelect: (id: string | null) => void
  onMove: (id: string, x: number, y: number) => void
  onError: (message: string) => void
}

interface Ctx {
  renderer: THREE.WebGLRenderer
  scene: THREE.Scene
  camera: THREE.PerspectiveCamera
  controls: OrbitControls
  content: THREE.Group
  pickables: THREE.Object3D[]
  pulses: { mesh: THREE.Mesh; offset: number }[]
  blinkers: THREE.Mesh[]
  frame: number
}

function label(text: string, color = '#e7edf4', size = 28): THREE.Sprite {
  const canvas = document.createElement('canvas')
  const ctx = canvas.getContext('2d')!
  ctx.font = `600 ${size}px Inter, system-ui, sans-serif`
  const width = Math.ceil(ctx.measureText(text).width) + 24
  canvas.width = width
  canvas.height = size + 20
  ctx.font = `600 ${size}px Inter, system-ui, sans-serif`
  ctx.fillStyle = 'rgba(9, 12, 17, 0.78)'
  ctx.beginPath()
  ctx.roundRect(0, 0, width, size + 20, 10)
  ctx.fill()
  ctx.fillStyle = color
  ctx.textBaseline = 'middle'
  ctx.fillText(text, 12, (size + 20) / 2)
  const texture = new THREE.CanvasTexture(canvas)
  texture.colorSpace = THREE.SRGBColorSpace
  const sprite = new THREE.Sprite(new THREE.SpriteMaterial({ map: texture, depthTest: false, transparent: true }))
  sprite.scale.set(width / 22, (size + 20) / 22, 1)
  sprite.renderOrder = 10
  return sprite
}

function dispose(object: THREE.Object3D): void {
  object.traverse((o) => {
    const mesh = o as THREE.Mesh
    mesh.geometry?.dispose()
    const materials = Array.isArray(mesh.material) ? mesh.material : mesh.material ? [mesh.material] : []
    for (const m of materials) {
      ;(m as THREE.SpriteMaterial).map?.dispose()
      m.dispose()
    }
  })
}

export default function TwinScene(props: TwinSceneProps) {
  const host = useRef<HTMLDivElement>(null)
  const ctxRef = useRef<Ctx | null>(null)
  const live = useRef(props)
  useLayoutEffect(() => {
    live.current = props
  })

  // ------------------------------------------------------------------------------- engine
  useEffect(() => {
    const el = host.current!
    let renderer: THREE.WebGLRenderer
    try {
      renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true })
    } catch {
      live.current.onError('3D view is not available in this browser (WebGL is disabled).')
      return
    }
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
    el.appendChild(renderer.domElement)
    renderer.domElement.setAttribute('aria-hidden', 'true')

    const { width: W, depth: D } = live.current.twin.floor
    const scene = new THREE.Scene()
    scene.fog = new THREE.Fog(0x05070a, 90, 220)
    const camera = new THREE.PerspectiveCamera(45, 1, 0.5, 500)
    const controls = new OrbitControls(camera, renderer.domElement)
    controls.enableDamping = true
    controls.maxPolarAngle = Math.PI / 2.15
    controls.minDistance = 12
    controls.maxDistance = 160
    scene.add(new THREE.HemisphereLight(0xbfe9ff, 0x0b0f16, 1.1))
    const sun = new THREE.DirectionalLight(0xffffff, 1.2)
    sun.position.set(30, 60, 20)
    scene.add(sun)

    const floor = new THREE.Mesh(new THREE.PlaneGeometry(W, D), new THREE.MeshStandardMaterial({ color: 0x0c1016, roughness: 0.95 }))
    floor.rotation.x = -Math.PI / 2
    floor.name = 'floor'
    scene.add(floor)
    const grid = new THREE.GridHelper(Math.max(W, D), Math.max(W, D) / 4, 0x22d3ee, 0x1d2430)
    ;(grid.material as THREE.Material).opacity = 0.18
    ;(grid.material as THREE.Material).transparent = true
    grid.scale.set(W / Math.max(W, D), 1, D / Math.max(W, D))
    scene.add(grid)
    const border = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.BoxGeometry(W, 0.01, D)), new THREE.LineBasicMaterial({ color: 0x8b5cf6 }))
    scene.add(border)

    const content = new THREE.Group()
    scene.add(content)
    const ctx: Ctx = { renderer, scene, camera, controls, content, pickables: [], pulses: [], blinkers: [], frame: 0 }
    ctxRef.current = ctx

    let fitted = false
    const resize = () => {
      const w = el.clientWidth || 1
      const h = el.clientHeight || 1
      renderer.setSize(w, h, false)
      renderer.domElement.style.width = '100%'
      renderer.domElement.style.height = '100%'
      camera.aspect = w / h
      camera.updateProjectionMatrix()
      if (!fitted) {
        // Frame the whole floor from ~55° above, whatever the panel's shape.
        const vfov = (camera.fov * Math.PI) / 180
        const hfov = 2 * Math.atan(Math.tan(vfov / 2) * camera.aspect)
        const dist = Math.max(W / 2 / Math.tan(hfov / 2), D / 2 / Math.tan(vfov / 2)) * 1.22
        const tilt = (55 * Math.PI) / 180
        camera.position.set(0, dist * Math.sin(tilt), dist * Math.cos(tilt))
        controls.target.set(0, 0, 4)
        controls.update()
        fitted = el.clientWidth > 0
      }
    }
    resize()
    const observer = new ResizeObserver(resize)
    observer.observe(el)

    // ----------------------------------------------------------------------- interaction
    const raycaster = new THREE.Raycaster()
    const pointer = new THREE.Vector2()
    const ground = new THREE.Plane(new THREE.Vector3(0, 1, 0), 0)
    let dragging: { id: string; group: THREE.Object3D } | null = null
    let downAt: { x: number; y: number } | null = null

    const setPointer = (e: PointerEvent) => {
      const r = renderer.domElement.getBoundingClientRect()
      pointer.set(((e.clientX - r.left) / r.width) * 2 - 1, -((e.clientY - r.top) / r.height) * 2 + 1)
      raycaster.setFromCamera(pointer, camera)
    }
    const deviceAt = (): string | null => {
      const hit = raycaster.intersectObjects(ctx.pickables, false)[0]
      return (hit?.object.userData.deviceId as string | undefined) ?? null
    }
    const onDown = (e: PointerEvent) => {
      setPointer(e)
      downAt = { x: e.clientX, y: e.clientY }
      const id = deviceAt()
      if (id && live.current.editMode) {
        const group = content.getObjectByName(`device:${id}`)
        if (group) {
          dragging = { id, group }
          controls.enabled = false
          renderer.domElement.setPointerCapture(e.pointerId)
        }
      }
    }
    const onMove = (e: PointerEvent) => {
      setPointer(e)
      if (dragging) {
        const p = new THREE.Vector3()
        if (raycaster.ray.intersectPlane(ground, p)) {
          dragging.group.position.x = Math.min(W / 2, Math.max(-W / 2, p.x))
          dragging.group.position.z = Math.min(D / 2, Math.max(-D / 2, p.z))
        }
        return
      }
      renderer.domElement.style.cursor = deviceAt() ? (live.current.editMode ? 'grab' : 'pointer') : 'default'
    }
    const onUp = (e: PointerEvent) => {
      if (dragging) {
        const { id, group } = dragging
        dragging = null
        controls.enabled = true
        live.current.onMove(id, group.position.x + W / 2, group.position.z + D / 2)
        return
      }
      if (downAt && Math.hypot(e.clientX - downAt.x, e.clientY - downAt.y) < 5) {
        setPointer(e)
        live.current.onSelect(deviceAt())
      }
      downAt = null
    }
    renderer.domElement.addEventListener('pointerdown', onDown)
    renderer.domElement.addEventListener('pointermove', onMove)
    renderer.domElement.addEventListener('pointerup', onUp)

    // ------------------------------------------------------------------------- animation
    const clock = new THREE.Clock()
    const tick = () => {
      ctx.frame = requestAnimationFrame(tick)
      if (document.hidden) return
      const t = clock.getElapsedTime()
      if (!live.current.reducedMotion) {
        for (const { mesh, offset } of ctx.pulses) {
          const phase = ((t + offset) % 1.8) / 1.8
          mesh.scale.setScalar(1 + phase * 1.6)
          ;(mesh.material as THREE.MeshBasicMaterial).opacity = 0.7 * (1 - phase)
        }
        for (const b of ctx.blinkers) (b.material as THREE.MeshBasicMaterial).opacity = 0.55 + 0.45 * Math.abs(Math.sin(t * 3))
      }
      controls.update()
      renderer.render(scene, camera)
      if (!el.dataset.ready) el.dataset.ready = 'true'
    }
    tick()

    return () => {
      cancelAnimationFrame(ctx.frame)
      observer.disconnect()
      renderer.domElement.removeEventListener('pointerdown', onDown)
      renderer.domElement.removeEventListener('pointermove', onMove)
      renderer.domElement.removeEventListener('pointerup', onUp)
      controls.dispose()
      dispose(scene)
      renderer.dispose()
      renderer.domElement.remove()
      ctxRef.current = null
    }
  }, [])

  // ------------------------------------------------------------------------------ content
  const { twin, placements, selectedId } = props
  useEffect(() => {
    const ctx = ctxRef.current
    if (!ctx) return
    const { width: W, depth: D } = twin.floor
    const world = (x: number, y: number) => new THREE.Vector3(x - W / 2, 0, y - D / 2)
    for (const child of [...ctx.content.children]) {
      dispose(child)
      ctx.content.remove(child)
    }
    ctx.pickables = []
    ctx.pulses = []
    ctx.blinkers = []

    for (const area of twin.areas) {
      const center = world(area.x + area.w / 2, area.y + area.h / 2)
      const slab = new THREE.Mesh(new THREE.BoxGeometry(area.w, 0.08, area.h),
        new THREE.MeshBasicMaterial({ color: area.simulated ? 0xfab219 : 0x22d3ee, transparent: true, opacity: 0.06 }))
      slab.position.copy(center)
      const edges = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.BoxGeometry(area.w, 0.6, area.h)),
        new THREE.LineBasicMaterial({ color: area.simulated ? 0xfab219 : 0x22d3ee, transparent: true, opacity: 0.55 }))
      edges.position.copy(center).setY(0.3)
      const text = label(area.simulated ? `${area.name} · simulated` : area.name, area.simulated ? '#fcd34d' : '#67e8f9', 26)
      text.position.copy(world(area.x + 3, area.y + 1.5)).setY(1.2)
      ctx.content.add(slab, edges, text)
    }

    for (const seg of twin.segments) {
      const pts = seg.device_ids.map((id) => placements[id]).filter(Boolean) as Placement[]
      if (pts.length < 2) continue
      const c = world(pts.reduce((s, p) => s + p.x, 0) / pts.length, pts.reduce((s, p) => s + p.y, 0) / pts.length)
      const node = new THREE.Mesh(new THREE.OctahedronGeometry(0.9), new THREE.MeshStandardMaterial({ color: 0x8b5cf6, emissive: 0x4c1d95 }))
      node.position.copy(c).setY(0.6)
      const text = label(seg.cidr, '#c4b5fd', 22)
      text.position.copy(c).setY(1.8)
      ctx.content.add(node, text)
      for (const p of pts) {
        const line = new THREE.Line(new THREE.BufferGeometry().setFromPoints([world(p.x, p.y).setY(0.15), c.clone().setY(0.15)]),
          new THREE.LineDashedMaterial({ color: 0x8b5cf6, dashSize: 0.8, gapSize: 0.6, transparent: true, opacity: 0.6 }))
        line.computeLineDistances()
        ctx.content.add(line)
      }
    }

    twin.devices.forEach((d, index) => {
      const place = placements[d.id]
      if (!place) return
      const group = new THREE.Group()
      group.name = `device:${d.id}`
      group.position.copy(world(place.x, place.y))
      const h = markerHeight(d)
      const color = new THREE.Color(statusColor(d))
      const body = new THREE.Mesh(new THREE.CylinderGeometry(1.4, 1.7, h, 28), new THREE.MeshStandardMaterial({
        color, emissive: color, emissiveIntensity: d.open_alerts ? 0.55 : 0.18, roughness: 0.4, metalness: 0.2,
        transparent: d.is_simulated, opacity: d.is_simulated ? 0.8 : 1,
      }))
      body.position.y = h / 2
      body.userData.deviceId = d.id
      ctx.pickables.push(body)
      group.add(body)
      const base = new THREE.Mesh(new THREE.RingGeometry(2.0, d.id === selectedId ? 2.8 : 2.3, 48),
        new THREE.MeshBasicMaterial({ color: d.id === selectedId ? 0xffffff : 0x22d3ee, transparent: true, opacity: d.id === selectedId ? 0.95 : 0.35, side: THREE.DoubleSide }))
      base.rotation.x = -Math.PI / 2
      base.position.y = 0.05
      group.add(base)
      if (d.open_alerts && d.max_alert_severity) {
        const pulse = new THREE.Mesh(new THREE.RingGeometry(2.2, 2.6, 48),
          new THREE.MeshBasicMaterial({ color: SEVERITY_COLOR[d.max_alert_severity], transparent: true, opacity: 0.6, side: THREE.DoubleSide }))
        pulse.rotation.x = -Math.PI / 2
        pulse.position.y = 0.08
        ctx.pulses.push({ mesh: pulse, offset: index * 0.37 })
        group.add(pulse)
      }
      if (d.open_incidents.length) {
        const pole = new THREE.Mesh(new THREE.CylinderGeometry(0.12, 0.12, 6, 8), new THREE.MeshBasicMaterial({ color: 0xf0565b }))
        pole.position.y = h + 3
        const lamp = new THREE.Mesh(new THREE.SphereGeometry(0.7, 16, 16), new THREE.MeshBasicMaterial({ color: 0xf0565b, transparent: true }))
        lamp.position.y = h + 6.2
        ctx.blinkers.push(lamp)
        group.add(pole, lamp)
      }
      const satellites = [...d.sensors.map((s) => ({ kind: 'sensor' as const, alert: s.in_breach })), ...d.cameras.map(() => ({ kind: 'camera' as const, alert: false }))]
      satellites.forEach((sat, i) => {
        const angle = (i / Math.max(1, satellites.length)) * Math.PI * 2
        const mesh = sat.kind === 'sensor'
          ? new THREE.Mesh(new THREE.SphereGeometry(0.55, 16, 16), new THREE.MeshStandardMaterial({ color: sat.alert ? 0xf0565b : 0x22d3ee, emissive: sat.alert ? 0xf0565b : 0x0e7490, emissiveIntensity: 0.6 }))
          : new THREE.Mesh(new THREE.ConeGeometry(0.6, 1.4, 16), new THREE.MeshStandardMaterial({ color: 0xa78bfa, emissive: 0x4c1d95 }))
        mesh.position.set(Math.cos(angle) * 3.4, 0.8, Math.sin(angle) * 3.4)
        if (sat.kind === 'camera') mesh.rotation.z = Math.PI / 2
        group.add(mesh)
      })
      const name = label(`${d.name}${d.is_simulated ? ' · sim' : ''}${place.auto ? ' · not placed' : ''}`, d.open_alerts ? '#ffb4b6' : '#e7edf4', 24)
      name.position.y = h + (d.open_incidents.length ? 7.8 : 1.8)
      group.add(name)
      ctx.content.add(group)
    })
  }, [twin, placements, selectedId])

  return <div ref={host} className="absolute inset-0" data-testid="twin-canvas" />
}
