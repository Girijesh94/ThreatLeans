import {Suspense, useEffect, useRef, useState} from 'react'
import {Canvas, useFrame} from '@react-three/fiber'
import {ShaderGradient, ShaderGradientCanvas} from '@shadergradient/react'
import {LiquidMetal} from '@paper-design/shaders-react'
import * as THREE from 'three'
import Container from './vendor/liquid-glass'

function Lens({motion, selected}: {motion:boolean; selected:number}) {
  const group = useRef<THREE.Group>(null)
  useFrame(({clock, pointer}) => {
    if (!group.current) return
    const target = new THREE.Euler(.28 + pointer.y * .18, (motion ? clock.elapsedTime * .09 : .35) + pointer.x * .2, -.42)
    group.current.rotation.x = THREE.MathUtils.lerp(group.current.rotation.x, target.x, .035)
    group.current.rotation.y = THREE.MathUtils.lerp(group.current.rotation.y, target.y, .035)
    group.current.rotation.z = target.z
  })
  return <group ref={group}>
    {[0,1,2,3].map(i => <mesh key={i} rotation={[i*.42,i*.25,i*.18]}>
      <torusGeometry args={[1.62-i*.21,.085+i*.015,16,100]}/>
      <meshStandardMaterial color={selected === i % 3 ? '#d4b294' : '#9ea8b6'} metalness={.94} roughness={.22}/>
    </mesh>)}
    <mesh rotation={[.3,.3,.2]}><icosahedronGeometry args={[.48,1]}/><meshPhysicalMaterial color="#cfb99f" metalness={.85} roughness={.2} clearcoat={1}/></mesh>
  </group>
}

function RefractivePlate() {
  const host = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!host.current) return
    const snapshot=document.createElement('canvas'); snapshot.width=window.innerWidth; snapshot.height=window.innerHeight
    const context=snapshot.getContext('2d'); if(!context) return
    const wash=context.createLinearGradient(0,0,snapshot.width,snapshot.height)
    wash.addColorStop(0,'#20232b'); wash.addColorStop(.5,'#8d8175'); wash.addColorStop(1,'#393d47')
    context.fillStyle=wash; context.fillRect(0,0,snapshot.width,snapshot.height)
    Container.pageSnapshot=snapshot
    const glass = new Container({borderRadius:24,tintOpacity:.12})
    host.current.append(glass.element); glass.element.style.width='100%'; glass.element.style.height='100%'
    glass.updateSizeFromDOM()
    const resize=()=>glass.updateSizeFromDOM(); window.addEventListener('resize',resize)
    return ()=>{window.removeEventListener('resize',resize); glass.destroy(); Container.pageSnapshot=null}
  },[])
  return <div className="refractive-plate" ref={host} aria-hidden="true"/>
}

export default function Scene({motion, selected}: {motion:boolean; selected:number}) {
  const host=useRef<HTMLDivElement>(null)
  const [visible,setVisible]=useState(!document.hidden)
  useEffect(()=>{let onScreen=true;const handle=()=>setVisible(onScreen&&!document.hidden);const observer=new IntersectionObserver(([entry])=>{onScreen=entry.isIntersecting;handle()},{rootMargin:'100px'});if(host.current)observer.observe(host.current);document.addEventListener('visibilitychange',handle);return()=>{observer.disconnect();document.removeEventListener('visibilitychange',handle)}},[])
  return <div className="scene-art" ref={host} aria-label="Animated three-dimensional evidence lens; decorative visualization">
    {visible && <>
      <div className="material-wash" aria-hidden="true"><ShaderGradientCanvas pixelDensity={1} lazyLoad pointerEvents="none">
        <ShaderGradient control="props" animate={motion ? 'on':'off'} type="plane" lightType="3d" grain="off"
          color1="#252832" color2="#967d68" color3="#465268" brightness={.8} uSpeed={.12} uStrength={2} cDistance={3.8}/>
      </ShaderGradientCanvas></div>
      <Canvas camera={{position:[0,0,5.6],fov:40}} dpr={[1,1.5]} frameloop={motion ? 'always':'demand'} gl={{antialias:true,alpha:true,powerPreference:'low-power'}}>
        <ambientLight intensity={1.1}/><directionalLight position={[4,3,4]} intensity={5} color="#f1ddc4"/>
        <directionalLight position={[-4,-2,3]} intensity={4} color="#b2c8ed"/>
        <Suspense fallback={null}><Lens motion={motion} selected={selected}/></Suspense>
      </Canvas>
      <RefractivePlate/>
      <div className="liquid-seal" aria-hidden="true"><LiquidMetal image="/mark.svg" colorBack="#00000000" colorTint="#bdb2a7" speed={motion ? .24 : 0} repetition={3} maxPixelCount={160000} width={130} height={130}/></div>
    </>}
  </div>
}
