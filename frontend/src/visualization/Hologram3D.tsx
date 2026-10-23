import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { DeviceType, DeviceStatus, SecurityStatus } from '../types';
import { Play, Pause, RotateCw, Eye, EyeOff, ShieldCheck, ShieldAlert, Cpu } from 'lucide-react';

interface HologramProps {
  deviceType: DeviceType;
  deviceStatus: DeviceStatus;
  securityStatus: SecurityStatus;
  affectedComponent?: string | null;
  verificationActive?: boolean;
  highlightError?: boolean;
  deviceName?: string;
}

export const Hologram3D: React.FC<HologramProps> = ({
  deviceType,
  deviceStatus,
  securityStatus,
  affectedComponent,
  verificationActive = false,
  highlightError = false,
  deviceName,
}) => {
  const mountRef = useRef<HTMLDivElement>(null);
  const [isPaused, setIsPaused] = useState(false);
  const [renderMode2D, setRenderMode2D] = useState(false);
  const [webGlSupported, setWebGlSupported] = useState(true);

  const sceneRef = useRef<THREE.Scene | null>(null);
  const rendererRef = useRef<THREE.WebGLRenderer | null>(null);
  const groupRef = useRef<THREE.Group | null>(null);
  const ringsGroupRef = useRef<THREE.Group | null>(null);
  const affectedMeshRef = useRef<THREE.Mesh | null>(null);
  const scanPlaneRef = useRef<THREE.Mesh | null>(null);
  const animFrameId = useRef<number | null>(null);

  // Dynamic theme colors based on state
  const isRejected = deviceStatus === 'UPDATE_REJECTED' || securityStatus === 'COMPROMISED' || highlightError;
  const isHealthy = deviceStatus === 'RUNNING' || deviceStatus === 'HEALTHY';
  const isVerifying = verificationActive || deviceStatus === 'VERIFYING' || deviceStatus === 'UPDATING';
  const isStopped = deviceStatus === 'STOPPED';

  const primaryColor = isRejected ? 0xef4444 : isHealthy ? 0x00f2fe : isVerifying ? 0x38bdf8 : 0x64748b;
  const glowColor = isRejected ? 0xdc2626 : isHealthy ? 0x06b6d4 : 0x0284c7;

  useEffect(() => {
    if (renderMode2D || !mountRef.current) return;

    // Check WebGL availability safely
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) {
        setWebGlSupported(false);
        setRenderMode2D(true);
        return;
      }
    } catch {
      setWebGlSupported(false);
      setRenderMode2D(true);
      return;
    }

    const width = mountRef.current.clientWidth || 380;
    const height = mountRef.current.clientHeight || 320;

    // 1. Scene, Camera, Renderer
    const scene = new THREE.Scene();
    sceneRef.current = scene;

    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.set(0, 1.8, 4.2);
    camera.lookAt(0, 0, 0);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    mountRef.current.innerHTML = '';
    mountRef.current.appendChild(renderer.domElement);
    rendererRef.current = renderer;

    // 2. Holographic Lighting
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.9);
    scene.add(ambientLight);

    const pointLight = new THREE.PointLight(glowColor, 2.5, 50);
    pointLight.position.set(2, 4, 3);
    scene.add(pointLight);

    // 3. Grid Platform & Rotating Rings
    const gridHelper = new THREE.GridHelper(3, 16, glowColor, 0x1e293b);
    gridHelper.position.y = -1.2;
    scene.add(gridHelper);

    const ringsGroup = new THREE.Group();
    ringsGroupRef.current = ringsGroup;
    scene.add(ringsGroup);

    for (let i = 0; i < 3; i++) {
      const ringGeo = new THREE.RingGeometry(1.0 + i * 0.35, 1.02 + i * 0.35, 32);
      const ringMat = new THREE.MeshBasicMaterial({
        color: glowColor,
        side: THREE.DoubleSide,
        transparent: true,
        opacity: 0.35 - i * 0.08,
      });
      const ring = new THREE.Mesh(ringGeo, ringMat);
      ring.rotation.x = Math.PI / 2;
      ring.position.y = -1.18 + i * 0.05;
      ringsGroup.add(ring);
    }

    // 4. Scanning laser plane for verification state
    const scanGeo = new THREE.PlaneGeometry(2.6, 2.6);
    const scanMat = new THREE.MeshBasicMaterial({
      color: 0x38bdf8,
      transparent: true,
      opacity: 0.25,
      side: THREE.DoubleSide,
    });
    const scanPlane = new THREE.Mesh(scanGeo, scanMat);
    scanPlane.rotation.x = Math.PI / 2;
    scanPlane.position.y = 0;
    scanPlaneRef.current = scanPlane;
    scene.add(scanPlane);

    // 5. Build Procedural 3D Device Model
    const modelGroup = new THREE.Group();
    groupRef.current = modelGroup;
    scene.add(modelGroup);

    buildDeviceModel(modelGroup, deviceType, primaryColor, affectedComponent);

    // 6. Animation Loop
    let clock = new THREE.Clock();
    let scanDirection = 1;

    const animate = () => {
      animFrameId.current = requestAnimationFrame(animate);

      if (isPaused) {
        renderer.render(scene, camera);
        return;
      }

      const elapsed = clock.getElapsedTime();

      // Rotate model slowly if running
      if (modelGroup && !isStopped) {
        modelGroup.rotation.y = elapsed * 0.45;
      }

      // Rotate scanner rings
      if (ringsGroup && !isStopped) {
        ringsGroup.rotation.y = -elapsed * 0.6;
      }

      // Vertical scanning beam if verifying
      if (scanPlane) {
        if (isVerifying) {
          scanPlane.visible = true;
          scanPlane.position.y += 0.02 * scanDirection;
          if (scanPlane.position.y > 1.2) scanDirection = -1;
          if (scanPlane.position.y < -1.0) scanDirection = 1;
        } else {
          scanPlane.visible = false;
        }
      }

      // Blink affected component mesh if attack error is active
      if (affectedMeshRef.current && isRejected) {
        const pulse = (Math.sin(elapsed * 8) + 1) / 2;
        (affectedMeshRef.current.material as THREE.MeshStandardMaterial).emissiveIntensity = pulse * 2.0;
      }

      renderer.render(scene, camera);
    };

    animate();

    const handleResize = () => {
      if (!mountRef.current || !renderer) return;
      const w = mountRef.current.clientWidth;
      const h = mountRef.current.clientHeight;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };

    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
      if (animFrameId.current) cancelAnimationFrame(animFrameId.current);
      if (renderer) renderer.dispose();
    };
  }, [deviceType, deviceStatus, securityStatus, affectedComponent, isPaused, renderMode2D, isRejected, isHealthy, isVerifying, isStopped]);

  // Construct recognizable procedural 3D model per device type
  function buildDeviceModel(group: THREE.Group, type: DeviceType, col: number, affected?: string | null) {
    const wireMat = new THREE.MeshStandardMaterial({
      color: col,
      roughness: 0.2,
      metalness: 0.8,
      wireframe: true,
      transparent: true,
      opacity: 0.85,
    });

    const glowMat = new THREE.MeshStandardMaterial({
      color: col,
      emissive: col,
      emissiveIntensity: 0.4,
      transparent: true,
      opacity: 0.45,
    });

    const errorMat = new THREE.MeshStandardMaterial({
      color: 0xef4444,
      emissive: 0xef4444,
      emissiveIntensity: 0.9,
      wireframe: true,
    });

    switch (type) {
      case 'camera': {
        // Camera Base / Mounting plate
        const base = new THREE.Mesh(new THREE.CylinderGeometry(0.5, 0.6, 0.15, 16), wireMat);
        base.position.y = -0.8;
        group.add(base);

        // Arm Stem
        const arm = new THREE.Mesh(new THREE.CylinderGeometry(0.1, 0.1, 0.6, 12), wireMat);
        arm.position.set(0, -0.45, 0);
        group.add(arm);

        // Camera Body Housing
        const bodyGeo = new THREE.CylinderGeometry(0.35, 0.45, 1.2, 16);
        const body = new THREE.Mesh(bodyGeo, wireMat);
        body.rotation.z = Math.PI / 2.2;
        body.position.set(0, 0.1, 0);
        group.add(body);

        // Lens Barrel (affected component: video pipeline)
        const lensGeo = new THREE.CylinderGeometry(0.25, 0.25, 0.4, 16);
        const lensMat = affected?.includes('Video') ? errorMat : glowMat;
        const lens = new THREE.Mesh(lensGeo, lensMat);
        lens.rotation.z = Math.PI / 2.2;
        lens.position.set(0.65, 0.2, 0);
        group.add(lens);
        if (affected?.includes('Video')) affectedMeshRef.current = lens;

        // Front Glass Optics
        const glass = new THREE.Mesh(new THREE.SphereGeometry(0.2, 16, 16), glowMat);
        glass.position.set(0.85, 0.26, 0);
        group.add(glass);
        break;
      }

      case 'environmental_sensor': {
        // Hexagonal Environmental Pod Housing
        const podGeo = new THREE.CylinderGeometry(0.65, 0.65, 0.8, 6);
        const pod = new THREE.Mesh(podGeo, wireMat);
        group.add(pod);

        // Ventilation Fin Grills (affected component: telemetry/ADC)
        const grillGeo = new THREE.TorusGeometry(0.72, 0.05, 8, 24);
        const grillMat = affected?.includes('Telemetry') || affected?.includes('Measurement') ? errorMat : wireMat;
        const grill = new THREE.Mesh(grillGeo, grillMat);
        grill.rotation.x = Math.PI / 2;
        group.add(grill);
        if (affected?.includes('Telemetry') || affected?.includes('Measurement')) affectedMeshRef.current = grill;

        // Top Sampling Dome
        const domeGeo = new THREE.SphereGeometry(0.45, 16, 16, 0, Math.PI * 2, 0, Math.PI / 2);
        const dome = new THREE.Mesh(domeGeo, glowMat);
        dome.position.y = 0.4;
        group.add(dome);
        break;
      }

      case 'smart_lock': {
        // Heavy Lock Chassis
        const chassisGeo = new THREE.BoxGeometry(0.7, 1.3, 0.35);
        const chassis = new THREE.Mesh(chassisGeo, wireMat);
        group.add(chassis);

        // Keypad Touchpad Area
        const padGeo = new THREE.PlaneGeometry(0.5, 0.5);
        const pad = new THREE.Mesh(padGeo, glowMat);
        pad.position.set(0, 0.3, 0.18);
        group.add(pad);

        // Solenoid Deadbolt Actuator Pin (affected component: Solenoid actuator)
        const boltGeo = new THREE.CylinderGeometry(0.14, 0.14, 0.6, 16);
        const boltMat = affected?.includes('Solenoid') || affected?.includes('Actuator') || affected?.includes('Lock') ? errorMat : glowMat;
        const bolt = new THREE.Mesh(boltGeo, boltMat);
        bolt.rotation.z = Math.PI / 2;
        bolt.position.set(0.45, -0.25, 0);
        group.add(bolt);
        if (affected?.includes('Solenoid') || affected?.includes('Actuator') || affected?.includes('Lock')) affectedMeshRef.current = bolt;
        break;
      }

      case 'router': {
        // Router Flat Gateway Body
        const bodyGeo = new THREE.BoxGeometry(1.3, 0.25, 0.85);
        const bodyMesh = new THREE.Mesh(bodyGeo, wireMat);
        group.add(bodyMesh);

        // Central LED Status Bar (affected: packet routing/firewall)
        const ledBarGeo = new THREE.BoxGeometry(1.1, 0.04, 0.04);
        const ledMat = affected?.includes('Routing') || affected?.includes('Firewall') || affected?.includes('Kernel') ? errorMat : glowMat;
        const ledBar = new THREE.Mesh(ledBarGeo, ledMat);
        ledBar.position.set(0, 0.13, 0.38);
        group.add(ledBar);
        if (affected?.includes('Routing') || affected?.includes('Firewall') || affected?.includes('Kernel')) affectedMeshRef.current = ledBar;

        // Dual Antenna Array
        for (let i of [-0.5, 0.5]) {
          const antGeo = new THREE.CylinderGeometry(0.04, 0.04, 0.9, 8);
          const ant = new THREE.Mesh(antGeo, wireMat);
          ant.position.set(i, 0.45, -0.38);
          group.add(ant);
        }
        break;
      }
    }
  }

  return (
    <div className="relative w-full h-[320px] rounded-xl overflow-hidden bg-gradient-to-b from-slate-900/90 to-slate-950/90 border border-slate-800 shadow-2xl flex flex-col justify-between">
      {/* Top Hologram Controls & Header */}
      <div className="flex items-center justify-between p-3 z-10 bg-slate-950/50 backdrop-blur-md border-b border-slate-800/60">
        <div className="flex items-center gap-2">
          <div className={`w-2.5 h-2.5 rounded-full ${isRejected ? 'bg-red-500 animate-pulse' : isHealthy ? 'bg-cyan-400 animate-pulse' : 'bg-slate-500'}`} />
          <span className="text-xs font-mono font-bold tracking-wider uppercase text-cyan-300">
            {deviceName || deviceType.replace('_', ' ')}
          </span>
          <span className="text-[10px] px-1.5 py-0.5 rounded font-mono bg-slate-800 text-slate-300 border border-slate-700">
            {deviceStatus}
          </span>
        </div>

        <div className="flex items-center gap-1.5">
          <button
            onClick={() => setIsPaused(!isPaused)}
            className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-100 transition-colors"
            title={isPaused ? 'Resume animation' : 'Pause animation'}
          >
            {isPaused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
          </button>
          <button
            onClick={() => setRenderMode2D(!renderMode2D)}
            className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-100 transition-colors"
            title={renderMode2D ? 'Switch to 3D View' : 'Switch to 2D Fallback'}
          >
            {renderMode2D ? <Eye className="w-3.5 h-3.5" /> : <EyeOff className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>

      {/* 3D Canvas Mount or 2D Fallback */}
      <div className="relative flex-1 w-full h-full flex items-center justify-center">
        {!renderMode2D ? (
          <div ref={mountRef} className="w-full h-full cursor-grab active:cursor-grabbing" />
        ) : (
          <div className="flex flex-col items-center justify-center p-6 text-center">
            <div className={`w-24 h-24 rounded-2xl flex items-center justify-center border-2 border-dashed ${isRejected ? 'border-red-500/60 bg-red-950/20 text-red-400' : 'border-cyan-500/60 bg-cyan-950/20 text-cyan-300'}`}>
              <Cpu className="w-12 h-12" />
            </div>
            <p className="mt-3 text-xs font-mono font-semibold text-slate-300 uppercase">
              2D Schematic Mode · {deviceType.toUpperCase()}
            </p>
            <p className="text-[11px] text-slate-400 mt-1 max-w-xs">
              Procedural vector schematic active. Low-resource mode enabled.
            </p>
          </div>
        )}

        {/* Verification Scanning Overlay */}
        {isVerifying && (
          <div className="absolute inset-0 pointer-events-none flex flex-col items-center justify-center bg-cyan-500/5">
            <div className="w-full h-0.5 bg-gradient-to-r from-transparent via-cyan-400 to-transparent shadow-[0_0_12px_#00f2fe] animate-bounce" />
            <span className="mt-4 px-2.5 py-1 text-[11px] font-mono font-bold bg-cyan-950/90 text-cyan-300 border border-cyan-500/50 rounded-full shadow-lg">
              SCANNING FIRMWARE PARTITION…
            </span>
          </div>
        )}

        {/* Attack Impact Warning Banner */}
        {isRejected && affectedComponent && (
          <div className="absolute bottom-2 left-2 right-2 p-2 rounded-lg bg-red-950/80 border border-red-500/60 backdrop-blur-md flex items-center gap-2 text-xs text-red-200">
            <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />
            <div className="truncate">
              <span className="font-semibold text-red-300">Target Component:</span> {affectedComponent}
            </div>
          </div>
        )}
      </div>

      {/* Hologram Bottom Status Bar */}
      <div className="p-2 px-3 z-10 bg-slate-950/70 border-t border-slate-800/60 flex items-center justify-between text-[11px] font-mono text-slate-400">
        <span className="flex items-center gap-1.5">
          <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
          Hologram Visualizer · Three.js WebGL
        </span>
        <span className="text-slate-500">Virtual Software Emulation Only</span>
      </div>
    </div>
  );
};
