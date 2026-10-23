import { execSync } from 'node:child_process';
import fs from 'node:fs';

export const APPROVED_EMULATORS = [
  {
    deviceId: 'DEV-CAM-01',
    name: 'TP-Link Tapo C200 Emulator',
    service: 'emulator-camera',
    image: 'cybershield/tapo-c200-emulator:v2.0',
    nonRootUser: '1001:1001',
    memoryLimit: '256M',
    cpuLimit: '0.50',
    networkIsolation: 'Internal bridge network',
    ports: '554/tcp, 8080/tcp',
    capabilitiesDropped: ['ALL'],
    readOnlyRoot: true
  },
  {
    deviceId: 'DEV-LCK-02',
    name: 'ESP32 Smart Locker Emulator',
    service: 'emulator-locker',
    image: 'cybershield/esp32-locker-emulator:v1.4',
    nonRootUser: '1001:1001',
    memoryLimit: '128M',
    cpuLimit: '0.25',
    networkIsolation: 'Internal bridge network',
    ports: '8081/tcp',
    capabilitiesDropped: ['ALL'],
    readOnlyRoot: true
  },
  {
    deviceId: 'DEV-ENV-03',
    name: 'DHT22 / AM2302 Sensor Emulator',
    service: 'emulator-sensor',
    image: 'cybershield/dht22-sensor-emulator:v1.1',
    nonRootUser: '1001:1001',
    memoryLimit: '128M',
    cpuLimit: '0.25',
    networkIsolation: 'Internal bridge network',
    ports: '8082/tcp',
    capabilitiesDropped: ['ALL'],
    readOnlyRoot: true
  },
  {
    deviceId: 'DEV-RTR-04',
    name: 'TP-Link Archer C6 Router Emulator',
    service: 'emulator-router',
    image: 'cybershield/archer-c6-emulator:v1.2',
    nonRootUser: '1001:1001',
    memoryLimit: '256M',
    cpuLimit: '0.50',
    networkIsolation: 'Internal bridge network',
    ports: '8443/tcp',
    capabilitiesDropped: ['ALL'],
    readOnlyRoot: true
  }
];

/**
 * Perform actual check of Docker daemon availability
 */
export function checkDockerStatus() {
  const socketExists = fs.existsSync('/var/run/docker.sock');
  let cliAvailable = false;
  let daemonRunning = false;
  let rawOutput = '';
  let containerList = [];

  try {
    const versionOut = execSync('docker --version', { stdio: ['pipe', 'pipe', 'pipe'], timeout: 2000 }).toString().trim();
    cliAvailable = true;

    // Check daemon
    const psOut = execSync('docker ps --format "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}"', { stdio: ['pipe', 'pipe', 'pipe'], timeout: 3000 }).toString().trim();
    daemonRunning = true;
    rawOutput = psOut;

    if (psOut) {
      containerList = psOut.split('\n').filter(Boolean).map(line => {
        const [id, name, image, status] = line.split('|');
        return { id, name, image, status };
      });
    }
  } catch (err) {
    // Docker is either not installed or daemon not running
    rawOutput = err.message;
  }

  const isAvailable = cliAvailable && daemonRunning;

  return {
    available: isAvailable,
    status: isAvailable ? 'RUNNING' : 'UNAVAILABLE',
    cliInstalled: cliAvailable,
    socketExists,
    daemonActive: daemonRunning,
    containers: containerList,
    message: isAvailable
      ? 'Docker Engine active; containerized device emulators monitored.'
      : 'Docker daemon unavailable in current environment. Software emulation mode active; device logic is simulated by Node.js backend. To run full Docker Compose container fleet with isolated micro-containers, use local setup instructions.',
    approvedEmulators: APPROVED_EMULATORS
  };
}
