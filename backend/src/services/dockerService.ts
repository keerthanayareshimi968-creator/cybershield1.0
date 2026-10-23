import http from 'http';
import fs from 'fs';
import os from 'os';

export interface DockerContainerInfo {
  id: string;
  name: string;
  deviceId: string;
  image: string;
  status: 'running' | 'stopped' | 'exited' | 'created';
  created: number;
  ports?: string;
  health?: 'healthy' | 'unhealthy' | 'starting' | 'none';
}

export interface DockerEngineStatus {
  available: boolean;
  mode: 'DOCKER_ENGINE' | 'OFFLINE_TEST_MODE';
  socketPath: string;
  version?: string;
  runningContainers: number;
  totalContainers: number;
  containers: DockerContainerInfo[];
  message: string;
  resourceLimits: {
    maxMemoryMb: number;
    cpuQuotaFraction: number;
    nonRootUser: string;
    privilegedAllowed: boolean;
    hostNetworkAllowed: boolean;
  };
}

// Approved device container images mapped to virtual device IDs
export const APPROVED_CONTAINER_IMAGES: Record<string, { image: string; tag: string; description: string }> = {
  'DEV-CAM-01': { image: 'cybershield-camera', tag: 'latest', description: 'TP-Link Tapo C200 Reference Container' },
  'DEV-LCK-02': { image: 'cybershield-locker', tag: 'latest', description: 'DIY ESP32 Keypad Locker Reference Container' },
  'DEV-ENV-03': { image: 'cybershield-sensor', tag: 'latest', description: 'DHT22 / AM2302 Sensor Reference Container' },
  'DEV-RTR-04': { image: 'cybershield-router', tag: 'latest', description: 'TP-Link Archer C6 Router Reference Container' },
};

function getSocketPath(): string {
  if (process.platform === 'win32') {
    return '//./pipe/docker_engine';
  }
  return '/var/run/docker.sock';
}

/**
 * Perform low-level HTTP request to Docker Engine daemon over Unix domain socket
 */
function dockerApiRequest<T = any>(endpoint: string, method: string = 'GET', data?: any): Promise<T> {
  return new Promise((resolve, reject) => {
    const socketPath = getSocketPath();

    if (!fs.existsSync(socketPath) && process.platform !== 'win32') {
      return reject(new Error(`Docker socket not found at ${socketPath}`));
    }

    const options: http.RequestOptions = {
      socketPath,
      path: endpoint,
      method,
      headers: {
        'Content-Type': 'application/json',
        Host: 'docker.sock',
      },
      timeout: 3000,
    };

    const req = http.request(options, (res) => {
      let rawData = '';
      res.on('data', (chunk) => {
        rawData += chunk;
      });
      res.on('end', () => {
        if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
          try {
            const parsed = rawData ? JSON.parse(rawData) : {};
            resolve(parsed);
          } catch {
            resolve(rawData as unknown as T);
          }
        } else {
          reject(new Error(`Docker API error (${res.statusCode}): ${rawData}`));
        }
      });
    });

    req.on('error', (err) => {
      reject(err);
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Docker API request timed out'));
    });

    if (data) {
      req.write(typeof data === 'string' ? data : JSON.stringify(data));
    }
    req.end();
  });
}

/**
 * Check Docker Engine availability and fetch container statuses
 */
export async function getDockerStatus(): Promise<DockerEngineStatus> {
  const socketPath = getSocketPath();
  const defaultLimits = {
    maxMemoryMb: 128,
    cpuQuotaFraction: 0.5,
    nonRootUser: 'iotuser (1001:1001)',
    privilegedAllowed: false,
    hostNetworkAllowed: false,
  };

  try {
    const versionInfo = await dockerApiRequest<any>('/version');
    const containersRaw = await dockerApiRequest<any[]>('/containers/json?all=1');

    const containers: DockerContainerInfo[] = (containersRaw || []).map((c) => {
      const name = (c.Names && c.Names[0] ? c.Names[0].replace(/^\//, '') : c.Id.substring(0, 12));
      const deviceId = name.replace(/^cybershield-/, '').toUpperCase();
      return {
        id: c.Id.substring(0, 12),
        name,
        deviceId,
        image: c.Image,
        status: c.State === 'running' ? 'running' : 'stopped',
        created: c.Created,
        health: c.Status?.includes('(healthy)') ? 'healthy' : 'none',
      };
    });

    const running = containers.filter((c) => c.status === 'running').length;

    return {
      available: true,
      mode: 'DOCKER_ENGINE',
      socketPath,
      version: versionInfo?.Version || 'Docker Engine Connected',
      runningContainers: running,
      totalContainers: containers.length,
      containers,
      message: `Connected to Docker Engine v${versionInfo?.Version || 'unknown'} via ${socketPath}. Device container isolation active.`,
      resourceLimits: defaultLimits,
    };
  } catch (err: any) {
    // Graceful offline fallback
    return {
      available: false,
      mode: 'OFFLINE_TEST_MODE',
      socketPath,
      runningContainers: 0,
      totalContainers: 0,
      containers: [],
      message: `Offline Test Mode: Docker daemon is not connected (${err.message}). Virtual devices execute safely in the built-in Node.js software sandbox. Real containers can be run locally using Docker Desktop.`,
      resourceLimits: defaultLimits,
    };
  }
}

/**
 * Start or create an emulated device container with strict security settings
 */
export async function startDeviceContainer(deviceId: string): Promise<{ success: boolean; containerId?: string; message: string }> {
  const approved = APPROVED_CONTAINER_IMAGES[deviceId];
  if (!approved) {
    throw new Error(`Device '${deviceId}' does not have an approved container image definition.`);
  }

  const containerName = `cybershield-${deviceId.toLowerCase()}`;

  try {
    // 1. Inspect existing container
    let existingId: string | null = null;
    try {
      const inspect = await dockerApiRequest<any>(`/containers/${containerName}/json`);
      if (inspect && inspect.Id) {
        existingId = inspect.Id;
      }
    } catch {
      existingId = null;
    }

    // 2. Create if not exists (with non-root user, memory limit 128MB, CPU limit 0.5, no privileged)
    if (!existingId) {
      const createPayload = {
        Image: `${approved.image}:${approved.tag}`,
        User: '1001:1001', // Non-root container user
        NetworkDisabled: false,
        HostConfig: {
          Memory: 128 * 1024 * 1024, // 128 MB limit
          MemorySwap: 128 * 1024 * 1024,
          NanoCpus: 500000000, // 0.5 CPU
          Privileged: false, // Disallow privileged mode
          NetworkMode: 'bridge', // Restricted bridge network, no host networking
          ReadonlyRootfs: false,
          SecurityOpt: ['no-new-privileges:true'],
          RestartPolicy: { Name: 'no' },
        },
        Labels: {
          'com.cybershield.device-id': deviceId,
          'com.cybershield.managed': 'true',
        },
      };

      const createRes = await dockerApiRequest<any>(`/containers/create?name=${containerName}`, 'POST', createPayload);
      existingId = createRes.Id;
    }

    // 3. Start container
    await dockerApiRequest(`/containers/${existingId}/start`, 'POST');

    return {
      success: true,
      containerId: existingId ? existingId.substring(0, 12) : undefined,
      message: `Docker container '${containerName}' started with non-root user and 128MB resource limit.`,
    };
  } catch (err: any) {
    return {
      success: false,
      message: `Docker execution error: ${err.message}. Ensure Docker Desktop is running and '${approved.image}' image is built.`,
    };
  }
}

/**
 * Stop an emulated device container
 */
export async function stopDeviceContainer(deviceId: string): Promise<{ success: boolean; message: string }> {
  const containerName = `cybershield-${deviceId.toLowerCase()}`;
  try {
    await dockerApiRequest(`/containers/${containerName}/stop?t=3`, 'POST');
    return {
      success: true,
      message: `Docker container '${containerName}' stopped cleanly.`,
    };
  } catch (err: any) {
    return {
      success: false,
      message: `Docker stop error: ${err.message}`,
    };
  }
}

/**
 * Restart an emulated device container
 */
export async function restartDeviceContainer(deviceId: string): Promise<{ success: boolean; message: string }> {
  const containerName = `cybershield-${deviceId.toLowerCase()}`;
  try {
    await dockerApiRequest(`/containers/${containerName}/restart?t=3`, 'POST');
    return {
      success: true,
      message: `Docker container '${containerName}' restarted.`,
    };
  } catch (err: any) {
    return {
      success: false,
      message: `Docker restart error: ${err.message}`,
    };
  }
}
