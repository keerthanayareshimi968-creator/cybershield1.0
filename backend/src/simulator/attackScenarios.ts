import { getDatabase, queryOne, execute } from '../database/db.js';
import { generateFirmwarePackage } from '../services/packageGenerator.js';
import { validateAndVerifyFirmware } from '../security/packageValidator.js';
import { handleRejectedFirmwareUpdate } from './deviceSimulator.js';

export interface AttackScenarioDefinition {
  type: string;
  name: string;
  description: string;
  expectedFailedCheck: string;
  attackVector: string;
  componentByDeviceType: Record<string, { component: string; consequence: string; defensiveAction: string }>;
}

export const ATTACK_SCENARIOS: Record<string, AttackScenarioDefinition> = {
  invalid_signature: {
    type: 'invalid_signature',
    name: 'Forged / Corrupted Digital Signature',
    description: 'Adversary modifies the firmware container or provides a forged cryptographic signature without possessing the trusted Ed25519 private key.',
    expectedFailedCheck: 'Ed25519 Digital Signature Authenticity',
    attackVector: 'Cryptographic forgery / signature corruption in transit',
    componentByDeviceType: {
      camera: {
        component: 'Video Streaming & RTSP Capture Pipeline',
        consequence: 'Unauthorized RTSP video feed hijacking, video blackout, or remote credential exfiltration.',
        defensiveAction: 'Digital signature verification rejects untrusted payload before staging. Camera stream uninterrupted.',
      },
      environmental_sensor: {
        component: 'Telemetry Acquisition Unit (ADC & Modbus)',
        consequence: 'Sensor metric spoofing, falsified temperature spikes, or suppressed safety hazard alerts.',
        defensiveAction: 'Package discarded at signature validation. Safe sensor calibration preserved.',
      },
      smart_lock: {
        component: 'Solenoid Actuator & Access Controller',
        consequence: 'Forced physical door unlock, master credential bypass, or lockout of legitimate occupants.',
        defensiveAction: 'Signature mismatch halts flashing. Lock lines remain securely latched.',
      },
      router: {
        component: 'Packet Routing Engine & Firewall Daemon',
        consequence: 'Man-in-the-Middle packet sniffing, malicious DNS redirection, or recruitment into IoT botnet.',
        defensiveAction: 'Untrusted package dropped at boundary. Core routing tables remain untouched.',
      },
    },
  },

  modified_firmware: {
    type: 'modified_firmware',
    name: 'Firmware Payload Modification (Tampering)',
    description: 'Adversary injects malicious opcodes into firmware.bin after signing, resulting in a cryptographic hash mismatch against manifest.json.',
    expectedFailedCheck: 'Firmware Binary Hash Verification',
    attackVector: 'Man-in-the-Middle payload tampering or mirror corruption',
    componentByDeviceType: {
      camera: {
        component: 'Flash Memory Partition & Boot Executable',
        consequence: 'Injected backdoor payload executing in camera supervisor mode.',
        defensiveAction: 'SHA-256 verification fails immediately. Corrupted binary purged from temporary memory.',
      },
      environmental_sensor: {
        component: 'Measurement Service & Sensor Microcontroller',
        consequence: 'Erratic readings, battery drain attack, or buffer overflow execution.',
        defensiveAction: 'Hash disparity triggers immediate drop. Device maintains factory baseline.',
      },
      smart_lock: {
        component: 'Secure Keypad Controller & Lock Supervisor',
        consequence: 'Unauthorized door actuation via corrupted driver logic.',
        defensiveAction: 'Hash comparison rejects file before flashing. Actuator driver untouched.',
      },
      router: {
        component: 'Network Kernel Image & Routing Daemon',
        consequence: 'Kernel-level rootkit deployment and DNS cache poisoning.',
        defensiveAction: 'Binary checksum mismatch aborts update. Clean kernel remains running.',
      },
    },
  },

  downgrade: {
    type: 'downgrade',
    name: 'Rollback / Firmware Downgrade Attack',
    description: 'Adversary forces the device to reinstall an older, previously approved firmware version that contains known unpatched CVE vulnerabilities.',
    expectedFailedCheck: 'Monotonic Version & Rollback Protection',
    attackVector: 'Rollback exploitation of legacy vulnerabilities',
    componentByDeviceType: {
      camera: {
        component: 'Network Stack & Web Interface Daemon',
        consequence: 'Revives patched buffer overflow vulnerabilities (e.g. CVE-2023-XXXX) for remote shell access.',
        defensiveAction: 'Strict monotonic version counter enforces version progression. Rollback request rejected.',
      },
      environmental_sensor: {
        component: 'BLE/Zigbee Radio Firmware',
        consequence: 'Exposes patched encryption flaws allowing unauthenticated local radio interception.',
        defensiveAction: 'Hardware minimum version policy blocks installation of deprecated software.',
      },
      smart_lock: {
        component: 'Bluetooth Access Protocol Handler',
        consequence: 'Re-enables patched replay flaws in old BLE pairing protocol.',
        defensiveAction: 'Device anti-rollback registers prohibit version regressions.',
      },
      router: {
        component: 'UPnP & WAN Administration Interface',
        consequence: 'Re-opens patched remote code execution vulnerability in router management port.',
        defensiveAction: 'Non-monotonic version check trips. Device firmware version remains at current level.',
      },
    },
  },

  replay: {
    type: 'replay',
    name: 'Update ID Replay Attack',
    description: 'Adversary captures an authentic past update broadcast and retransmits it over the network to disrupt device state or trigger unexpected restarts.',
    expectedFailedCheck: 'Anti-Replay Token Validation',
    attackVector: 'Network traffic sniffing and retransmission of prior update tokens',
    componentByDeviceType: {
      camera: {
        component: 'OTA State Machine & Session Coordinator',
        consequence: 'Denial of Service through continuous unneeded flashing cycles and service downtime.',
        defensiveAction: 'SQLite accepted_update_ids registry identifies reused UUID. Duplicate discarded.',
      },
      environmental_sensor: {
        component: 'Sensor Power Management Controller',
        consequence: 'Battery exhaustion through continuous flash memory erasing and writing.',
        defensiveAction: 'Replay token check rejects duplicate update before radio receiver powers up flash chip.',
      },
      smart_lock: {
        component: 'Access Verification Core',
        consequence: 'State confusion and lock cycling during repeated update handshakes.',
        defensiveAction: 'Duplicate update ID blocked at the gateway level.',
      },
      router: {
        component: 'Gateway Firmware Orchestrator',
        consequence: 'WAN connection dropping and recurring routing restart cycles.',
        defensiveAction: 'Nonce ledger blocks reused token. Firewall alerts security dashboard.',
      },
    },
  },

  unknown_key: {
    type: 'unknown_key',
    name: 'Untrusted / Rogue Signing Key',
    description: 'Adversary signs a firmware package using an unauthorized private key whose corresponding public key is not registered in the device hardware root of trust.',
    expectedFailedCheck: 'Ed25519 Digital Signature Authenticity',
    attackVector: 'Unauthorized certificate authority / rogue third-party firmware injection',
    componentByDeviceType: {
      camera: {
        component: 'Hardware Secure Element & Key Registry',
        consequence: 'Installation of rogue root certificate allowing persistent untrusted vendor management.',
        defensiveAction: 'Keystore lookup rejects unknown key ID. Package marked as UNTRUSTED.',
      },
      environmental_sensor: {
        component: 'Firmware Trust Verifier',
        consequence: 'Takeover of telemetry sensor network by rogue cloud platform.',
        defensiveAction: 'Unknown key identifier rejected. Only approved hardware signers accepted.',
      },
      smart_lock: {
        component: 'Root Trust Controller',
        consequence: 'Subversion of all cryptographic authentication mechanisms for lock access.',
        defensiveAction: 'Device hardware trust anchor rejects foreign key.',
      },
      router: {
        component: 'Firmware Signature Verification Module',
        consequence: 'Replacement of legitimate operating system with rogue surveillance firmware.',
        defensiveAction: 'Rogue key ID fails certificate hierarchy check. Binary quarantined.',
      },
    },
  },

  malformed: {
    type: 'malformed',
    name: 'Malformed Package Container / Zip Slip',
    description: 'Adversary submits corrupted metadata, missing signatures, or deceptive archive paths attempting parser crash or directory traversal.',
    expectedFailedCheck: 'Firmware Package Archive',
    attackVector: 'Zip-slip directory traversal or parser exploitation',
    componentByDeviceType: {
      camera: {
        component: 'Archive Extraction & Parser Service',
        consequence: 'System crash, denial of service, or arbitrary file overwrite via traversal.',
        defensiveAction: 'Safe in-memory ZIP inspection checks file entries. Traversal and malformed archives rejected.',
      },
      environmental_sensor: {
        component: 'Update Unpack Routine',
        consequence: 'Memory exhaustion or sensor microprocessor crash.',
        defensiveAction: 'Schema check rejects incomplete package before any memory allocation.',
      },
      smart_lock: {
        component: 'Container Parser',
        consequence: 'Buffer overflow or parser freeze leaving lock in unmanaged state.',
        defensiveAction: 'Strict schema enforcement validates structure before processing.',
      },
      router: {
        component: 'Firmware Daemon Ingestion Pipeline',
        consequence: 'Directory traversal escaping firmware sandbox into router rootfs.',
        defensiveAction: 'Path traversal detector halts extraction. Malformed file discarded.',
      },
    },
  },
};

export async function runAttackSimulation(deviceId: string, scenarioType: string): Promise<any> {
  const db = await getDatabase();
  const device = queryOne<any>(db, 'SELECT * FROM devices WHERE id = ?', [deviceId]);
  if (!device) {
    throw new Error(`Device '${deviceId}' not found.`);
  }

  const scenarioDef = ATTACK_SCENARIOS[scenarioType];
  if (!scenarioDef) {
    throw new Error(`Unsupported scenario '${scenarioType}'.`);
  }

  // If scenario is replay, ensure a prior update ID exists in accepted_update_ids
  let overrideUpdateId: string | undefined = undefined;
  if (scenarioType === 'replay') {
    const existingAccepted = queryOne<{ update_id: string }>(
      db,
      'SELECT update_id FROM accepted_update_ids WHERE device_id = ? LIMIT 1',
      [deviceId]
    );
    if (existingAccepted) {
      overrideUpdateId = existingAccepted.update_id;
    } else {
      // Seed an accepted ID first so the replay is authentic!
      overrideUpdateId = 'UPD-LEGACY-AUTH-001';
      execute(
        db,
        `INSERT OR IGNORE INTO accepted_update_ids (device_id, update_id, accepted_at)
         VALUES (?, ?, ?)`,
        [deviceId, overrideUpdateId, new Date(Date.now() - 3600000).toISOString()]
      );
    }
  }

  // Generate harmless test package for this scenario
  const packageData = await generateFirmwarePackage({
    deviceId,
    scenario: scenarioType as any,
    overrideUpdateId,
  });

  // Execute genuine backend verification
  const verification = await validateAndVerifyFirmware(packageData.buffer, deviceId, packageData.fileName);

  // Retrieve device component impact info
  const compInfo = scenarioDef.componentByDeviceType[device.type] || {
    component: 'Device Controller Subsystem',
    consequence: 'Potential service disruption or unauthorized code execution.',
    defensiveAction: 'Strict verification blocks untrusted firmware.',
  };

  const sessionId = `SIM-${Date.now()}`;
  const now = new Date().toISOString();

  // Handle rejected state in device simulator
  await handleRejectedFirmwareUpdate(
    deviceId,
    verification.reason,
    verification.updateId || 'N/A',
    scenarioDef.expectedFailedCheck
  );

  // Record simulation session in database
  execute(
    db,
    `INSERT INTO simulation_sessions (id, device_id, scenario_type, title, status, detected_check, affected_component, potential_impact, defense_action, steps_json, created_at)
     VALUES (?, ?, ?, ?, 'BLOCKED', ?, ?, ?, ?, ?, ?)`,
    [
      sessionId,
      deviceId,
      scenarioType,
      scenarioDef.name,
      scenarioDef.expectedFailedCheck,
      compInfo.component,
      compInfo.consequence,
      compInfo.defensiveAction,
      JSON.stringify(verification.checks),
      now,
    ]
  );

  return {
    sessionId,
    deviceId,
    deviceName: device.name,
    deviceType: device.type,
    currentFirmwareVersion: device.firmware_version,
    scenarioType,
    title: scenarioDef.name,
    description: scenarioDef.description,
    status: 'BLOCKED',
    failedCheck: scenarioDef.expectedFailedCheck,
    affectedComponent: compInfo.component,
    potentialImpact: compInfo.consequence,
    defensiveAction: compInfo.defensiveAction,
    verification,
    notice: 'Controlled software simulation only. Harmless test payload used. No real hardware was affected or harmed.',
  };
}
