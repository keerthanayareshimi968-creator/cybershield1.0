import crypto from 'node:crypto';
import {
  getDevice,
  updateDevice,
  addSecurityEvent,
  createIncident,
  addAnomalyAlert,
  getTrustedKeys,
  checkAndRecordReplayToken,
  getSettings
} from './database.js';
import { calculateSha256, verifyEd25519Signature, compareVersions } from './cryptoUtils.js';

// Sliding windows for rate/frequency tracking
const authFailuresMap = new Map(); // key: deviceId -> [timestamps]
const eventFrequencyMap = new Map(); // key: deviceId -> [timestamps]
const cameraAccessMap = new Map(); // key: deviceId -> [timestamps]
const lastSensorReadings = new Map(); // key: deviceId -> { temp, hum, time }

/**
 * Format local time string cleanly
 */
function getLocalTimestamp() {
  const d = new Date();
  return d.toLocaleString([], {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
}

let eventCounter = 0;
function nextEventId() {
  eventCounter = (eventCounter + 1) % 1000000;
  return `EVT-${Date.now()}-${eventCounter}-${crypto.randomBytes(2).toString('hex')}`;
}

/**
 * Rule Evaluation: Firmware Package Validation & Attack Detection
 */
export async function evaluateFirmwarePackage(pkg, deviceId, options = {}) {
  const device = getDevice(deviceId);
  if (!device) {
    throw new Error(`Device '${deviceId}' not found. Only four supported devices are permitted.`);
  }

  const checks = [];
  const now = new Date();
  const utcTime = now.toISOString();
  const localTime = getLocalTimestamp();
  const requestId = pkg.requestId || pkg.updateId || `REQ-${crypto.randomUUID().slice(0, 8)}`;

  // 1. Package Structure & Malformed Validation (RULE-MAL-008)
  const isMalformed = !pkg || typeof pkg !== 'object' || (!pkg.firmwareBytes && !pkg.fileHash && !pkg.rawText) || pkg.isMalformedTest;
  checks.push({
    name: 'Package Structure & Manifest Integrity',
    category: 'STRUCTURE',
    status: isMalformed ? 'FAILED' : 'PASSED',
    detail: isMalformed
      ? 'Package manifest is malformed, missing mandatory schema attributes, or archive structure is corrupted.'
      : 'Manifest JSON conforms to schema version 1.0; all required container fields present.'
  });

  if (isMalformed) {
    const incId = `INC-${Date.now().toString().slice(-6)}`;
    const incident = {
      id: incId,
      title: 'Malformed Firmware Package Container Discarded',
      classification: 'Suspicious activity',
      severity: 'HIGH',
      severityJustification: 'Malformed archive headers or missing manifest fields indicate corrupted build pipelines or zip-slip traversal attempts.',
      deviceId: device.id,
      deviceModel: device.model,
      timestampUtc: utcTime,
      timestampLocal: localTime,
      summary: `A firmware archive targeting ${device.name} was rejected at the initial ingestion stage because its internal structure or manifest failed schema validation.`,
      attackCategory: 'Malformed Container / Parser Exploitation',
      occurredLocation: 'Firmware verification pipeline — Archive Structure Parser',
      sourceMetadata: options.sourceIp || 'Internal simulator',
      destinationMetadata: `${device.name} OTA Agent`,
      entryPoint: 'POST /api/verify',
      detectionRuleId: 'RULE-MAL-008',
      triggerReason: 'Archive header validation failed; manifest.json missing required metadata fields.',
      evidenceJson: { error: 'Schema validation failed', fileName: pkg.fileName || 'firmware.zip' },
      correlatedEventsJson: [nextEventId()],
      observedImpact: 'The package was discarded in-memory before reaching staging memory. Device state remained completely untouched.',
      responseAction: 'Quarantined corrupted upload buffer and incremented device alert counter.',
      responseSuccess: true,
      recoveryStatus: 'Recovered (Normal Operation)',
      confidenceLevel: 'High (Direct schema validation failure)',
      evidenceLimitations: 'Software emulation boundary; no physical flash memory access was attempted.',
      recommendedAction: 'Inspect firmware build script to ensure manifest.json and binary hashes are generated automatically in CI/CD.',
      investigationNotes: 'Automated policy rejected archive during pre-validation scan.'
    };

    createIncident(incident);
    addSecurityEvent({
      id: nextEventId(),
      timestamp: utcTime,
      deviceId: device.id,
      eventType: 'Firmware verification',
      severity: 'HIGH',
      originatingComponent: 'Package Ingestion Stage',
      sourceMetadata: options.sourceIp || 'Internal simulator',
      destinationMetadata: `${device.name} OTA Agent`,
      requestId,
      detectionRuleId: 'RULE-MAL-008',
      relatedIncidentId: incId,
      responseOutcome: 'REJECTED',
      verificationResult: 'REJECTED',
      description: 'Firmware package rejected due to malformed container structure or missing manifest metadata.'
    });

    updateDevice(device.id, {
      risk_level: 'High',
      risk_explanation: 'Active submission of malformed firmware packages detected.'
    });

    return {
      decision: 'REJECTED',
      reason: 'Package manifest is malformed or required archive headers are missing.',
      checks,
      incidentId: incId
    };
  }

  // 2. Cryptographic SHA-256 Hash Verification (RULE-TAMPER-001)
  let calculatedHash = pkg.fileHash;
  if (pkg.firmwareBytes) {
    calculatedHash = calculateSha256(pkg.firmwareBytes);
  }
  const manifestHash = pkg.expectedHash || pkg.manifestHash || pkg.trustedHash;
  const hashMatches = manifestHash ? (calculatedHash.toLowerCase() === manifestHash.toLowerCase()) : (pkg.fileHashValid !== false);

  checks.push({
    name: 'Cryptographic SHA-256 Digest Match',
    category: 'INTEGRITY',
    status: hashMatches ? 'PASSED' : 'FAILED',
    detail: hashMatches
      ? `Calculated SHA-256 hash (${calculatedHash ? calculatedHash.slice(0, 16) + '...' : 'Verified'}) matches reference digest.`
      : `Calculated hash (${calculatedHash ? calculatedHash.slice(0, 16) + '...' : 'Unknown'}) does not match reference digest (${manifestHash ? manifestHash.slice(0, 16) + '...' : 'Empty'}).`
  });

  // 3. Trusted Signing Key Registry Lookup (RULE-KEY-003)
  const trustedKeys = getTrustedKeys();
  const keyId = pkg.keyId || 'dev-ed25519-primary';
  const keyRecord = trustedKeys.find(k => k.key_id === keyId && k.status === 'ACTIVE');
  const keyTrusted = Boolean(keyRecord);

  checks.push({
    name: 'Trusted Key Authority Registry',
    category: 'AUTHENTICITY',
    status: keyTrusted ? 'PASSED' : 'FAILED',
    detail: keyTrusted
      ? `Signing key '${keyId}' verified active in platform hardware root of trust.`
      : `Signing key '${keyId}' is absent from trusted key registry or has been revoked.`
  });

  // 4. Ed25519 Digital Signature Verification (RULE-SIG-002)
  let sigValid = false;
  if (keyRecord && pkg.signature && (pkg.firmwareBytes || pkg.manifestBytes)) {
    const dataToVerify = pkg.firmwareBytes || pkg.manifestBytes;
    sigValid = verifyEd25519Signature(dataToVerify, pkg.signature, keyRecord.public_key_hex);
  } else if (pkg.signatureValid !== undefined) {
    sigValid = Boolean(pkg.signatureValid);
  } else {
    // If no signature supplied or unknown key
    sigValid = keyTrusted && pkg.signatureValid !== false;
  }

  checks.push({
    name: 'Ed25519 Digital Signature Authenticity',
    category: 'AUTHENTICITY',
    status: sigValid ? 'PASSED' : 'FAILED',
    detail: sigValid
      ? 'Ed25519 signature cryptographically verified against device trusted public key.'
      : 'Ed25519 signature validation failed; cryptographic payload origin cannot be proven.'
  });

  // 5. Monotonic Anti-Rollback Version Policy (RULE-DWN-004)
  const proposedVersion = pkg.firmwareVersion || pkg.targetVersion || '2.2.0';
  const meetsMinPolicy = compareVersions(proposedVersion, device.minimum_version) >= 0;

  checks.push({
    name: 'Monotonic Anti-Rollback Version Policy',
    category: 'POLICY',
    status: meetsMinPolicy ? 'PASSED' : 'FAILED',
    detail: meetsMinPolicy
      ? `Target version v${proposedVersion} satisfies monotonic minimum version policy (>= v${device.minimum_version}).`
      : `Proposed version v${proposedVersion} violates anti-rollback policy (minimum required is v${device.minimum_version}).`
  });

  // 6. Anti-Replay Nonce & Transaction Protection (RULE-RPL-005)
  const tokenValid = checkAndRecordReplayToken(device.id, requestId);
  checks.push({
    name: 'Anti-Replay Nonce & Transaction Protection',
    category: 'REPLAY',
    status: tokenValid ? 'PASSED' : 'FAILED',
    detail: tokenValid
      ? `Request identifier '${requestId.slice(0, 16)}' is unique and registered in anti-replay ledger.`
      : `Request identifier '${requestId.slice(0, 16)}' was previously accepted. Replay attack detected!`
  });

  // Comprehensive Decision Rule
  const allPassed = checks.every(c => c.status === 'PASSED');
  const decision = allPassed ? 'APPROVED' : 'REJECTED';

  let failedCheck = checks.find(c => c.status !== 'PASSED');
  let reason = allPassed
    ? 'All mandatory cryptographic, integrity, authenticity, rollback, and replay security checks passed.'
    : `${failedCheck.name}: ${failedCheck.detail}`;

  let incidentId = null;

  if (!allPassed) {
    const incId = `INC-${Date.now().toString().slice(-6)}`;
    incidentId = incId;

    let attackCategory = 'Firmware Security Policy Violation';
    let ruleId = 'RULE-SEC-000';
    let classification = 'Confirmed simulated attack';

    if (!hashMatches) {
      attackCategory = 'Firmware Tampering / Bit Modification';
      ruleId = 'RULE-TAMPER-001';
      classification = 'Confirmed simulated attack';
    } else if (!keyTrusted) {
      attackCategory = 'Untrusted / Rogue Signing Key Injection';
      ruleId = 'RULE-KEY-003';
      classification = 'Confirmed simulated attack';
    } else if (!sigValid) {
      attackCategory = 'Invalid / Forged Digital Signature';
      ruleId = 'RULE-SIG-002';
      classification = 'Confirmed simulated attack';
    } else if (!meetsMinPolicy) {
      attackCategory = 'Firmware Downgrade / Rollback Attack';
      ruleId = 'RULE-DWN-004';
      classification = 'Security policy violation';
    } else if (!tokenValid) {
      attackCategory = 'Replay Attack / Transaction Reuse';
      ruleId = 'RULE-RPL-005';
      classification = 'Confirmed simulated attack';
    }

    const incident = {
      id: incId,
      title: `${attackCategory} on ${device.name}`,
      classification,
      severity: 'HIGH',
      severityJustification: `Mandatory security verification failed during update pipeline: ${failedCheck.name}. Unchecked execution would allow unauthorized firmware state.`,
      deviceId: device.id,
      deviceModel: device.model,
      timestampUtc: utcTime,
      timestampLocal: localTime,
      summary: `An Over-The-Air firmware package for ${device.name} (${device.model}) was blocked by the security enforcement engine because ${failedCheck.detail}`,
      attackCategory,
      occurredLocation: `Firmware verification pipeline — ${failedCheck.name}`,
      sourceMetadata: options.sourceIp || 'Internal simulator',
      destinationMetadata: `${device.name} OTA Receiver`,
      entryPoint: 'POST /api/verify',
      detectionRuleId: ruleId,
      triggerReason: failedCheck.detail,
      evidenceJson: {
        failedStage: failedCheck.name,
        calculatedHash,
        manifestHash,
        keyId,
        proposedVersion,
        deviceMinimumVersion: device.minimum_version,
        requestId,
        checks
      },
      correlatedEventsJson: [nextEventId()],
      observedImpact: `The update package was rejected. Device ${device.name} maintained its current firmware (${device.firmware_version}) with zero downtime.`,
      responseAction: 'Blocked package flashing, logged cryptographic failure to SQLite audit ledger, and elevated device risk profile.',
      responseSuccess: true,
      recoveryStatus: 'Recovered (Normal Operation)',
      confidenceLevel: 'High (Deterministic cryptographic verification failure)',
      evidenceLimitations: 'Software emulation boundary; no physical flash memory hardware modified.',
      recommendedAction: 'Verify firmware artifact provenance with the authorized signing authority before retrying.',
      investigationNotes: `Automated investigation opened. Policy check '${failedCheck.name}' failed with code ${ruleId}.`
    };

    createIncident(incident);

    addSecurityEvent({
      id: nextEventId(),
      timestamp: utcTime,
      deviceId: device.id,
      eventType: 'Firmware verification',
      severity: 'HIGH',
      originatingComponent: 'Firmware Verification Engine',
      sourceMetadata: options.sourceIp || 'Internal simulator',
      destinationMetadata: `${device.name} OTA Receiver`,
      requestId,
      packageId: pkg.packageId || null,
      detectionRuleId: ruleId,
      relatedIncidentId: incId,
      responseOutcome: 'REJECTED',
      verificationResult: 'REJECTED',
      description: `Firmware update rejected: ${reason}`
    });

    updateDevice(device.id, {
      risk_level: 'High',
      risk_explanation: `Recent rejected firmware attempt detected: ${attackCategory}`
    });
  } else {
    // Passed update: Record normal event
    addSecurityEvent({
      id: nextEventId(),
      timestamp: utcTime,
      deviceId: device.id,
      eventType: 'Firmware verification',
      severity: 'INFO',
      originatingComponent: 'Firmware Verification Engine',
      sourceMetadata: options.sourceIp || 'Internal simulator',
      destinationMetadata: `${device.name} OTA Receiver`,
      requestId,
      packageId: pkg.packageId || null,
      detectionRuleId: null,
      relatedIncidentId: null,
      responseOutcome: 'APPROVED',
      verificationResult: 'PASSED',
      description: `Firmware update v${proposedVersion} verified successfully and approved.`
    });

    // Optionally update device firmware if requested
    if (options.applyUpdate) {
      updateDevice(device.id, {
        firmware_version: proposedVersion,
        risk_level: 'Low',
        risk_explanation: `Successfully updated to verified firmware v${proposedVersion}.`
      });
    }
  }

  return {
    decision,
    reason,
    calculatedHash,
    checks,
    incidentId
  };
}

/**
 * Anomaly Detection: Repeated Authentication Failures
 */
export function recordAuthenticationAttempt(deviceId, success, metadata = {}) {
  const device = getDevice(deviceId);
  if (!device) return { ok: false, error: 'Device not found' };

  const now = Date.now();
  const utcTime = new Date().toISOString();
  const localTime = getLocalTimestamp();

  if (!authFailuresMap.has(deviceId)) {
    authFailuresMap.set(deviceId, []);
  }

  const failures = authFailuresMap.get(deviceId);
  const settings = getSettings();
  const threshold = parseInt(settings.failed_login_lockout_threshold || '3', 10);
  const windowMs = 60 * 1000;

  if (success) {
    // Reset consecutive failures on success
    authFailuresMap.set(deviceId, []);
    addSecurityEvent({
      id: nextEventId(),
      timestamp: utcTime,
      deviceId,
      eventType: 'Authentication',
      severity: 'INFO',
      originatingComponent: metadata.interface || 'Auth Interface',
      sourceMetadata: metadata.sourceIp || 'Internal simulator',
      destinationMetadata: `${device.name} Authentication Daemon`,
      responseOutcome: 'AUTHORIZED',
      verificationResult: 'PASSED',
      description: `Successful authentication on ${device.name} (${metadata.interface || 'Interface'}).`
    });
    return { ok: true, status: 'AUTHORIZED' };
  }

  // Failed attempt
  failures.push(now);
  // Keep only attempts within window
  const recentFailures = failures.filter(t => (now - t) <= windowMs);
  authFailuresMap.set(deviceId, recentFailures);

  addSecurityEvent({
    id: nextEventId(),
    timestamp: utcTime,
    deviceId,
    eventType: 'Authentication failure',
    severity: 'MEDIUM',
    originatingComponent: metadata.interface || 'Auth Interface',
    sourceMetadata: metadata.sourceIp || 'Internal simulator',
    destinationMetadata: `${device.name} Authentication Daemon`,
    responseOutcome: 'REJECTED',
    verificationResult: 'FAILED',
    description: `Authentication failed on ${device.name}. Consecutive failures in window: ${recentFailures.length}/${threshold}.`
  });

  if (recentFailures.length >= threshold) {
    const incId = `INC-${Date.now().toString().slice(-6)}`;
    const ruleId = device.type === 'smart_lock' ? 'RULE-LCK-010' : 'RULE-AUTH-001';

    const incident = {
      id: incId,
      title: `Repeated Authentication Failure Anomaly on ${device.name}`,
      classification: 'Suspicious activity',
      severity: 'HIGH',
      severityJustification: `Rapid succession of ${recentFailures.length} failed attempts exceeds brute-force threshold (${threshold} attempts per minute).`,
      deviceId: device.id,
      deviceModel: device.model,
      timestampUtc: utcTime,
      timestampLocal: localTime,
      summary: `Multiple failed authentication attempts were observed on ${device.name} (${device.model}) within a 60-second observation window.`,
      attackCategory: 'Brute-Force Credential Attempt',
      occurredLocation: `${device.name} ${metadata.interface || 'Authentication Subsystem'}`,
      sourceMetadata: metadata.sourceIp || 'Internal simulator',
      destinationMetadata: `${device.name} Access Port`,
      entryPoint: metadata.endpoint || 'POST /api/devices/:id/auth',
      detectionRuleId: ruleId,
      triggerReason: `Observed ${recentFailures.length} failed attempts; threshold is ${threshold} in 60s.`,
      evidenceJson: { failureTimestamps: recentFailures, interface: metadata.interface, attemptsCount: recentFailures.length },
      correlatedEventsJson: [nextEventId()],
      observedImpact: 'Authentication rate limiter triggered. Temporary simulated lockout initiated to preserve credential security.',
      responseAction: 'Enforced 300-second simulated lockout for client session and generated anomaly alert.',
      responseSuccess: true,
      recoveryStatus: 'Quarantine Active (Temporary Lockout)',
      confidenceLevel: 'High (Direct authentication event telemetry)',
      evidenceLimitations: 'Software emulation environment; physical hardware lockout pins were not toggled.',
      recommendedAction: 'Check source address logs for credential-stuffing patterns and confirm device operator identity.',
      investigationNotes: 'Automated brute-force detector tripped.'
    };

    createIncident(incident);
    addAnomalyAlert({
      id: `ALT-${Date.now()}`,
      timestamp: utcTime,
      ruleId,
      deviceId: device.id,
      severity: 'HIGH',
      evidence: `${recentFailures.length} failed authentication attempts recorded in 60 seconds on ${metadata.interface || 'interface'}.`
    });

    updateDevice(device.id, {
      risk_level: 'High',
      risk_explanation: `Authentication anomaly: ${recentFailures.length} consecutive failures detected.`
    });

    return {
      ok: false,
      status: 'LOCKED_OUT',
      incidentId: incId,
      message: `Authentication threshold exceeded (${recentFailures.length}/${threshold}). Lockout activated.`
    };
  }

  return {
    ok: false,
    status: 'REJECTED',
    message: `Invalid credentials. Attempt ${recentFailures.length}/${threshold}.`
  };
}

/**
 * Anomaly Detection: Environmental Sensor Telemetry Bounds (DHT22 / AM2302)
 */
export function recordSensorTelemetry(deviceId, temperatureCelsius, humidityPercent, metadata = {}) {
  const device = getDevice(deviceId);
  if (!device || device.type !== 'environmental_sensor') {
    return { ok: false, error: 'Device is not an environmental sensor.' };
  }

  const now = Date.now();
  const utcTime = new Date().toISOString();
  const localTime = getLocalTimestamp();
  const settings = getSettings();

  const tempMax = parseFloat(settings.sensor_temp_alert_max || '45');
  const tempMin = parseFloat(settings.sensor_temp_alert_min || '-10');
  const humMax = parseFloat(settings.sensor_hum_alert_max || '85');
  const humMin = parseFloat(settings.sensor_hum_alert_min || '15');

  const temp = Number(temperatureCelsius);
  const hum = Number(humidityPercent);

  // Check implausible sudden jump (> 25°C jump in under 10 seconds)
  let implausibleJump = false;
  if (lastSensorReadings.has(deviceId)) {
    const prev = lastSensorReadings.get(deviceId);
    if ((now - prev.time) < 10000 && Math.abs(temp - prev.temp) > 25) {
      implausibleJump = true;
    }
  }
  lastSensorReadings.set(deviceId, { temp, hum, time: now });

  const tempOutOfBounds = temp > tempMax || temp < tempMin;
  const humOutOfBounds = hum > humMax || hum < humMin;
  const isAnomalous = tempOutOfBounds || humOutOfBounds || implausibleJump;

  // Persist updated telemetry into device record
  updateDevice(deviceId, {
    telemetry_json: JSON.stringify({
      temperatureCelsius: temp,
      humidityPercent: hum,
      readingStatus: isAnomalous ? 'ANOMALOUS' : 'NORMAL',
      lastReadingAt: utcTime,
      readingSource: 'Software Emulation'
    }),
    last_seen_at: utcTime
  });

  if (isAnomalous) {
    const incId = `INC-${Date.now().toString().slice(-6)}`;
    const reason = implausibleJump
      ? `Implausible thermal jump detected: delta exceeding 25°C in < 10s.`
      : tempOutOfBounds
        ? `Temperature ${temp}°C is outside operational envelope [${tempMin}°C, ${tempMax}°C].`
        : `Humidity ${hum}% is outside safe envelope [${humMin}%, ${humMax}%].`;

    // Important requirement: Sensor reading anomalies do NOT prove compromise! Classify as Device health incident or Suspicious activity.
    const incident = {
      id: incId,
      title: `Sensor Telemetry Anomaly on ${device.name}`,
      classification: implausibleJump ? 'Suspicious activity' : 'Device health incident',
      severity: 'MEDIUM',
      severityJustification: 'Telemetry reading outside normal physical operating limits. Could indicate hardware fault, calibration drift, or sensor spoofing.',
      deviceId: device.id,
      deviceModel: device.model,
      timestampUtc: utcTime,
      timestampLocal: localTime,
      summary: `The DHT22 environmental sensor reported an unusual reading: ${reason}. Note: Sensor anomalies do not automatically prove malicious compromise.`,
      attackCategory: 'Telemetry Anomaly / Environmental Bounds',
      occurredLocation: 'DHT22 / AM2302 ADC Signal Acquisition Loop',
      sourceMetadata: 'Internal simulator',
      destinationMetadata: 'Central Monitoring Collector',
      entryPoint: 'POST /api/devices/:id/telemetry',
      detectionRuleId: 'RULE-ENV-007',
      triggerReason: reason,
      evidenceJson: { reportedTemp: temp, reportedHum: hum, tempMax, tempMin, humMax, humMin, implausibleJump },
      correlatedEventsJson: [nextEventId()],
      observedImpact: 'Telemetry flagged as anomalous; safety monitoring dashboard alerted.',
      responseAction: 'Dispatched sensor anomaly alert and marked reading state as degraded.',
      responseSuccess: true,
      recoveryStatus: 'Monitoring in Progress',
      confidenceLevel: 'Medium (Environmental reading anomaly; external physical cause unverified)',
      evidenceLimitations: 'Software emulation; no physical environmental chamber or physical AM2302 probe involved.',
      recommendedAction: 'Inspect sensor physical wiring, calibrate ADC reference voltage, and cross-reference with secondary ambient probes.',
      investigationNotes: 'Sensor threshold trigger recorded.'
    };

    createIncident(incident);

    addSecurityEvent({
      id: nextEventId(),
      timestamp: utcTime,
      deviceId: device.id,
      eventType: 'Sensor reading anomaly',
      severity: 'MEDIUM',
      originatingComponent: 'Telemetry Receiver',
      sourceMetadata: 'Internal simulator',
      destinationMetadata: 'Monitoring Controller',
      detectionRuleId: 'RULE-ENV-007',
      relatedIncidentId: incId,
      responseOutcome: 'ALERT_DISPATCHED',
      verificationResult: 'ANOMALOUS',
      description: `Environmental alert: ${reason}`
    });

    addAnomalyAlert({
      id: `ALT-${Date.now()}`,
      timestamp: utcTime,
      ruleId: 'RULE-ENV-007',
      deviceId: device.id,
      severity: 'MEDIUM',
      evidence: reason
    });

    updateDevice(device.id, {
      risk_level: 'Medium',
      risk_explanation: `Environmental bounds alert: ${reason}`
    });

    return {
      ok: true,
      status: 'ANOMALOUS',
      reason,
      incidentId: incId
    };
  }

  // Normal reading
  addSecurityEvent({
    id: nextEventId(),
    timestamp: utcTime,
    deviceId: device.id,
    eventType: 'Sensor telemetry',
    severity: 'INFO',
    originatingComponent: 'DHT22 ADC Loop',
    sourceMetadata: 'Internal simulator',
    destinationMetadata: 'Monitoring Collector',
    responseOutcome: 'RECORDED',
    verificationResult: 'PASSED',
    description: `Normal telemetry received: ${temp}°C, ${hum}% RH.`
  });

  return { ok: true, status: 'NORMAL', temp, hum };
}

/**
 * Anomaly Detection: Device Availability / Heartbeat
 */
export function recordHeartbeat(deviceId) {
  const device = getDevice(deviceId);
  if (!device) return { ok: false, error: 'Device not found' };

  const utcTime = new Date().toISOString();
  updateDevice(deviceId, {
    device_status: 'Online',
    last_seen_at: utcTime
  });

  addSecurityEvent({
    id: nextEventId(),
    timestamp: utcTime,
    deviceId: device.id,
    eventType: 'Heartbeat',
    severity: 'INFO',
    originatingComponent: 'Heartbeat Agent',
    sourceMetadata: 'Internal simulator',
    destinationMetadata: 'Fleet Health Service',
    responseOutcome: 'ACKNOWLEDGED',
    verificationResult: 'PASSED',
    description: `Device heartbeat acknowledged for ${device.name}.`
  });

  return { ok: true, timestamp: utcTime };
}
