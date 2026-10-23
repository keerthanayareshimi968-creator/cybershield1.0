import { test, describe, before } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  generateSampleFirmwareFiles,
  runVerificationTrial,
  getAutoUpdateServerStatus
} from '../src/autoUpdateServer.js';

import {
  getDatabase,
  getDevice,
  getSimulationTrials
} from '../src/database.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

describe('Feature: Automatic Firmware Update Server & 3D Simulation', () => {
  before(() => {
    getDatabase();
  });

  test('A. Server generates two sample firmware files: one valid and one invalid', () => {
    const bundle = generateSampleFirmwareFiles('DEV-CAM-01');

    assert.ok(bundle, 'Sample bundle should be generated');
    assert.strictEqual(bundle.deviceId, 'DEV-CAM-01');
    assert.ok(bundle.validPackage, 'Must have validPackage');
    assert.ok(bundle.invalidPackage, 'Must have invalidPackage');

    // Valid package properties
    assert.strictEqual(bundle.validPackage.type, 'valid');
    assert.strictEqual(bundle.validPackage.expectedOutcome, 'APPROVED');
    assert.strictEqual(bundle.validPackage.signatureValid, true);
    assert.strictEqual(bundle.validPackage.keyId, 'dev-ed25519-primary');
    assert.ok(bundle.validPackage.fileHash.length === 64, 'SHA-256 hash must be 64 hex characters');
    assert.strictEqual(bundle.validPackage.visualIndicator, 'green_carry_to_device');

    // Invalid package properties
    assert.strictEqual(bundle.invalidPackage.type, 'invalid');
    assert.strictEqual(bundle.invalidPackage.expectedOutcome, 'REJECTED');
    assert.strictEqual(bundle.invalidPackage.signatureValid, false);
    assert.strictEqual(bundle.invalidPackage.visualIndicator, 'red_blocked_before_device');

    // Check files actually written to disk
    const validDiskPath = path.join(__dirname, '..', 'public', bundle.validPackage.filePath);
    const invalidDiskPath = path.join(__dirname, '..', 'public', bundle.invalidPackage.filePath);

    assert.ok(fs.existsSync(validDiskPath), 'Valid sample file must exist on disk');
    assert.ok(fs.existsSync(invalidDiskPath), 'Invalid sample file must exist on disk');
  });

  test('B. Valid firmware verification trial passes, increments version, and directs green animation to device', async () => {
    const trial = await runVerificationTrial('DEV-CAM-01', 'valid');

    assert.strictEqual(trial.decision, 'APPROVED');
    assert.strictEqual(trial.animation.color, 'green');
    assert.strictEqual(trial.animation.type, 'carry_to_device');
    assert.strictEqual(trial.animation.lineHex, '#10B981');
    assert.strictEqual(trial.animation.barrierAction, 'PASS_THROUGH');

    // All checks must pass
    assert.ok(trial.checks.every(c => c.status === 'PASSED'), 'All mandatory checks must pass for valid firmware');

    // Device firmware updated
    const device = getDevice('DEV-CAM-01');
    assert.strictEqual(device.firmware_version, trial.firmwareVersion);
  });

  test('C. Invalid firmware verification trial is blocked, raises security alert, and directs red animation stopping at barrier', async () => {
    const trial = await runVerificationTrial('DEV-CAM-01', 'invalid');

    assert.strictEqual(trial.decision, 'REJECTED');
    assert.strictEqual(trial.animation.color, 'red');
    assert.strictEqual(trial.animation.type, 'blocked_before_device');
    assert.strictEqual(trial.animation.lineHex, '#EF4444');
    assert.strictEqual(trial.animation.barrierAction, 'DEFLECT_AND_DESTROY');

    // At least one check failed (signature / hash)
    assert.ok(trial.checks.some(c => c.status === 'FAILED'), 'Cryptographic check must fail for invalid firmware');
    assert.ok(trial.incidentId, 'Incident ID must be generated for blocked attack');
  });

  test('D. Simulation trials are persisted in SQLite and available for Overview and 3D ledger', () => {
    const trials = getSimulationTrials(10);
    assert.ok(trials.length >= 2, 'Must have at least 2 trials logged');

    const validTrial = trials.find(t => t.packageType === 'valid');
    const invalidTrial = trials.find(t => t.packageType === 'invalid');

    assert.ok(validTrial, 'Must find valid trial in history');
    assert.strictEqual(validTrial.decision, 'APPROVED');
    assert.strictEqual(validTrial.color, 'green');

    assert.ok(invalidTrial, 'Must find invalid trial in history');
    assert.strictEqual(invalidTrial.decision, 'REJECTED');
    assert.strictEqual(invalidTrial.color, 'red');

    const status = getAutoUpdateServerStatus();
    assert.strictEqual(status.serverStatus, 'ACTIVE');
    assert.ok(status.totalTrialsToday >= 2);
  });
});
