import React, { useState } from 'react';
import { VirtualDevice, VerificationResult } from '../types';
import { api } from '../services/api';
import {
  FileCode,
  Upload,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Download,
  Sparkles,
  ShieldCheck,
  ShieldAlert,
  Flame,
  ArrowRight,
  FileText,
  Lock,
} from 'lucide-react';

interface FirmwareLabViewProps {
  devices: VirtualDevice[];
  onRefresh: () => Promise<void>;
  onVerificationDone?: (res: VerificationResult) => void;
}

export const FirmwareLabView: React.FC<FirmwareLabViewProps> = ({
  devices,
  onRefresh,
  onVerificationDone,
}) => {
  const [selectedDeviceId, setSelectedDeviceId] = useState<string>(devices[0]?.id || '');
  const [uploadedInfo, setUploadedInfo] = useState<any | null>(null);
  const [verificationResult, setVerificationResult] = useState<VerificationResult | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const selectedDevice = devices.find(d => d.id === selectedDeviceId) || devices[0];

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (file.size > 10 * 1024 * 1024) {
      setErrorMsg('File exceeds 10 MB maximum upload limit.');
      return;
    }

    setIsUploading(true);
    setErrorMsg(null);
    setVerificationResult(null);

    try {
      const data = await api.uploadFirmware(file);
      setUploadedInfo(data);
    } catch (err: any) {
      setErrorMsg(err.message);
    } finally {
      setIsUploading(false);
    }
  };

  const handleGenerateSample = async (scenario: string) => {
    if (!selectedDeviceId) {
      setErrorMsg('Select a target virtual device first.');
      return;
    }
    setIsGenerating(true);
    setErrorMsg(null);
    setVerificationResult(null);

    try {
      const res = await api.generateSamplePackage(selectedDeviceId, scenario);
      setUploadedInfo({
        fileId: res.fileId,
        fileName: res.fileName,
        fileSize: res.fileSize,
        fileHash: res.fileHash,
        detectedFormat: 'IoT CyberShield Signed OTA Package (.zip)',
        isDeployableFirmware: true,
        manifest: res.manifest,
        sampleDescription: res.description,
        expectedResult: res.expectedResult,
      });
    } catch (err: any) {
      setErrorMsg(err.message);
    } finally {
      setIsGenerating(false);
    }
  };

  const handleVerify = async () => {
    if (!uploadedInfo?.fileId || !selectedDeviceId) {
      setErrorMsg('Select a device and upload or generate a firmware package first.');
      return;
    }

    setIsVerifying(true);
    setErrorMsg(null);

    try {
      const result = await api.verifyFirmware(selectedDeviceId, uploadedInfo.fileId);
      setVerificationResult(result);
      if (onVerificationDone) onVerificationDone(result);
      await onRefresh();
    } catch (err: any) {
      setErrorMsg(err.message);
    } finally {
      setIsVerifying(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-100">Firmware Testing Lab</h1>
        <p className="text-xs text-slate-400 mt-0.5">
          Inspect cryptographic integrity, evaluate Ed25519 digital signatures, and enforce monotonic rollback policies.
        </p>
      </div>

      {errorMsg && (
        <div className="p-3 bg-red-950/80 border border-red-500/60 rounded-xl text-xs text-red-200 flex items-center justify-between">
          <span>{errorMsg}</span>
          <button onClick={() => setErrorMsg(null)} className="text-red-400 hover:text-red-200">
            ✕
          </button>
        </div>
      )}

      {/* 1-Click Sample Generator Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-900 to-cyan-950/40 border border-slate-800 rounded-2xl p-5 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-300">
              Sample Package Generator (Local Development Keys)
            </h3>
          </div>
          <span className="text-[10px] font-mono text-slate-500">
            Signs deterministic test containers on server
          </span>
        </div>
        <p className="text-xs text-slate-400 leading-relaxed">
          Generate pre-signed authentic test packages or deliberate attack scenarios for target device{' '}
          <strong className="text-cyan-300 font-mono">{selectedDevice?.name || 'Selected Node'}</strong>:
        </p>

        <div className="flex flex-wrap gap-2 pt-1">
          <button
            onClick={() => handleGenerateSample('valid')}
            disabled={isGenerating}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-950/80 hover:bg-emerald-900/80 text-emerald-300 border border-emerald-800/60 flex items-center gap-1.5 transition-colors"
          >
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            <span>Valid Update (PASS)</span>
          </button>
          <button
            onClick={() => handleGenerateSample('invalid_signature')}
            disabled={isGenerating}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-red-950/80 hover:bg-red-900/80 text-red-300 border border-red-800/60 flex items-center gap-1.5 transition-colors"
          >
            <XCircle className="w-3.5 h-3.5 text-red-400" />
            <span>Invalid Signature (FAIL)</span>
          </button>
          <button
            onClick={() => handleGenerateSample('modified_firmware')}
            disabled={isGenerating}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-red-950/80 hover:bg-red-900/80 text-red-300 border border-red-800/60 flex items-center gap-1.5 transition-colors"
          >
            <Flame className="w-3.5 h-3.5 text-orange-400" />
            <span>Modified Payload (FAIL)</span>
          </button>
          <button
            onClick={() => handleGenerateSample('downgrade')}
            disabled={isGenerating}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-orange-950/80 hover:bg-orange-900/80 text-orange-300 border border-orange-800/60 flex items-center gap-1.5 transition-colors"
          >
            <AlertTriangle className="w-3.5 h-3.5 text-orange-400" />
            <span>Downgrade Attack (FAIL)</span>
          </button>
          <button
            onClick={() => handleGenerateSample('replay')}
            disabled={isGenerating}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-red-950/80 hover:bg-red-900/80 text-red-300 border border-red-800/60 flex items-center gap-1.5 transition-colors"
          >
            <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
            <span>Replay Attack (FAIL)</span>
          </button>
          <button
            onClick={() => handleGenerateSample('unknown_key')}
            disabled={isGenerating}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 flex items-center gap-1.5 transition-colors"
          >
            <Lock className="w-3.5 h-3.5 text-slate-400" />
            <span>Unknown Key (FAIL)</span>
          </button>
        </div>
      </div>

      {/* Main Grid: Upload & Inspection vs Verification Results */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Form & Inspection (6 cols) */}
        <div className="lg:col-span-6 bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-4">
          <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <Upload className="w-4 h-4 text-cyan-400" />
            <span>Target Node & Firmware Container</span>
          </h3>

          {/* Device Selector */}
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Target Virtual Device</label>
            <select
              value={selectedDeviceId}
              onChange={e => {
                setSelectedDeviceId(e.target.value);
                setVerificationResult(null);
              }}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-cyan-500"
            >
              {devices.map(d => (
                <option key={d.id} value={d.id}>
                  {d.id} — {d.name} (Current: v{d.firmware_version})
                </option>
              ))}
            </select>
          </div>

          {/* Upload Dropzone */}
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Firmware File (.zip or .bin)</label>
            <div className="border-2 border-dashed border-slate-800 hover:border-cyan-500/60 rounded-xl p-5 text-center bg-slate-950/40 transition-colors">
              <input
                type="file"
                id="firmware-file-input"
                onChange={handleFileUpload}
                accept=".zip,.bin,.tar,.gz,.txt"
                className="hidden"
              />
              <label htmlFor="firmware-file-input" className="cursor-pointer block">
                <FileCode className="w-8 h-8 text-cyan-400 mx-auto mb-2" />
                <p className="text-xs font-semibold text-slate-200">
                  {isUploading ? 'Uploading & calculating hash…' : 'Click to select or drop firmware package'}
                </p>
                <p className="text-[10px] text-slate-500 mt-1">
                  Upload safe test archive up to 10 MB. Server hashes bytes and extracts manifest in memory.
                </p>
              </label>
            </div>
          </div>

          {/* Uploaded Package Metadata Details */}
          {uploadedInfo && (
            <div className="p-4 bg-slate-950/80 rounded-xl border border-slate-800 space-y-3 text-xs">
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
                <div className="flex items-center gap-2">
                  <FileText className="w-4 h-4 text-cyan-400" />
                  <span className="font-semibold text-slate-200 truncate max-w-[220px]">
                    {uploadedInfo.fileName}
                  </span>
                </div>
                <span className="font-mono text-[11px] text-slate-400">
                  {(uploadedInfo.fileSize / 1024).toFixed(1)} KB
                </span>
              </div>

              {uploadedInfo.sampleDescription && (
                <p className="text-[11px] text-cyan-300 font-mono bg-cyan-950/40 p-2 rounded border border-cyan-800/40">
                  Scenario: {uploadedInfo.sampleDescription}
                </p>
              )}

              <div className="space-y-1 font-mono text-[11px]">
                <div className="flex justify-between text-slate-400">
                  <span>Detected Format:</span>
                  <span className="text-slate-200">{uploadedInfo.detectedFormat}</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>SHA-256 (Server):</span>
                  <span className="text-cyan-300 truncate max-w-[180px]" title={uploadedInfo.fileHash}>
                    {uploadedInfo.fileHash.substring(0, 16)}...
                  </span>
                </div>
                {uploadedInfo.manifest && (
                  <>
                    <div className="flex justify-between text-slate-400">
                      <span>Proposed Version:</span>
                      <span className="text-teal-300 font-bold">v{uploadedInfo.manifest.firmwareVersion}</span>
                    </div>
                    <div className="flex justify-between text-slate-400">
                      <span>Signer Key ID:</span>
                      <span className="text-slate-300">{uploadedInfo.manifest.keyId}</span>
                    </div>
                    <div className="flex justify-between text-slate-400">
                      <span>Update ID:</span>
                      <span className="text-slate-300">{uploadedInfo.manifest.updateId}</span>
                    </div>
                  </>
                )}
              </div>

              {uploadedInfo.warning && (
                <div className="p-2.5 rounded bg-orange-950/60 border border-orange-500/40 text-[11px] text-orange-200">
                  {uploadedInfo.warning}
                </div>
              )}

              <div className="flex items-center gap-2 pt-2">
                <button
                  onClick={handleVerify}
                  disabled={isVerifying}
                  className="flex-1 py-2.5 px-4 rounded-lg font-bold text-xs bg-cyan-500 hover:bg-cyan-400 text-slate-950 shadow-lg shadow-cyan-500/20 transition-all flex items-center justify-center gap-1.5"
                >
                  <ShieldCheck className="w-4 h-4" />
                  <span>{isVerifying ? 'Evaluating Checks…' : 'Verify & Evaluate Security'}</span>
                </button>

                {uploadedInfo.readyToVerify && (
                  <a
                    href={`/api/firmware/download-sample?fileId=${encodeURIComponent(uploadedInfo.fileId)}`}
                    download
                    className="p-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors"
                    title="Download generated test package"
                  >
                    <Download className="w-4 h-4" />
                  </a>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Right Column: Verification Results (6 cols) */}
        <div className="lg:col-span-6 bg-slate-900/80 border border-slate-800 rounded-2xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-sm font-bold text-slate-100">Verification Outcome</h3>
                <p className="text-xs text-slate-400">Multi-stage cryptographic and policy checklist</p>
              </div>

              {verificationResult ? (
                <span
                  className={`text-xs font-mono font-bold px-2.5 py-1 rounded-md ${
                    verificationResult.decision === 'APPROVED'
                      ? 'bg-teal-950 text-teal-300 border border-teal-700'
                      : 'bg-red-950 text-red-300 border border-red-700'
                  }`}
                >
                  {verificationResult.decision}
                </span>
              ) : (
                <span className="text-xs font-mono text-slate-500 bg-slate-800 px-2.5 py-1 rounded">
                  WAITING FOR RUN
                </span>
              )}
            </div>

            {!verificationResult ? (
              <div className="p-12 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-xl">
                Upload or generate a package and run verification to inspect the multi-stage evaluation pipeline.
              </div>
            ) : (
              <div className="space-y-3">
                {/* Decision Banner */}
                <div
                  className={`p-3.5 rounded-xl border flex items-start gap-3 ${
                    verificationResult.decision === 'APPROVED'
                      ? 'bg-teal-950/60 border-teal-500/50 text-teal-200'
                      : 'bg-red-950/60 border-red-500/50 text-red-200'
                  }`}
                >
                  {verificationResult.decision === 'APPROVED' ? (
                    <CheckCircle2 className="w-5 h-5 text-teal-400 shrink-0 mt-0.5" />
                  ) : (
                    <XCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
                  )}
                  <div className="text-xs">
                    <p className="font-bold text-sm">
                      {verificationResult.decision === 'APPROVED'
                        ? 'Firmware Approved & Flashed to Virtual Node'
                        : 'Firmware Rejected — Previous Trusted Version Preserved'}
                    </p>
                    <p className="mt-1 opacity-90">{verificationResult.reason}</p>
                  </div>
                </div>

                {/* Individual Checklist Steps */}
                <div className="space-y-2 pt-2">
                  <h4 className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider">
                    Pipeline Stages ({verificationResult.checks.length} Checks)
                  </h4>
                  {verificationResult.checks.map(check => {
                    const isPassed = check.status === 'PASSED';
                    return (
                      <div
                        key={check.id}
                        className={`p-3 rounded-xl border text-xs flex items-start justify-between gap-3 ${
                          isPassed
                            ? 'bg-slate-950/50 border-slate-800/80 text-slate-300'
                            : 'bg-red-950/30 border-red-800/60 text-red-200'
                        }`}
                      >
                        <div className="flex items-start gap-2.5">
                          <div
                            className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${
                              isPassed ? 'bg-teal-400' : 'bg-red-400'
                            }`}
                          />
                          <div>
                            <span className="font-bold font-mono text-slate-200">{check.name}</span>
                            <p className="text-[11px] text-slate-400 mt-0.5">{check.detail}</p>
                          </div>
                        </div>
                        <span
                          className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded whitespace-nowrap ${
                            isPassed
                              ? 'bg-teal-950 text-teal-300 border border-teal-800/60'
                              : 'bg-red-950 text-red-300 border border-red-800/60'
                          }`}
                        >
                          {check.status}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>

          <div className="pt-4 border-t border-slate-800 text-[11px] text-slate-500 font-mono">
            Cryptographic signatures verified with Node.js crypto Ed25519 engine.
          </div>
        </div>
      </div>
    </div>
  );
};
