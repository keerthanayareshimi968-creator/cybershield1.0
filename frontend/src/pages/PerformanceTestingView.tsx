import React, { useState } from 'react';
import { PerformanceBenchmark } from '../types';
import { api } from '../services/api';
import {
  Gauge,
  Play,
  RotateCcw,
  Zap,
  Clock,
  CheckCircle2,
  Cpu,
  Layers,
  Hash,
  Lock,
  Activity,
} from 'lucide-react';

export const PerformanceTestingView: React.FC = () => {
  const [iterations, setIterations] = useState<number>(25);
  const [payloadSizeKb, setPayloadSizeKb] = useState<number>(256);
  const [benchmarkResult, setBenchmarkResult] = useState<PerformanceBenchmark | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleRunBenchmark = async () => {
    setIsRunning(true);
    setErrorMsg(null);
    try {
      const data = await api.runBenchmark(iterations, payloadSizeKb);
      setBenchmarkResult(data);
    } catch (err: any) {
      setErrorMsg(err.message);
    } finally {
      setIsRunning(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-100">Performance Testing & Benchmarking</h1>
        <p className="text-xs text-slate-400 mt-0.5">
          Measure real cryptographic throughput, hashing latency, and signature verification duration on the host server.
        </p>
      </div>

      {errorMsg && (
        <div className="p-3 bg-red-950/80 border border-red-500/60 rounded-xl text-xs text-red-200">
          {errorMsg}
        </div>
      )}

      {/* Benchmark Configuration Bar */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-4">
          <div>
            <label className="text-[10px] font-mono font-bold text-slate-400 uppercase block mb-1">
              Test Iterations
            </label>
            <div className="flex items-center gap-1.5">
              {[10, 25, 50, 100].map(cnt => (
                <button
                  key={cnt}
                  onClick={() => setIterations(cnt)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-colors ${
                    iterations === cnt
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                      : 'bg-slate-950 border border-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {cnt}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="text-[10px] font-mono font-bold text-slate-400 uppercase block mb-1">
              Sample Payload Size
            </label>
            <select
              value={payloadSizeKb}
              onChange={e => setPayloadSizeKb(parseInt(e.target.value, 10))}
              className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-200"
            >
              <option value="64">64 KB (Microcontroller Image)</option>
              <option value="256">256 KB (Embedded RTOS Partition)</option>
              <option value="1024">1024 KB (1 MB Linux Firmware Slice)</option>
              <option value="4096">4096 KB (4 MB Full Flash Image)</option>
            </select>
          </div>
        </div>

        <button
          onClick={handleRunBenchmark}
          disabled={isRunning}
          className="flex items-center gap-2 px-5 py-2.5 rounded-lg text-xs font-bold bg-cyan-500 hover:bg-cyan-400 text-slate-950 shadow-lg shadow-cyan-500/20 transition-all font-sans"
        >
          <Play className="w-4 h-4 fill-current" />
          <span>{isRunning ? 'Benchmarking Engine…' : 'Execute Benchmark Suite'}</span>
        </button>
      </div>

      {/* Benchmark Results Display */}
      {benchmarkResult ? (
        <div className="space-y-6">
          {/* 4 Cards for Core Metrics */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* SHA-256 Hashing */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono font-bold uppercase text-cyan-400">STAGE 01</span>
                <Hash className="w-4 h-4 text-cyan-400" />
              </div>
              <div>
                <h4 className="text-sm font-bold text-slate-100">SHA-256 Hashing</h4>
                <p className="text-2xl font-bold font-mono text-cyan-300 mt-1">
                  {benchmarkResult.benchmarks.sha256.avg} ms
                </p>
                <span className="text-[10px] text-slate-500">Average execution duration</span>
              </div>
              <div className="pt-2 border-t border-slate-800 flex justify-between text-[11px] font-mono text-slate-400">
                <span>Min: {benchmarkResult.benchmarks.sha256.min} ms</span>
                <span>Max: {benchmarkResult.benchmarks.sha256.max} ms</span>
              </div>
            </div>

            {/* Ed25519 Verification */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono font-bold uppercase text-teal-400">STAGE 02</span>
                <Lock className="w-4 h-4 text-teal-400" />
              </div>
              <div>
                <h4 className="text-sm font-bold text-slate-100">Ed25519 Signature Verify</h4>
                <p className="text-2xl font-bold font-mono text-teal-300 mt-1">
                  {benchmarkResult.benchmarks.ed25519Verify.avg} ms
                </p>
                <span className="text-[10px] text-slate-500">Average asymmetric verification</span>
              </div>
              <div className="pt-2 border-t border-slate-800 flex justify-between text-[11px] font-mono text-slate-400">
                <span>Min: {benchmarkResult.benchmarks.ed25519Verify.min} ms</span>
                <span>Max: {benchmarkResult.benchmarks.ed25519Verify.max} ms</span>
              </div>
            </div>

            {/* Canonical JSON Serialization */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono font-bold uppercase text-indigo-400">STAGE 03</span>
                <Layers className="w-4 h-4 text-indigo-400" />
              </div>
              <div>
                <h4 className="text-sm font-bold text-slate-100">Canonical JSON Manifest</h4>
                <p className="text-2xl font-bold font-mono text-indigo-300 mt-1">
                  {benchmarkResult.benchmarks.canonicalJson.avg} ms
                </p>
                <span className="text-[10px] text-slate-500">Deterministic key sorting</span>
              </div>
              <div className="pt-2 border-t border-slate-800 flex justify-between text-[11px] font-mono text-slate-400">
                <span>Min: {benchmarkResult.benchmarks.canonicalJson.min} ms</span>
                <span>Max: {benchmarkResult.benchmarks.canonicalJson.max} ms</span>
              </div>
            </div>

            {/* Complete Pipeline Estimate */}
            <div className="bg-slate-900/80 border border-cyan-500/30 rounded-2xl p-5 space-y-3 shadow-lg shadow-cyan-500/5">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono font-bold uppercase text-emerald-400">TOTAL LATENCY</span>
                <Zap className="w-4 h-4 text-emerald-400" />
              </div>
              <div>
                <h4 className="text-sm font-bold text-slate-100">Total Security Pipeline</h4>
                <p className="text-2xl font-bold font-mono text-emerald-400 mt-1">
                  {benchmarkResult.benchmarks.fullPipelineEstimate.avg} ms
                </p>
                <span className="text-[10px] text-slate-500">End-to-end evaluation</span>
              </div>
              <div className="pt-2 border-t border-slate-800 flex justify-between text-[11px] font-mono text-slate-400">
                <span>Iterations: {benchmarkResult.iterations}</span>
                <span className="text-teal-400">100% Passed</span>
              </div>
            </div>
          </div>

          <div className="p-4 bg-slate-900/60 rounded-xl border border-slate-800 text-xs text-slate-400 flex items-start gap-2.5">
            <Clock className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
            <div>
              <span className="font-semibold text-slate-200">Host Environment Measurement Note:</span>
              <p className="mt-0.5 leading-relaxed">
                {benchmarkResult.note} Benchmarking distinguishes real host server CPU execution duration from software-modeled virtual IoT device transfer intervals.
              </p>
            </div>
          </div>
        </div>
      ) : (
        <div className="p-16 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-2xl">
          Click &quot;Execute Benchmark Suite&quot; to measure real host cryptographic execution times over {iterations} iterations.
        </div>
      )}
    </div>
  );
};
