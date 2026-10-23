import React, { useState, useEffect } from 'react';
import { SecurityEvent, VirtualDevice } from '../types';
import { api } from '../services/api';
import {
  ListOrdered,
  Search,
  Filter,
  Download,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  ShieldAlert,
  ShieldCheck,
  AlertCircle,
  FileText,
} from 'lucide-react';

interface SecurityLogsViewProps {
  devices: VirtualDevice[];
}

export const SecurityLogsView: React.FC<SecurityLogsViewProps> = ({ devices }) => {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [search, setSearch] = useState('');
  const [selectedDevice, setSelectedDevice] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState('');
  const [selectedEventType, setSelectedEventType] = useState('');
  const [offset, setOffset] = useState(0);
  const [limit] = useState(25);
  const [isLoading, setIsLoading] = useState(false);

  const fetchLogs = async () => {
    setIsLoading(true);
    try {
      const data = await api.getLogs({
        deviceId: selectedDevice || undefined,
        severity: selectedSeverity || undefined,
        eventType: selectedEventType || undefined,
        search: search || undefined,
        limit,
        offset,
      });
      setEvents(data.events);
      setTotal(data.total);
    } catch {
      // ignore
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [selectedDevice, selectedSeverity, selectedEventType, offset]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setOffset(0);
    fetchLogs();
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
      case 'HIGH':
        return 'bg-red-950/80 text-red-300 border border-red-800/60';
      case 'MEDIUM':
        return 'bg-orange-950/80 text-orange-300 border border-orange-800/60';
      case 'LOW':
        return 'bg-amber-950/80 text-amber-300 border border-amber-800/60';
      default:
        return 'bg-slate-800 text-slate-300 border border-slate-700';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Security Event Logs</h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Cryptographic audit trail recorded in persistent SQLite database.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <a
            href="/api/logs/export-csv"
            download="cybershield_security_events.csv"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export CSV</span>
          </a>

          <button
            onClick={fetchLogs}
            disabled={isLoading}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-100 bg-slate-800/60 border border-slate-700 transition-colors"
            title="Refresh logs"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-4 space-y-3">
        <form onSubmit={handleSearchSubmit} className="flex gap-2">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
            <input
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search by event reason code, description, or update ID..."
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <button
            type="submit"
            className="px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold"
          >
            Search
          </button>
        </form>

        <div className="flex flex-wrap items-center gap-3 text-xs">
          <div className="flex items-center gap-1.5 text-slate-400">
            <Filter className="w-3.5 h-3.5" />
            <span>Filter by:</span>
          </div>

          <select
            value={selectedDevice}
            onChange={e => {
              setSelectedDevice(e.target.value);
              setOffset(0);
            }}
            className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-200 text-xs font-mono"
          >
            <option value="">All Devices</option>
            {devices.map(d => (
              <option key={d.id} value={d.id}>
                {d.id} — {d.name}
              </option>
            ))}
          </select>

          <select
            value={selectedSeverity}
            onChange={e => {
              setSelectedSeverity(e.target.value);
              setOffset(0);
            }}
            className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-200 text-xs font-mono"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
            <option value="INFO">INFO</option>
          </select>

          <select
            value={selectedEventType}
            onChange={e => {
              setSelectedEventType(e.target.value);
              setOffset(0);
            }}
            className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-200 text-xs font-mono"
          >
            <option value="">All Event Types</option>
            <option value="FIRMWARE_UPDATE_SUCCESS">FIRMWARE_UPDATE_SUCCESS</option>
            <option value="FIRMWARE_UPDATE_REJECTED">FIRMWARE_UPDATE_REJECTED</option>
            <option value="SECURE_BOOT_SUCCESS">SECURE_BOOT_SUCCESS</option>
            <option value="SECURE_BOOT_FAILED">SECURE_BOOT_FAILED</option>
            <option value="REMOTE_ATTESTATION">REMOTE_ATTESTATION</option>
            <option value="DEVICE_REGISTERED">DEVICE_REGISTERED</option>
            <option value="SYSTEM_INITIALIZATION">SYSTEM_INITIALIZATION</option>
          </select>
        </div>
      </div>

      {/* Logs Table */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 text-[10px] font-mono uppercase tracking-wider bg-slate-950/40">
                <th className="py-3 px-4">TIMESTAMP</th>
                <th className="py-3 px-4">NODE ID</th>
                <th className="py-3 px-4">EVENT TYPE</th>
                <th className="py-3 px-4">SEVERITY</th>
                <th className="py-3 px-4">RESULT</th>
                <th className="py-3 px-4">DESCRIPTION / REASON CODE</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
              {events.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-500 font-sans">
                    No matching audit records found.
                  </td>
                </tr>
              ) : (
                events.map(evt => (
                  <tr key={evt.id} className="hover:bg-slate-800/40 text-slate-300">
                    <td className="py-3 px-4 whitespace-nowrap text-slate-400">
                      {new Date(evt.created_at).toLocaleString([], {
                        month: 'short',
                        day: '2-digit',
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit',
                      })}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap text-cyan-300 font-bold">
                      {evt.device_id || 'SYSTEM'}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap text-slate-200">
                      {evt.event_type}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded text-[9px] font-bold ${getSeverityBadge(evt.severity)}`}>
                        {evt.severity}
                      </span>
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      {evt.verification_result ? (
                        <span
                          className={`px-2 py-0.5 rounded text-[9px] font-bold ${
                            evt.verification_result === 'APPROVED' || evt.verification_result === 'PASSED'
                              ? 'bg-teal-950 text-teal-300'
                              : 'bg-red-950 text-red-300'
                          }`}
                        >
                          {evt.verification_result}
                        </span>
                      ) : (
                        <span className="text-slate-500">-</span>
                      )}
                    </td>
                    <td className="py-3 px-4 max-w-md font-sans">
                      <span className="text-slate-200 block">{evt.description}</span>
                      <span className="text-[10px] font-mono text-slate-500">
                        Reason: {evt.reason_code} {evt.update_id ? `· ${evt.update_id}` : ''}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Footer */}
        <div className="p-4 border-t border-slate-800/80 bg-slate-950/40 flex items-center justify-between text-xs text-slate-400">
          <span>
            Showing {events.length} of {total} audit records
          </span>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setOffset(Math.max(0, offset - limit))}
              disabled={offset === 0}
              className="p-1.5 rounded bg-slate-800 text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-700 transition-colors"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="font-mono text-[11px]">
              Page {Math.floor(offset / limit) + 1} of {Math.ceil(total / limit) || 1}
            </span>
            <button
              onClick={() => setOffset(offset + limit)}
              disabled={offset + limit >= total}
              className="p-1.5 rounded bg-slate-800 text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-700 transition-colors"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
