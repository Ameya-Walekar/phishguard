import React, { useState, useEffect, useCallback } from 'react';
import { fetchLogs } from './api/backend';
import ThreatChart from './components/ThreatChart';
import {
  ShieldAlert, ShieldCheck, Activity, Download,
  Server, AlertTriangle, Shield, Lock, Trash2, RefreshCw
} from 'lucide-react';

function App() {
  const [logs, setLogs] = useState([]);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);

  const loadIntelligence = useCallback(async (showSpinner = false) => {
    if (showSpinner) setIsRefreshing(true);
    const data = await fetchLogs();
    setLogs(data);
    if (showSpinner) setIsRefreshing(false);
  }, []);

  useEffect(() => {
    loadIntelligence();
  }, [loadIntelligence]);

  const handleClearLogs = () => {
    setLogs([]);          // just wipe local state — no backend call
    setShowConfirm(false);
  };

  const blockedThreats  = logs.filter(log => log.risk_score >= 0.7).length;
  const safePasses      = logs.filter(log => log.risk_score <= 0.2).length;
  const forensicTriage  = logs.length - blockedThreats - safePasses;

  const exportIoCReport = (log) => {
    const report = {
      timestamp: new Date().toISOString(),
      threat_type: "Phishing/Malicious URL",
      indicator_of_compromise: log.url,
      ml_confidence_score: log.risk_score,
      system_verdict: log.status,
      action_taken: log.risk_score >= 0.7 ? "Blocked by Extension" : "Silently Monitored",
      backend_telemetry: "Extracted Lexical Features & Forensic Data Check"
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const downloadUrl = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = `PhishGuard_IoC_${log.url.replace(/[^a-zA-Z0-9]/g, "_")}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="h-screen flex flex-col bg-gradient-to-br from-gray-900 via-slate-900 to-black text-gray-100 p-4 font-sans overflow-hidden">

      {/* Confirm modal */}
      {showConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
          <div className="bg-gray-900 border border-red-500/30 rounded-xl p-6 max-w-sm w-full mx-4 shadow-2xl shadow-red-900/20">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-9 h-9 rounded-lg bg-red-500/10 border border-red-500/30 flex items-center justify-center">
                <Trash2 className="w-4 h-4 text-red-400" />
              </div>
              <h3 className="text-sm font-bold text-white tracking-wide">Clear Dashboard?</h3>
            </div>
            <p className="text-xs text-gray-400 mb-5 leading-relaxed">
              This will remove all entries from the dashboard view. The data on the backend is unaffected and will reload on next refresh.
            </p>
            <div className="flex gap-2">
              <button
                onClick={() => setShowConfirm(false)}
                className="flex-1 px-3 py-2 text-xs font-semibold bg-gray-800 hover:bg-gray-700 border border-gray-700 rounded-lg transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleClearLogs}
                className="flex-1 px-3 py-2 text-xs font-semibold bg-red-600 hover:bg-red-500 rounded-lg transition-colors text-white"
              >
                Yes, Clear View
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Header */}
      <header className="flex-none mb-4 flex justify-between items-center border-b border-gray-800 pb-3">
        <h1 className="text-2xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 to-cyan-500 flex items-center gap-2">
          <Shield className="w-6 h-6 text-emerald-400" /> PhishGuard Dashboard
        </h1>
        <div className="flex items-center gap-2">
          <button
            onClick={() => loadIntelligence(true)}
            disabled={isRefreshing}
            title="Refresh logs"
            className="p-1.5 rounded-lg bg-gray-800/50 border border-gray-700/50 hover:bg-gray-700/60 transition-colors disabled:opacity-40"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-gray-400 ${isRefreshing ? 'animate-spin' : ''}`} />
          </button>
          <div className="px-3 py-1 bg-gray-800/50 backdrop-blur-md rounded-full text-[10px] border border-gray-700/50 flex items-center gap-2">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span className="text-emerald-400 font-mono font-bold tracking-wider">SYSTEM ONLINE</span>
          </div>
        </div>
      </header>

      {/* Metrics + Graph */}
      <div className="flex-none grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4">
        <div className="lg:col-span-2 grid grid-cols-2 md:grid-cols-4 gap-3">
          <div className="bg-gray-800/40 backdrop-blur-sm p-3 rounded-lg border border-gray-700/50 flex flex-col justify-between">
            <div className="flex justify-between items-start">
              <h2 className="text-[14px] font-bold text-gray-400 uppercase tracking-widest">Total</h2>
              <Activity className="w-3.5 h-3.5 text-blue-400" />
            </div>
            <p className="text-xl font-bold text-white mt-0.5">{logs.length}</p>
          </div>
          <div className="bg-gray-800/40 backdrop-blur-sm p-3 rounded-lg border border-gray-700/50 flex flex-col justify-between">
            <div className="flex justify-between items-start">
              <h2 className="text-[14px] font-bold text-gray-400 uppercase tracking-widest">Safe</h2>
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            </div>
            <p className="text-xl font-bold text-emerald-400 mt-0.5">{safePasses}</p>
          </div>
          <div className="bg-gray-800/40 backdrop-blur-sm p-3 rounded-lg border border-gray-700/50 flex flex-col justify-between">
            <div className="flex justify-between items-start">
              <h2 className="text-[14px] font-bold text-gray-400 uppercase tracking-widest">Triage</h2>
              <Server className="w-3.5 h-3.5 text-amber-400" />
            </div>
            <p className="text-xl font-bold text-amber-400 mt-0.5">{forensicTriage}</p>
          </div>
          <div className="bg-gray-800/40 backdrop-blur-sm p-3 rounded-lg border border-gray-700/50 flex flex-col justify-between">
            <div className="flex justify-between items-start">
              <h2 className="text-[14px] font-bold text-gray-400 uppercase tracking-widest">Malicious</h2>
              <ShieldAlert className="w-3.5 h-3.5 text-red-500" />
            </div>
            <p className="text-xl font-bold text-red-500 mt-0.5">{blockedThreats}</p>
          </div>
        </div>

        <div className="lg:col-span-1 bg-gray-800/40 backdrop-blur-sm p-3 rounded-lg border border-gray-700/50 h-32 flex flex-col">
          <h2 className="text-[9px] font-bold text-gray-400 uppercase tracking-widest mb-1 flex items-center gap-1.5">
            <Activity className="w-3 h-3 text-blue-400" /> Risk Trends
          </h2>
          <div className="flex-1 min-h-0">
            {logs.length > 0 ? <ThreatChart data={logs} /> : <p className="text-gray-500 text-[10px] font-mono">No data</p>}
          </div>
        </div>
      </div>

      {/* Traffic Logs */}
      <div className="flex-1 bg-gray-800/40 backdrop-blur-sm rounded-lg border border-gray-700/50 shadow-xl overflow-hidden flex flex-col">
        <div className="p-3 border-b border-gray-700/50 bg-gray-900/50 flex-none flex justify-between items-center">
          <h2 className="text-xs font-bold text-gray-300 uppercase tracking-widest flex items-center gap-2">
            <Server className="w-4 h-4 text-emerald-400" /> Live Intercepted Traffic
          </h2>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowConfirm(true)}
              disabled={logs.length === 0}
              title={logs.length === 0 ? "No logs to clear" : "Clear dashboard view"}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[10px] font-semibold
                         bg-red-900/20 border border-red-500/20 text-red-400
                         hover:bg-red-600 hover:text-white hover:border-red-600
                         disabled:opacity-30 disabled:cursor-not-allowed
                         transition-all duration-150"
            >
              <Trash2 className="w-3 h-3" /> Clear Logs
            </button>
            <Lock className="w-3.5 h-3.5 text-gray-600" />
          </div>
        </div>

        <div className="flex-1 overflow-y-auto custom-scrollbar">
          {logs.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full gap-3 text-gray-600">
              <Shield className="w-8 h-8 opacity-30" />
              <p className="text-xs font-mono tracking-widest uppercase opacity-60">No intercepts recorded</p>
            </div>
          ) : (
            <table className="w-full text-left border-collapse">
              <thead className="bg-gray-900 sticky top-0 z-10 text-gray-400 text-[10px] uppercase tracking-widest border-b border-gray-700/50">
                <tr>
                  <th className="p-4 font-semibold">Target URL</th>
                  <th className="p-4 font-semibold text-center w-24">Lexical Risk</th>
                  <th className="p-4 font-semibold w-24">Status</th>
                  <th className="p-4 font-semibold text-right w-24">Action</th>
                </tr>
              </thead>
              <tbody className="text-gray-300">
                {[...logs].reverse().map((log) => (
                  <tr key={log.id} className="border-b border-gray-700/30 hover:bg-gray-700/40 transition-colors text-xs">
                    <td className="p-4 font-mono truncate max-w-[200px]">{log.url}</td>
                    <td className="p-4 text-center">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${log.risk_score >= 0.7 ? 'bg-red-500/10 text-red-400 border border-red-500/30' : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'}`}>
                        {log.risk_score.toFixed(3)}
                      </span>
                    </td>
                    <td className="p-4 font-medium flex items-center gap-1.5">
                      {log.status === "Safe" ? <ShieldCheck className="w-3 h-3 text-emerald-400" /> : <AlertTriangle className="w-3 h-3 text-red-400" />}
                      {log.status}
                    </td>
                    <td className="p-4 text-right">
                      <button onClick={() => exportIoCReport(log)} className="inline-flex items-center gap-1.5 bg-gray-700 hover:bg-emerald-600 px-2 py-1 rounded transition-colors text-[10px]">
                        <Download className="w-3 h-3" /> JSON
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;