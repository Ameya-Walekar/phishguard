import React, { useState, useEffect } from 'react';
import { fetchLogs } from './api/backend';
import ThreatChart from './components/ThreatChart';
import { ShieldAlert, ShieldCheck, Activity, Download, Server, AlertTriangle, Shield, Lock } from 'lucide-react';

function App() {
  const [logs, setLogs] = useState([]);

  useEffect(() => {
    const loadIntelligence = async () => {
      const data = await fetchLogs();
      setLogs(data);
    };
    loadIntelligence();
  }, []);

  const blockedThreats = logs.filter(log => log.risk_score >= 0.7).length;
  const safePasses = logs.filter(log => log.risk_score <= 0.2).length;
  const forensicTriage = logs.length - blockedThreats - safePasses;

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
      
      {/* Header */}
      <header className="flex-none mb-4 flex justify-between items-center border-b border-gray-800 pb-3">
        <h1 className="text-2xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 to-cyan-500 flex items-center gap-2">
          <Shield className="w-6 h-6 text-emerald-400" /> PhishGuard Dashboard
        </h1>
        <div className="px-3 py-1 bg-gray-800/50 backdrop-blur-md rounded-full text-[10px] border border-gray-700/50 flex items-center gap-2">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
          </span>
          <span className="text-emerald-400 font-mono font-bold tracking-wider">SYSTEM ONLINE</span>
        </div>
      </header>

      {/* Top Section: Compact Metrics (Left) and Graph (Right) */}
      <div className="flex-none grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4">
        
        {/* Metric Cards - Left (2/3 width) */}
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
               <h2 className="text-[14px] font-bold text-gray-400 uppercase tracking-widest">Blocked</h2>
               <ShieldAlert className="w-3.5 h-3.5 text-red-500" />
            </div>
            <p className="text-xl font-bold text-red-500 mt-0.5">{blockedThreats}</p>
          </div>
        </div>

        {/* Threat Graph - Right (1/3 width) */}
        <div className="lg:col-span-1 bg-gray-800/40 backdrop-blur-sm p-3 rounded-lg border border-gray-700/50 h-32 flex flex-col">
          <h2 className="text-[9px] font-bold text-gray-400 uppercase tracking-widest mb-1 flex items-center gap-1.5">
            <Activity className="w-3 h-3 text-blue-400" /> Risk Trends
          </h2>
          <div className="flex-1 min-h-0">
            {logs.length > 0 ? <ThreatChart data={logs} /> : <p className="text-gray-500 text-[10px] font-mono">No data</p>}
          </div>
        </div>
      </div>

      {/* Traffic Logs - Bottom (Full width, Scrollable) */}
      <div className="flex-1 bg-gray-800/40 backdrop-blur-sm rounded-lg border border-gray-700/50 shadow-xl overflow-hidden flex flex-col">
        <div className="p-3 border-b border-gray-700/50 bg-gray-900/50 flex-none flex justify-between items-center">
           <h2 className="text-xs font-bold text-gray-300 uppercase tracking-widest flex items-center gap-2">
             <Server className="w-4 h-4 text-emerald-400" /> Live Intercepted Traffic
           </h2>
           <Lock className="w-3.5 h-3.5 text-gray-600" />
        </div>
        <div className="flex-1 overflow-y-auto custom-scrollbar">
          <table className="w-full text-left border-collapse">
            <thead className="bg-gray-900 sticky top-0 z-10 text-gray-400 text-[10px] uppercase tracking-widest border-b border-gray-700/50">
              <tr>
                <th className="p-4 font-semibold">Target URL</th>
                <th className="p-4 font-semibold text-center w-24">Risk</th>
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
        </div>
      </div>
    </div>
  );
}

export default App;