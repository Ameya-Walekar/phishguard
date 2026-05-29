import React from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

export default function ThreatChart({ data }) {
  // Format the backend logs specifically for Recharts
  const chartData = data.map((log, index) => ({
    scanId: `ID-${log.id}`,
    riskScore: log.risk_score,
    url: log.url,
  }));

  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={chartData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
        <defs>
          <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
            {/* Crimson red gradient for high-risk visualizing */}
            <stop offset="5%" stopColor="#ef4444" stopOpacity={0.8}/>
            <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="#374151" vertical={false} />
        <XAxis dataKey="scanId" stroke="#9ca3af" fontSize={12} />
        <YAxis stroke="#9ca3af" domain={[0, 1]} fontSize={12} />
        <Tooltip 
          contentStyle={{ backgroundColor: '#1f2937', borderColor: '#374151', color: '#fff', borderRadius: '8px' }}
          itemStyle={{ color: '#ef4444', fontWeight: 'bold' }}
          labelStyle={{ color: '#9ca3af' }}
        />
        <Area type="monotone" dataKey="riskScore" stroke="#ef4444" strokeWidth={2} fillOpacity={1} fill="url(#colorRisk)" />
      </AreaChart>
    </ResponsiveContainer>
  );
}