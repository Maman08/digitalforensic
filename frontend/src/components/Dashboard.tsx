import React from 'react';
import { Activity, Shield, Wifi, AlertTriangle } from 'lucide-react';
import { NetworkStats } from '../types';

const mockStats: NetworkStats = {
  packetsPerSecond: 1250,
  bandwidthUsage: 45.8,
  activeConnections: 28,
  alertsCount: 3
};

export function Dashboard() {
  return (
    <div className="p-8">
      <h1 className="text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500 mb-8">
        Dashboard Overview
      </h1>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <StatCard 
          title="Network Traffic"
          value={`${mockStats.packetsPerSecond} pps`}
          icon={<Activity className="w-6 h-6" />}
          color="text-cyan-400"
        />
        <StatCard 
          title="Bandwidth Usage"
          value={`${mockStats.bandwidthUsage} MB/s`}
          icon={<Wifi className="w-6 h-6" />}
          color="text-emerald-400"
        />
        <StatCard 
          title="Active Connections"
          value={mockStats.activeConnections.toString()}
          icon={<Shield className="w-6 h-6" />}
          color="text-violet-400"
        />
        <StatCard 
          title="Active Alerts"
          value={mockStats.alertsCount.toString()}
          icon={<AlertTriangle className="w-6 h-6" />}
          color="text-orange-400"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-gray-900/50 backdrop-blur-sm rounded-xl p-6 shadow-2xl hover-card">
          <h2 className="text-xl font-semibold text-gray-100 mb-4">Network Activity</h2>
          <div className="aspect-[16/9] bg-black/50 rounded-lg flex items-center justify-center border border-gray-800/50">
            <span className="text-gray-400">Network Graph Visualization</span>
          </div>
        </div>

        <div className="bg-gray-900/50 backdrop-blur-sm rounded-xl p-6 shadow-2xl hover-card">
          <h2 className="text-xl font-semibold text-gray-100 mb-4">Recent Alerts</h2>
          <div className="space-y-4">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="bg-black/50 rounded-lg p-4 flex items-center space-x-4 border border-gray-800/50 transition-all duration-300 hover:border-orange-500/30">
                <div className="w-2 h-2 rounded-full bg-orange-400 shadow-lg shadow-orange-400/50"></div>
                <div>
                  <h3 className="text-gray-100 font-medium">Suspicious Activity Detected</h3>
                  <p className="text-gray-400 text-sm">Port scan attempt from 192.168.1.{100 + i}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function StatCard({ title, value, icon, color }: { 
  title: string;
  value: string;
  icon: React.ReactNode;
  color: string;
}) {
  return (
    <div className="bg-gray-900/50 backdrop-blur-sm rounded-xl p-6 shadow-2xl hover-card border border-gray-800/50">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-gray-400 font-medium">{title}</h3>
        <div className={`${color} transform transition-transform duration-300 hover:scale-110`}>{icon}</div>
      </div>
      <p className="text-2xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-gray-100 to-gray-300">{value}</p>
    </div>
  );
}