import React from 'react';
import { NetworkDevice } from '../types';
import { Shield, Clock, Radio, RefreshCw, Filter } from 'lucide-react';

const mockDevices: NetworkDevice[] = [
  {
    id: '1',
    ip: '192.168.1.7',
    connectionDuration: '2h 15m',
    protocol: 'TCP',
    ports: ['80', '443'],
    status: 'active',
    lastSeen: '2 seconds ago'
  },
  {
    id: '2',
    ip: '192.168.1.3',
    connectionDuration: '45m',
    protocol: 'UDP',
    ports: ['53'],
    status: 'active',
    lastSeen: '5 seconds ago'
  }
];

export function NetworkMonitor() {
  return (
    <div className="p-8">
      <h1 className="text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500 mb-8">
        Network Monitoring
      </h1>

      <div className="bg-gray-900/50 backdrop-blur-sm rounded-xl p-6 shadow-2xl hover-card mb-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-semibold text-gray-100">Connected Devices</h2>
          <div className="flex space-x-2">
            <button className="px-4 py-2 bg-cyan-500/10 text-cyan-400 rounded-lg transition-all duration-300 btn-glow flex items-center space-x-2">
              <RefreshCw className="w-4 h-4" />
              <span>Refresh</span>
            </button>
            <button className="px-4 py-2 bg-gray-800/50 text-gray-300 rounded-lg transition-all duration-300 hover:bg-gray-700/50 flex items-center space-x-2">
              <Filter className="w-4 h-4" />
              <span>Filter</span>
            </button>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-left text-gray-400 border-b border-gray-800/50">
                <th className="pb-3">Status</th>
                <th className="pb-3">IP Address</th>
                <th className="pb-3">Protocol</th>
                <th className="pb-3">Ports</th>
                <th className="pb-3">Duration</th>
                <th className="pb-3">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {mockDevices.map((device) => (
                <tr key={device.id} className="border-b border-gray-800/50 table-row-hover">
                  <td className="py-4">
                    <span className={`inline-block w-2 h-2 rounded-full ${
                      device.status === 'active' ? 'bg-green-400 shadow-lg shadow-green-400/50' : 'bg-gray-400'
                    }`}></span>
                  </td>
                  <td className="py-4 text-gray-100">{device.ip}</td>
                  <td className="py-4 text-gray-100">{device.protocol}</td>
                  <td className="py-4 text-gray-100">{device.ports.join(', ')}</td>
                  <td className="py-4 text-gray-100">{device.connectionDuration}</td>
                  <td className="py-4 text-gray-400">{device.lastSeen}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="grid grid-cols-1  gap-6">
        <div className="bg-gray-900/50 backdrop-blur-sm rounded-xl p-6 shadow-2xl ">
          <h2 className="text-xl font-semibold text-gray-100 mb-4">Traffic Analysis</h2>
          <div className="bg-gray-900/50 p-6 rounded-lg border border-gray-800">
        <iframe
          src="http://localhost:3000/d/eebzend3lr7k0f/net-guard?orgId=1&from=2025-02-08T21:46:10.000Z&to=2025-02-08T21:51:10.000Z&timezone=browser&refresh=5s"
          width="100%"
          height="600"
          frameBorder="0"
          title="Grafana Dashboard"
        />
      </div>
        </div>

        
      </div>
    </div>
  );
}

function MetricCard({ icon, label, value }: {
  icon: React.ReactNode;
  label: string;
  value: string;
}) {
  return (
    <div className="bg-black/50 rounded-lg p-4 border border-gray-800/50 transition-all duration-300 hover:border-cyan-500/30">
      <div className="flex items-center space-x-3 mb-2">
        <div className="text-cyan-400">{icon}</div>
        <span className="text-gray-400 text-sm">{label}</span>
      </div>
      <p className="text-xl font-semibold text-transparent bg-clip-text bg-gradient-to-r from-gray-100 to-gray-300">{value}</p>
    </div>
  );
}