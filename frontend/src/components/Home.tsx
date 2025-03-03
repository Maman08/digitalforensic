import React from 'react';
import { Shield, Activity, Network, Lock, ChevronRight, Zap, Radio, Wifi } from 'lucide-react';

export function Home() {
  const quickActions = [
    {
      title: "Network Analysis",
      description: "Monitor real-time network traffic and analyze patterns",
      icon: <Network className="w-6 h-6 text-cyan-400" />,
      status: "Active",
      metric: "1.2k packets/sec"
    },
    {
      title: "Security Scan",
      description: "Run comprehensive vulnerability assessments",
      icon: <Shield className="w-6 h-6 text-purple-400" />,
      status: "Last scan: 2h ago",
      metric: "0 critical issues"
    },
    {
      title: "System Health",
      description: "Check overall system performance and status",
      icon: <Activity className="w-6 h-6 text-emerald-400" />,
      status: "Healthy",
      metric: "98% uptime"
    }
  ];

  const recentAlerts = [
    {
      type: "Security",
      message: "Unusual port scanning activity detected",
      time: "10 minutes ago",
      severity: "high"
    },
    {
      type: "Performance",
      message: "Network latency spike on main gateway",
      time: "25 minutes ago",
      severity: "medium"
    },
    {
      type: "System",
      message: "Automatic security patches installed",
      time: "1 hour ago",
      severity: "low"
    }
  ];

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'high':
        return 'text-red-400 border-red-500/20 bg-red-500/10';
      case 'medium':
        return 'text-yellow-400 border-yellow-500/20 bg-yellow-500/10';
      case 'low':
        return 'text-blue-400 border-blue-500/20 bg-blue-500/10';
      default:
        return 'text-gray-400 border-gray-500/20 bg-gray-500/10';
    }
  };

  return (
    <div className="p-8">
      {/* Welcome Section */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500 mb-4">
          Welcome to NetGuardian Pro
        </h1>
        <p className="text-gray-400 max-w-3xl">
          Your comprehensive network security and monitoring solution. Monitor, analyze, and secure your network infrastructure with advanced tools and real-time insights.
        </p>
      </div>

      {/* Quick Actions Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        {quickActions.map((action, index) => (
          <div key={index} className="bg-gray-900/50 backdrop-blur-sm rounded-xl p-6 hover-card">
            <div className="flex items-center space-x-3 mb-4">
              {action.icon}
              <h3 className="text-xl font-bold text-gray-100">{action.title}</h3>
            </div>
            <p className="text-gray-400 mb-4">{action.description}</p>
            <div className="flex justify-between items-center">
              <span className="text-sm text-gray-500">{action.status}</span>
              <span className="text-sm text-cyan-400">{action.metric}</span>
            </div>
          </div>
        ))}
      </div>

      {/* System Overview */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <div className="bg-gray-900/50 backdrop-blur-sm rounded-xl p-6 hover-card">
          <h2 className="text-xl font-semibold text-gray-100 mb-4 flex items-center">
            <Radio className="w-5 h-5 text-cyan-400 mr-2" />
            Network Status
          </h2>
          <div className="grid grid-cols-2 gap-4">
            <MetricCard
              label="Active Connections"
              value="1,284"
              trend="+12%"
              trendUp={true}
            />
            <MetricCard
              label="Bandwidth Usage"
              value="45.8 MB/s"
              trend="-3%"
              trendUp={false}
            />
            <MetricCard
              label="Packet Loss"
              value="0.02%"
              trend="-0.01%"
              trendUp={false}
            />
            <MetricCard
              label="Response Time"
              value="24ms"
              trend="+2ms"
              trendUp={true}
            />
          </div>
        </div>

        <div className="bg-gray-900/50 backdrop-blur-sm rounded-xl p-6 hover-card">
          <h2 className="text-xl font-semibold text-gray-100 mb-4 flex items-center">
            <Lock className="w-5 h-5 text-purple-400 mr-2" />
            Recent Alerts
          </h2>
          <div className="space-y-4">
            {recentAlerts.map((alert, index) => (
              <div 
                key={index}
                className={`p-4 rounded-lg border ${getSeverityColor(alert.severity)} transition-all duration-300`}
              >
                <div className="flex justify-between items-start mb-1">
                  <span className="font-medium">{alert.type}</span>
                  <span className="text-sm text-gray-500">{alert.time}</span>
                </div>
                <p className="text-sm">{alert.message}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Quick Links */}
      <div className="bg-gray-900/50 backdrop-blur-sm rounded-xl p-6 hover-card">
        <h2 className="text-xl font-semibold text-gray-100 mb-4 flex items-center">
          <Zap className="w-5 h-5 text-yellow-400 mr-2" />
          Quick Actions
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <button className="p-4 bg-cyan-500/10 rounded-lg transition-all duration-300 btn-glow flex items-center justify-between hover:bg-cyan-500/20">
            <span className="text-cyan-400">Run Security Scan</span>
            <ChevronRight className="w-5 h-5" />
          </button>
          <button className="p-4 bg-purple-500/10 rounded-lg transition-all duration-300 hover:bg-purple-500/20 border border-purple-500/30 flex items-center justify-between">
            <span className="text-purple-400">View Reports</span>
            <ChevronRight className="w-5 h-5" />
          </button>
          <button className="p-4 bg-emerald-500/10 rounded-lg transition-all duration-300 hover:bg-emerald-500/20 border border-emerald-500/30 flex items-center justify-between">
            <span className="text-emerald-400">System Settings</span>
            <ChevronRight className="w-5 h-5" />
          </button>
        </div>
      </div>
    </div>
  );
}

function MetricCard({ label, value, trend, trendUp }: {
  label: string;
  value: string;
  trend: string;
  trendUp: boolean;
}) {
  return (
    <div className="bg-black/50 rounded-lg p-4 border border-gray-800/50">
      <div className="text-sm text-gray-400 mb-1">{label}</div>
      <div className="text-xl font-bold text-gray-100">{value}</div>
      <div className={`text-sm ${trendUp ? 'text-emerald-400' : 'text-red-400'}`}>
        {trend}
      </div>
    </div>
  );
}