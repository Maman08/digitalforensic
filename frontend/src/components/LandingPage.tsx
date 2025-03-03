import React from 'react';
import { Shield, Activity, Network, Lock, ChevronRight, Zap, Radio, Wifi } from 'lucide-react';
import { Link } from 'react-router-dom';

export function LandingPage() {
  return (
    <div className="min-h-screen relative overflow-hidden">
      {/* Animated Background Grid */}
      <div className="absolute inset-0 cyber-grid opacity-30"></div>
      
      {/* Floating Particles */}
      <div className="absolute inset-0 overflow-hidden">
        {[...Array(20)].map((_, i) => (
          <div
            key={i}
            className="absolute w-2 h-2 bg-cyan-500/30 rounded-full animate-float"
            style={{
              left: `${Math.random() * 100}%`,
              top: `${Math.random() * 100}%`,
              animationDelay: `${Math.random() * 5}s`,
              animationDuration: `${5 + Math.random() * 10}s`
            }}
          />
        ))}
      </div>

      {/* Hero Section */}
      <div className="relative z-10">
        <div className="container mx-auto px-6 py-16">
          <div className="text-center mb-16">
            <div className="flex justify-center mb-6">
              <div className="relative">
                <Shield className="w-20 h-20 text-cyan-400 animate-pulse" />
                <div className="absolute inset-0 bg-cyan-500/20 blur-xl rounded-full"></div>
              </div>
            </div>
            <h1 className="text-5xl md:text-7xl font-bold mb-6 text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-600 glitch-text">
              NetGuardian Pro
            </h1>
            <p className="text-xl text-gray-400 mb-8 max-w-2xl mx-auto">
              Advanced network security and packet analysis platform for the modern cyber landscape
            </p>
            <div className="flex justify-center space-x-4">
              <Link
                to="/dashboard"
                className="px-8 py-3 bg-cyan-500/10 text-cyan-400 rounded-lg transition-all duration-300 btn-glow flex items-center space-x-2 hover:bg-cyan-500/20"
              >
                <span>Launch Dashboard</span>
                <ChevronRight className="w-5 h-5" />
              </Link>
              <a
                href="#features"
                className="px-8 py-3 bg-purple-500/10 text-purple-400 rounded-lg transition-all duration-300 hover:bg-purple-500/20 border border-purple-500/30"
              >
                Learn More
              </a>
            </div>
          </div>

          {/* Stats Section */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-16">
            <div className="bg-gray-900/50 backdrop-blur-sm rounded-xl p-6 hover-card">
              <div className="flex items-center space-x-4 mb-4">
                <Activity className="w-8 h-8 text-cyan-400" />
                <h3 className="text-2xl font-bold text-gray-100">Real-time Analysis</h3>
              </div>
              <p className="text-gray-400">Monitor network traffic and detect threats as they happen with millisecond precision</p>
            </div>
            <div className="bg-gray-900/50 backdrop-blur-sm rounded-xl p-6 hover-card">
              <div className="flex items-center space-x-4 mb-4">
                <Network className="w-8 h-8 text-purple-400" />
                <h3 className="text-2xl font-bold text-gray-100">Deep Inspection</h3>
              </div>
              <p className="text-gray-400">Advanced packet analysis and vulnerability scanning for comprehensive security</p>
            </div>
            <div className="bg-gray-900/50 backdrop-blur-sm rounded-xl p-6 hover-card">
              <div className="flex items-center space-x-4 mb-4">
                <Lock className="w-8 h-8 text-emerald-400" />
                <h3 className="text-2xl font-bold text-gray-100">Secure Platform</h3>
              </div>
              <p className="text-gray-400">Enterprise-grade security with end-to-end encryption and secure data handling</p>
            </div>
          </div>

          {/* Features Section */}
          <div id="features" className="py-16">
            <h2 className="text-4xl font-bold text-center mb-12 text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500">
              Advanced Features
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
              <FeatureCard
                icon={<Zap className="w-6 h-6" />}
                title="Packet Analysis"
                description="Detailed packet inspection and protocol analysis for comprehensive network visibility"
                color="text-yellow-400"
              />
              <FeatureCard
                icon={<Radio className="w-6 h-6" />}
                title="Network Monitoring"
                description="Real-time monitoring of network traffic patterns and anomaly detection"
                color="text-cyan-400"
              />
              <FeatureCard
                icon={<Shield className="w-6 h-6" />}
                title="Vulnerability Scanning"
                description="Automated security assessments and vulnerability detection"
                color="text-purple-400"
              />
              <FeatureCard
                icon={<Activity className="w-6 h-6" />}
                title="Performance Metrics"
                description="Comprehensive network performance monitoring and analysis"
                color="text-emerald-400"
              />
              <FeatureCard
                icon={<Lock className="w-6 h-6" />}
                title="Security Alerts"
                description="Instant notifications for potential security threats and breaches"
                color="text-red-400"
              />
              <FeatureCard
                icon={<Wifi className="w-6 h-6" />}
                title="Protocol Support"
                description="Support for all major network protocols and custom protocol analysis"
                color="text-blue-400"
              />
            </div>
          </div>

          {/* CTA Section */}
          <div className="text-center py-16">
            <h2 className="text-3xl font-bold mb-6 text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-purple-500">
              Ready to secure your network?
            </h2>
            <Link
              to="/dashboard"
              className="inline-flex items-center space-x-2 px-8 py-3 bg-gradient-to-r from-cyan-500/20 to-purple-500/20 text-cyan-400 rounded-lg transition-all duration-300 btn-glow hover:from-cyan-500/30 hover:to-purple-500/30"
            >
              <span>Get Started Now</span>
              <ChevronRight className="w-5 h-5" />
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}

function FeatureCard({ icon, title, description, color }: {
  icon: React.ReactNode;
  title: string;
  description: string;
  color: string;
}) {
  return (
    <div className="bg-gray-900/50 backdrop-blur-sm rounded-xl p-6 hover-card border border-gray-800/50 transition-all duration-300 hover:border-cyan-500/30">
      <div className={`${color} mb-4`}>{icon}</div>
      <h3 className="text-xl font-bold text-gray-100 mb-2">{title}</h3>
      <p className="text-gray-400">{description}</p>
    </div>
  );
}