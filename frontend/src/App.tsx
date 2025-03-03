import React, { useState, useEffect } from 'react';
import { Layout, BarChart2, Shield, Search, Home as HomeIcon } from 'lucide-react';
import { Dashboard } from './components/Dashboard';
import { NetworkMonitor } from './components/NetworkMonitor';
import {MemoryForensic} from './components/MemoryForensic'
import { VulnerabilityScanner } from './components/VulnerabilityScanner';
import {SSHDashboard} from "./components/SSHDashboard"
import { Home } from './components/Home';
import { Terminal } from './components/Terminal';

function App() {
  const [activeTab, setActiveTab] = useState('home');

  // Mouse position tracking for hover effects
  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      document.querySelectorAll('.hover-card, .btn-glow').forEach((el) => {
        const rect = (el as HTMLElement).getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        (el as HTMLElement).style.setProperty('--mouse-x', `${x}px`);
        (el as HTMLElement).style.setProperty('--mouse-y', `${y}px`);
      });
    };

    window.addEventListener('mousemove', handleMouseMove);
    return () => window.removeEventListener('mousemove', handleMouseMove);
  }, []);

  const navigation = [
    { id: 'home', name: 'Home', icon: <HomeIcon className="w-5 h-5" /> },
    { id: 'dashboard', name: 'Dashboard', icon: <Layout className="w-5 h-5" /> },
    { id: 'network', name: 'Network Monitor', icon: <BarChart2 className="w-5 h-5" /> },
    { id: 'vulnerabilities', name: 'Scanner', icon: <Search className="w-5 h-5" /> },
    { id: 'memoryforensic', name: 'Memory Forensic', icon: <Search className="w-5 h-5" /> },
    { id: 'sshdashboard', name: 'SSH Dashboard', icon: <Search className="w-5 h-5" /> }
  ];

  return (
    <div className="min-h-screen bg-black text-white flex relative overflow-hidden">
      <div className="absolute inset-0 cyber-grid opacity-30"></div>
      
      {/* Sidebar */}
      <div className="w-64 gradient-dark shadow-2xl relative z-10">
        <div className="p-6">
          <div 
            className="flex items-center space-x-3 mb-8 hover-card p-4 rounded-lg glitch-container"
            data-text="NetGuard"
          >
            <Shield className="w-8 h-8 text-teal-400" />
            <span className="text-xl font-bold text-holographic">
              NetGuard
            </span>
          </div>
          
          <nav className="space-y-3">
            {navigation.map((item) => (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg btn-glow ${
                  activeTab === item.id
                    ? 'bg-gradient-to-r from-teal-500/20 to-cyan-500/20 text-teal-300'
                    : 'text-gray-400 hover:text-teal-300'
                }`}
              >
                {item.icon}
                <span>{item.name}</span>
              </button>
            ))}
          </nav>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 overflow-auto relative z-10">
        <div className="fade-in">
          {activeTab === 'home' && <Home />}
          {activeTab === 'dashboard' && <Dashboard />}
          {activeTab === 'network' && <NetworkMonitor />}
          {activeTab === 'vulnerabilities' && <VulnerabilityScanner />}
          {activeTab === 'memoryforensic' && <MemoryForensic />}
          {activeTab === 'sshdashboard' && <SSHDashboard/>}
        </div>
      </div>

      {/* Integrated Terminal */}
      <Terminal />
    </div>
  );
}

export default App