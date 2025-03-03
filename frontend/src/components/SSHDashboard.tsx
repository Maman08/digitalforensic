// import React, { useState, useEffect } from 'react';
// import { Table } from "./ui/table";
// import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
// import { Badge } from "./ui/badge";
// import { Alert, AlertTitle, AlertDescription } from "./ui/alert";
// import { Tabs, TabsContent, TabsList, TabsTrigger } from "./ui/tabs";
// import { ShieldAlert, AlertTriangle, Check, RefreshCw, Server, Network, Shield } from 'lucide-react';

// interface SSHConnection {
//   src_ip: string;
//   dst_ip: string;
//   timestamp: string;
// }

// interface BruteForceAttempt {
//   [key: string]: number;
// }

// interface SSHAttackDetection {
//   suspicious_ips: string[];
//   brute_force_attempts: BruteForceAttempt;
// }

// export const SSHDashboard: React.FC = () => {
//   const [sshConnections, setSSHConnections] = useState<SSHConnection[]>([]);
//   const [attackDetection, setAttackDetection] = useState<SSHAttackDetection>({
//     suspicious_ips: [],
//     brute_force_attempts: {}
//   });
//   const [isLoading, setIsLoading] = useState<boolean>(true);
//   const [lastUpdated, setLastUpdated] = useState<string>('');
//   const [activeTab, setActiveTab] = useState('overview');
//   const [selectedIP, setSelectedIP] = useState<string | null>(null);
  
//   const trustedIPs = ["192.168.45.57", "163.70.139.60"];
  
//   // Simulate fetching data from API
//   const fetchData = async () => {
//     setIsLoading(true);
//     try {
//       // In a real app, these would be actual API calls
//       // const connectionsResponse = await fetch('/api/ssh-connections');
//       // const attacksResponse = await fetch('/api/detect-ssh-attacks');
      
//       // Simulated data for demonstration
//       const mockConnections: SSHConnection[] = [
//         { src_ip: '45.132.67.89', dst_ip: '192.168.1.5', timestamp: '2025-03-02T14:23:17Z' },
//         { src_ip: '192.168.45.57', dst_ip: '192.168.1.5', timestamp: '2025-03-02T14:20:45Z' },
//         { src_ip: '89.248.165.32', dst_ip: '192.168.1.5', timestamp: '2025-03-02T14:18:10Z' },
//         { src_ip: '45.132.67.89', dst_ip: '192.168.1.10', timestamp: '2025-03-02T14:15:22Z' },
//         { src_ip: '103.145.12.8', dst_ip: '192.168.1.5', timestamp: '2025-03-02T14:10:05Z' },
//         { src_ip: '163.70.139.60', dst_ip: '192.168.1.10', timestamp: '2025-03-02T13:58:33Z' },
//       ];
      
//       const mockAttackData: SSHAttackDetection = {
//         suspicious_ips: ['45.132.67.89', '103.145.12.8', '89.248.165.32'],
//         brute_force_attempts: {
//           '45.132.67.89': 28,
//           '103.145.12.8': 12,
//           '89.248.165.32': 47,
//           '77.246.159.92': 3,
//         }
//       };
      
//       setSSHConnections(mockConnections);
//       setAttackDetection(mockAttackData);
//       setLastUpdated(new Date().toLocaleTimeString());
//     } catch (error) {
//       console.error('Error fetching data:', error);
//     } finally {
//       setIsLoading(false);
//     }
//   };
  
//   useEffect(() => {
//     fetchData();
    
//     // Set up regular refresh interval
//     const intervalId = setInterval(fetchData, 30000);
    
//     return () => clearInterval(intervalId);
//   }, []);
  
//   const getBadgeStyle = (ip: string) => {
//     if (trustedIPs.includes(ip)) {
//       return 'bg-green-100 text-green-800 hover:bg-green-200';
//     }
//     if (attackDetection.suspicious_ips.includes(ip)) {
//       return 'bg-red-100 text-red-800 hover:bg-red-200';
//     }
//     if (attackDetection.brute_force_attempts[ip]) {
//       return 'bg-yellow-100 text-yellow-800 hover:bg-yellow-200';
//     }
//     return 'bg-blue-100 text-blue-800 hover:bg-blue-200';
//   };
  
//   const getThreatLevel = (ip: string) => {
//     if (trustedIPs.includes(ip)) {
//       return 'Trusted';
//     }
    
//     const bruteForceCount = attackDetection.brute_force_attempts[ip] || 0;
//     const isSuspicious = attackDetection.suspicious_ips.includes(ip);
    
//     if (isSuspicious && bruteForceCount > 20) {
//       return 'Critical';
//     } else if (isSuspicious || bruteForceCount > 20) {
//       return 'High';
//     } else if (bruteForceCount > 5) {
//       return 'Medium';
//     } else if (bruteForceCount > 0) {
//       return 'Low';
//     }
    
//     return 'None';
//   };

//   const getThreatLevelBadge = (level: string) => {
//     switch (level) {
//       case 'Critical':
//         return <Badge className="bg-red-600 text-white">Critical</Badge>;
//       case 'High':
//         return <Badge className="bg-red-500 text-white">High</Badge>;
//       case 'Medium':
//         return <Badge className="bg-orange-500 text-white">Medium</Badge>;
//       case 'Low':
//         return <Badge className="bg-yellow-500 text-white">Low</Badge>;
//       case 'Trusted':
//         return <Badge className="bg-green-500 text-white">Trusted</Badge>;
//       default:
//         return <Badge className="bg-gray-500 text-white">None</Badge>;
//     }
//   };
  
//   const uniqueIPs = Array.from(new Set([
//     ...sshConnections.map(conn => conn.src_ip),
//     ...Object.keys(attackDetection.brute_force_attempts)
//   ]));
  
//   const handleIPClick = (ip: string) => {
//     setSelectedIP(ip);
//     setActiveTab('ipDetails');
//   };
  
//   const refreshData = () => {
//     fetchData();
//   };
  
//   const threatSummary = {
//     critical: uniqueIPs.filter(ip => getThreatLevel(ip) === 'Critical').length,
//     high: uniqueIPs.filter(ip => getThreatLevel(ip) === 'High').length,
//     medium: uniqueIPs.filter(ip => getThreatLevel(ip) === 'Medium').length,
//     low: uniqueIPs.filter(ip => getThreatLevel(ip) === 'Low').length,
//     trusted: uniqueIPs.filter(ip => getThreatLevel(ip) === 'Trusted').length,
//   };
  
//   return (
//     <div className="p-6 max-w-6xl mx-auto">
//       <div className="flex justify-between items-center mb-6">
//         <h1 className="text-3xl font-bold flex items-center">
//           <Shield className="mr-2" /> SSH Lateral Movement Detection
//         </h1>
//         <div className="flex items-center space-x-2">
//           <span className="text-sm text-gray-500">Last updated: {lastUpdated}</span>
//           <button 
//             onClick={refreshData}
//             className="p-2 rounded-full hover:bg-gray-100"
//             disabled={isLoading}
//           >
//             <RefreshCw className={`h-5 w-5 ${isLoading ? 'animate-spin' : ''}`} />
//           </button>
//         </div>
//       </div>
      
//       <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
//         <TabsList className="mb-4">
//           <TabsTrigger value="overview">Overview</TabsTrigger>
//           <TabsTrigger value="connections">Connections</TabsTrigger>
//           <TabsTrigger value="threats">Threats</TabsTrigger>
//           {selectedIP && (
//             <TabsTrigger value="ipDetails">IP: {selectedIP}</TabsTrigger>
//           )}
//         </TabsList>
        
//         <TabsContent value="overview" className="space-y-4">
//           <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
//             <Card>
//               <CardHeader className="pb-2">
//                 <CardTitle className="text-lg">Active Connections</CardTitle>
//               </CardHeader>
//               <CardContent>
//                 <div className="text-3xl font-bold">{sshConnections.length}</div>
//                 <p className="text-sm text-gray-500">Total SSH sessions</p>
//               </CardContent>
//             </Card>
            
//             <Card>
//               <CardHeader className="pb-2">
//                 <CardTitle className="text-lg">Suspicious IPs</CardTitle>
//               </CardHeader>
//               <CardContent>
//                 <div className="text-3xl font-bold">{attackDetection.suspicious_ips.length}</div>
//                 <p className="text-sm text-gray-500">Unauthorized successful logins</p>
//               </CardContent>
//             </Card>
            
//             <Card>
//               <CardHeader className="pb-2">
//                 <CardTitle className="text-lg">Brute Force Attempts</CardTitle>
//               </CardHeader>
//               <CardContent>
//                 <div className="text-3xl font-bold">{Object.keys(attackDetection.brute_force_attempts).length}</div>
//                 <p className="text-sm text-gray-500">IPs with failed password attempts</p>
//               </CardContent>
//             </Card>
//           </div>
          
//           <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
//             <Card>
//               <CardHeader>
//                 <CardTitle>Threat Summary</CardTitle>
//                 <CardDescription>SSH connection threat assessment</CardDescription>
//               </CardHeader>
//               <CardContent>
//                 <div className="space-y-2">
//                   <div className="flex justify-between items-center">
//                     <span className="flex items-center">
//                       <Badge className="bg-red-600 text-white mr-2">Critical</Badge>
//                       Critical Threats
//                     </span>
//                     <span className="font-bold">{threatSummary.critical}</span>
//                   </div>
//                   <div className="flex justify-between items-center">
//                     <span className="flex items-center">
//                       <Badge className="bg-red-500 text-white mr-2">High</Badge>
//                       High Risk
//                     </span>
//                     <span className="font-bold">{threatSummary.high}</span>
//                   </div>
//                   <div className="flex justify-between items-center">
//                     <span className="flex items-center">
//                       <Badge className="bg-orange-500 text-white mr-2">Medium</Badge>
//                       Medium Risk
//                     </span>
//                     <span className="font-bold">{threatSummary.medium}</span>
//                   </div>
//                   <div className="flex justify-between items-center">
//                     <span className="flex items-center">
//                       <Badge className="bg-yellow-500 text-white mr-2">Low</Badge>
//                       Low Risk
//                     </span>
//                     <span className="font-bold">{threatSummary.low}</span>
//                   </div>
//                   <div className="flex justify-between items-center">
//                     <span className="flex items-center">
//                       <Badge className="bg-green-500 text-white mr-2">Trusted</Badge>
//                       Trusted IPs
//                     </span>
//                     <span className="font-bold">{threatSummary.trusted}</span>
//                   </div>
//                 </div>
//               </CardContent>
//             </Card>
            
//             <Card>
//               <CardHeader>
//                 <CardTitle>Recent Activity</CardTitle>
//                 <CardDescription>Latest SSH connections</CardDescription>
//               </CardHeader>
//               <CardContent>
//                 <div className="space-y-2 max-h-64 overflow-y-auto">
//                   {sshConnections.slice(0, 5).map((conn, index) => (
//                     <div key={index} className="p-2 border rounded flex justify-between items-center">
//                       <div>
//                         <div className="font-medium cursor-pointer hover:underline" onClick={() => handleIPClick(conn.src_ip)}>
//                           {conn.src_ip}
//                         </div>
//                         <div className="text-sm text-gray-500">To: {conn.dst_ip}</div>
//                       </div>
//                       <div className="flex items-center space-x-2">
//                         {getThreatLevelBadge(getThreatLevel(conn.src_ip))}
//                         <div className="text-xs text-gray-500">
//                           {new Date(conn.timestamp).toLocaleTimeString()}
//                         </div>
//                       </div>
//                     </div>
//                   ))}
//                 </div>
//               </CardContent>
//             </Card>
//           </div>
          
//           {threatSummary.critical > 0 && (
//             <Alert className="bg-red-50 border-red-200">
//               <ShieldAlert className="h-4 w-4 text-red-600" />
//               <AlertTitle className="text-red-600">Critical SSH Threats Detected</AlertTitle>
//               <AlertDescription>
//                 {threatSummary.critical} critical-level threats detected. These IPs have successfully logged in from untrusted sources and show brute force patterns.
//               </AlertDescription>
//             </Alert>
//           )}
//         </TabsContent>
        
//         <TabsContent value="connections">
//           <Card>
//             <CardHeader>
//               <CardTitle className="flex items-center">
//                 <Network className="mr-2 h-5 w-5" /> SSH Connections
//               </CardTitle>
//               <CardDescription>All detected SSH connection attempts</CardDescription>
//             </CardHeader>
//             <CardContent>
//               <Table>
//                 <thead>
//                   <tr>
//                     <th className="text-left p-2">Source IP</th>
//                     <th className="text-left p-2">Destination IP</th>
//                     <th className="text-left p-2">Timestamp</th>
//                     <th className="text-left p-2">Threat Level</th>
//                     <th className="text-left p-2">Status</th>
//                   </tr>
//                 </thead>
//                 <tbody>
//                   {sshConnections.map((conn, index) => (
//                     <tr key={index} className="border-t">
//                       <td className="p-2">
//                         <span 
//                           className="cursor-pointer hover:underline font-medium"
//                           onClick={() => handleIPClick(conn.src_ip)}
//                         >
//                           {conn.src_ip}
//                         </span>
//                       </td>
//                       <td className="p-2">{conn.dst_ip}</td>
//                       <td className="p-2">{new Date(conn.timestamp).toLocaleString()}</td>
//                       <td className="p-2">{getThreatLevelBadge(getThreatLevel(conn.src_ip))}</td>
//                       <td className="p-2">
//                         {trustedIPs.includes(conn.src_ip) ? (
//                           <Badge className="bg-green-100 text-green-800">Authorized</Badge>
//                         ) : attackDetection.suspicious_ips.includes(conn.src_ip) ? (
//                           <Badge className="bg-red-100 text-red-800">Suspicious Login</Badge>
//                         ) : (
//                           <Badge className="bg-blue-100 text-blue-800">Connection</Badge>
//                         )}
//                       </td>
//                     </tr>
//                   ))}
//                 </tbody>
//               </Table>
//             </CardContent>
//           </Card>
//         </TabsContent>
        
//         <TabsContent value="threats">
//           <Card>
//             <CardHeader>
//               <CardTitle className="flex items-center">
//                 <AlertTriangle className="mr-2 h-5 w-5" /> Detected Threats
//               </CardTitle>
//               <CardDescription>SSH brute force attempts and suspicious logins</CardDescription>
//             </CardHeader>
//             <CardContent>
//               <Table>
//                 <thead>
//                   <tr>
//                     <th className="text-left p-2">IP Address</th>
//                     <th className="text-left p-2">Failed Attempts</th>
//                     <th className="text-left p-2">Successful Login</th>
//                     <th className="text-left p-2">Threat Level</th>
//                     <th className="text-left p-2">Status</th>
//                   </tr>
//                 </thead>
//                 <tbody>
//                   {uniqueIPs.filter(ip => 
//                     attackDetection.brute_force_attempts[ip] > 0 || 
//                     attackDetection.suspicious_ips.includes(ip)
//                   ).sort((a, b) => {
//                     const levelA = getThreatLevel(a);
//                     const levelB = getThreatLevel(b);
//                     const levels = ['Critical', 'High', 'Medium', 'Low', 'None', 'Trusted'];
//                     return levels.indexOf(levelA) - levels.indexOf(levelB);
//                   }).map((ip, index) => (
//                     <tr key={index} className="border-t">
//                       <td className="p-2">
//                         <span 
//                           className="cursor-pointer hover:underline font-medium"
//                           onClick={() => handleIPClick(ip)}
//                         >
//                           {ip}
//                         </span>
//                       </td>
//                       <td className="p-2">{attackDetection.brute_force_attempts[ip] || 0}</td>
//                       <td className="p-2">
//                         {attackDetection.suspicious_ips.includes(ip) ? (
//                           <Check className="text-red-500" />
//                         ) : (
//                           <span>-</span>
//                         )}
//                       </td>
//                       <td className="p-2">{getThreatLevelBadge(getThreatLevel(ip))}</td>
//                       <td className="p-2">
//                         {trustedIPs.includes(ip) ? (
//                           <Badge className="bg-green-100 text-green-800">Trusted IP</Badge>
//                         ) : attackDetection.suspicious_ips.includes(ip) && attackDetection.brute_force_attempts[ip] > 20 ? (
//                           <Badge className="bg-red-100 text-red-800">Lateral Movement</Badge>
//                         ) : attackDetection.suspicious_ips.includes(ip) ? (
//                           <Badge className="bg-red-100 text-red-800">Suspicious Access</Badge>
//                         ) : attackDetection.brute_force_attempts[ip] > 20 ? (
//                           <Badge className="bg-orange-100 text-orange-800">Heavy Brute Force</Badge>
//                         ) : attackDetection.brute_force_attempts[ip] > 0 ? (
//                           <Badge className="bg-yellow-100 text-yellow-800">Brute Force</Badge>
//                         ) : (
//                           <Badge className="bg-gray-100 text-gray-800">Normal</Badge>
//                         )}
//                       </td>
//                     </tr>
//                   ))}
//                 </tbody>
//               </Table>
//             </CardContent>
//           </Card>
//         </TabsContent>
        
//         {selectedIP && (
//           <TabsContent value="ipDetails">
//             <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
//               <Card>
//                 <CardHeader>
//                   <CardTitle className="flex items-center">
//                     <Server className="mr-2 h-5 w-5" /> IP Details: {selectedIP}
//                   </CardTitle>
//                   <CardDescription>
//                     {trustedIPs.includes(selectedIP) ? (
//                       <Badge className="bg-green-100 text-green-800">Trusted IP</Badge>
//                     ) : (
//                       getThreatLevelBadge(getThreatLevel(selectedIP))
//                     )}
//                   </CardDescription>
//                 </CardHeader>
//                 <CardContent>
//                   <div className="space-y-4">
//                     <div>
//                       <h3 className="font-medium">Status Summary</h3>
//                       <div className="mt-2 space-y-2">
//                         <div className="flex justify-between">
//                           <span>Failed Login Attempts:</span>
//                           <span className="font-bold">{attackDetection.brute_force_attempts[selectedIP] || 0}</span>
//                         </div>
//                         <div className="flex justify-between">
//                           <span>Successful Unauthorized Login:</span>
//                           <span className="font-bold">{attackDetection.suspicious_ips.includes(selectedIP) ? 'Yes' : 'No'}</span>
//                         </div>
//                         <div className="flex justify-between">
//                           <span>Trusted IP:</span>
//                           <span className="font-bold">{trustedIPs.includes(selectedIP) ? 'Yes' : 'No'}</span>
//                         </div>
//                         <div className="flex justify-between">
//                           <span>Threat Level:</span>
//                           <span>{getThreatLevelBadge(getThreatLevel(selectedIP))}</span>
//                         </div>
//                       </div>
//                     </div>
                    
//                     {!trustedIPs.includes(selectedIP) && attackDetection.suspicious_ips.includes(selectedIP) && (
//                       <Alert className="bg-red-50 border-red-200">
//                         <ShieldAlert className="h-4 w-4 text-red-600" />
//                         <AlertTitle className="text-red-600">Potential Lateral Movement Detected</AlertTitle>
//                         <AlertDescription>
//                           This IP has successfully logged in despite not being in the trusted IPs list.
//                           {attackDetection.brute_force_attempts[selectedIP] > 10 && 
//                             " It has also performed multiple failed login attempts, suggesting brute force attacks."}
//                         </AlertDescription>
//                       </Alert>
//                     )}
//                   </div>
//                 </CardContent>
//               </Card>
              
//               <Card>
//                 <CardHeader>
//                   <CardTitle>Connection History</CardTitle>
//                   <CardDescription>SSH connections for this IP</CardDescription>
//                 </CardHeader>
//                 <CardContent>
//                   <div className="space-y-2 max-h-64 overflow-y-auto">
//                     {sshConnections
//                       .filter(conn => conn.src_ip === selectedIP)
//                       .map((conn, index) => (
//                         <div key={index} className="p-2 border rounded flex justify-between">
//                           <div>
//                             <div className="font-medium">To: {conn.dst_ip}</div>
//                             <div className="text-sm text-gray-500">
//                               {new Date(conn.timestamp).toLocaleString()}
//                             </div>
//                           </div>
//                           <div>
//                             {attackDetection.suspicious_ips.includes(selectedIP) ? (
//                               <Badge className="bg-red-100 text-red-800">Suspicious</Badge>
//                             ) : (
//                               <Badge className="bg-blue-100 text-blue-800">Connection</Badge>
//                             )}
//                           </div>
//                         </div>
//                       ))}
//                     {sshConnections.filter(conn => conn.src_ip === selectedIP).length === 0 && (
//                       <p className="text-gray-500">No connection history available</p>
//                     )}
//                   </div>
//                 </CardContent>
//               </Card>
//             </div>
            
//             <div className="mt-4">
//               <Card>
//                 <CardHeader>
//                   <CardTitle>Recommended Actions</CardTitle>
//                 </CardHeader>
//                 <CardContent>
//                   <div className="space-y-2">
//                     {trustedIPs.includes(selectedIP) ? (
//                       <Alert className="bg-green-50 border-green-200">
//                         <Check className="h-4 w-4 text-green-600" />
//                         <AlertTitle className="text-green-600">Trusted IP</AlertTitle>
//                         <AlertDescription>
//                           This IP is in the trusted IPs list and is authorized for SSH access.
//                         </AlertDescription>
//                       </Alert>
//                     ) : getThreatLevel(selectedIP) === 'Critical' ? (
//                       <>
//                         <Alert className="bg-red-50 border-red-200">
//                           <ShieldAlert className="h-4 w-4 text-red-600" />
//                           <AlertTitle className="text-red-600">Critical Threat - Immediate Action Required</AlertTitle>
//                           <AlertDescription>
//                             This IP has successfully logged in and shows aggressive brute force patterns. Consider immediate blocking and investigation for potential breach.
//                           </AlertDescription>
//                         </Alert>
//                         <div className="p-2 border rounded">
//                           <h4 className="font-medium">Block this IP with iptables:</h4>
//                           <code className="block bg-gray-100 p-2 mt-1 rounded text-sm">
//                             sudo iptables -A INPUT -s {selectedIP} -j DROP
//                           </code>
//                         </div>
//                       </>
//                     ) : attackDetection.suspicious_ips.includes(selectedIP) ? (
//                       <>
//                         <Alert className="bg-red-50 border-red-200">
//                           <AlertTriangle className="h-4 w-4 text-red-600" />
//                           <AlertTitle className="text-red-600">Suspicious Login - Action Recommended</AlertTitle>
//                           <AlertDescription>
//                             This IP has successfully logged in but is not in the trusted IPs list. Verify if this access is legitimate or block if unauthorized.
//                           </AlertDescription>
//                         </Alert>
//                         <div className="p-2 border rounded">
//                           <h4 className="font-medium">Add to trusted IPs if legitimate:</h4>
//                           <code className="block bg-gray-100 p-2 mt-1 rounded text-sm">
//                             # Add to trusted_ips list in configuration
//                             trusted_ips.append("{selectedIP}")
//                           </code>
//                         </div>
//                       </>
//                     ) : attackDetection.brute_force_attempts[selectedIP] > 10 ? (
//                       <>
//                         <Alert className="bg-orange-50 border-orange-200">
//                           <AlertTriangle className="h-4 w-4 text-orange-600" />
//                           <AlertTitle className="text-orange-600">Brute Force Attempts - Consider Blocking</AlertTitle>
//                           <AlertDescription>
//                             This IP has made multiple failed login attempts ({attackDetection.brute_force_attempts[selectedIP]}), indicating possible brute force attacks.
//                           </AlertDescription>
//                         </Alert>
//                         <div className="p-2 border rounded">
//                           <h4 className="font-medium">Temporarily block with fail2ban:</h4>
//                           <code className="block bg-gray-100 p-2 mt-1 rounded text-sm">
//                             sudo fail2ban-client set sshd banip {selectedIP}
//                           </code>
//                         </div>
//                       </>
//                     ) : (
//                       <Alert className="bg-blue-50 border-blue-200">
//                         <AlertTriangle className="h-4 w-4 text-blue-600" />
//                         <AlertTitle className="text-blue-600">Low Risk - Monitor Activity</AlertTitle>
//                         <AlertDescription>
//                           This IP shows limited suspicious activity. Continue monitoring for any changes in behavior.
//                         </AlertDescription>
//                       </Alert>
//                     )}
//                   </div>
//                 </CardContent>
//               </Card>
//             </div>
//           </TabsContent>
//         )}
//       </Tabs>
//     </div>
//   );
// };





import React, { useState, useEffect } from 'react';
import { Table } from "./ui/table";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Badge } from "./ui/badge";
import { Alert, AlertTitle, AlertDescription } from "./ui/alert";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./ui/tabs";
import { ShieldAlert, AlertTriangle, Check, RefreshCw, Server, Network, Shield } from 'lucide-react';
import axios from 'axios';

interface SSHConnection {
  src_ip: string;
  dst_ip: string;
  timestamp: string;
}

interface BruteForceAttempt {
  [key: string]: number;
}

interface SSHAttackDetection {
  suspicious_ips: string[];
  brute_force_attempts: BruteForceAttempt;
}

export const SSHDashboard: React.FC = () => {
  const [sshConnections, setSSHConnections] = useState<SSHConnection[]>([]);
  const [attackDetection, setAttackDetection] = useState<SSHAttackDetection>({
    suspicious_ips: [],
    brute_force_attempts: {}
  });
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [lastUpdated, setLastUpdated] = useState<string>('');
  const [activeTab, setActiveTab] = useState('overview');
  const [selectedIP, setSelectedIP] = useState<string | null>(null);
  
  const trustedIPs = ["192.168.45.57", "163.70.139.60"];
  
  // Fetch data from backend
  const fetchData = async () => {
    setIsLoading(true);
    try {
      // Fetch SSH connections
      const connectionsResponse = await axios.get('http://localhost:8004/ssh-connections');
      setSSHConnections(connectionsResponse.data.ssh_connections);

      // Fetch SSH attack detection data
      const attacksResponse = await axios.get('http://localhost:8004/detect-ssh-attacks');
      setAttackDetection(attacksResponse.data.ssh_attack_detection);

      // Update last updated time
      setLastUpdated(new Date().toLocaleTimeString());
    } catch (error) {
      console.error('Error fetching data:', error);
    } finally {
      setIsLoading(false);
    }
  };
  
  useEffect(() => {
    fetchData();
    
    // Set up regular refresh interval
    const intervalId = setInterval(fetchData, 5000); // Refresh every 5 seconds
    
    return () => clearInterval(intervalId);
  }, []);
  
  const getBadgeStyle = (ip: string) => {
    if (trustedIPs.includes(ip)) {
      return 'bg-green-100 text-green-800 hover:bg-green-200';
    }
    if (attackDetection.suspicious_ips.includes(ip)) {
      return 'bg-red-100 text-red-800 hover:bg-red-200';
    }
    if (attackDetection.brute_force_attempts[ip]) {
      return 'bg-yellow-100 text-yellow-800 hover:bg-yellow-200';
    }
    return 'bg-blue-100 text-blue-800 hover:bg-blue-200';
  };
  
  const getThreatLevel = (ip: string) => {
    if (trustedIPs.includes(ip)) {
      return 'Trusted';
    }
    
    const bruteForceCount = attackDetection.brute_force_attempts[ip] || 0;
    const isSuspicious = attackDetection.suspicious_ips.includes(ip);
    
    if (isSuspicious && bruteForceCount > 20) {
      return 'Critical';
    } else if (isSuspicious || bruteForceCount > 20) {
      return 'High';
    } else if (bruteForceCount > 5) {
      return 'Medium';
    } else if (bruteForceCount > 0) {
      return 'Low';
    }
    
    return 'None';
  };

  const getThreatLevelBadge = (level: string) => {
    switch (level) {
      case 'Critical':
        return <Badge className="bg-red-600 text-white">Critical</Badge>;
      case 'High':
        return <Badge className="bg-red-500 text-white">High</Badge>;
      case 'Medium':
        return <Badge className="bg-orange-500 text-white">Medium</Badge>;
      case 'Low':
        return <Badge className="bg-yellow-500 text-white">Low</Badge>;
      case 'Trusted':
        return <Badge className="bg-green-500 text-white">Trusted</Badge>;
      default:
        return <Badge className="bg-gray-500 text-white">None</Badge>;
    }
  };
  
  const uniqueIPs = Array.from(new Set([
    ...sshConnections.map(conn => conn.src_ip),
    ...Object.keys(attackDetection.brute_force_attempts)
  ]));
  
  const handleIPClick = (ip: string) => {
    setSelectedIP(ip);
    setActiveTab('ipDetails');
  };
  
  const refreshData = () => {
    fetchData();
  };
  
  const threatSummary = {
    critical: uniqueIPs.filter(ip => getThreatLevel(ip) === 'Critical').length,
    high: uniqueIPs.filter(ip => getThreatLevel(ip) === 'High').length,
    medium: uniqueIPs.filter(ip => getThreatLevel(ip) === 'Medium').length,
    low: uniqueIPs.filter(ip => getThreatLevel(ip) === 'Low').length,
    trusted: uniqueIPs.filter(ip => getThreatLevel(ip) === 'Trusted').length,
  };
  
  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-3xl font-bold flex items-center">
          <Shield className="mr-2" /> SSH Lateral Movement Detection
        </h1>
        <div className="flex items-center space-x-2">
          <span className="text-sm text-gray-500">Last updated: {lastUpdated}</span>
          <button 
            onClick={refreshData}
            className="p-2 rounded-full hover:bg-gray-100"
            disabled={isLoading}
          >
            <RefreshCw className={`h-5 w-5 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>
      
      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="mb-4">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="connections">Connections</TabsTrigger>
          <TabsTrigger value="threats">Threats</TabsTrigger>
          {selectedIP && (
            <TabsTrigger value="ipDetails">IP: {selectedIP}</TabsTrigger>
          )}
        </TabsList>
        
        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-lg">Active Connections</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">{sshConnections.length}</div>
                <p className="text-sm text-gray-500">Total SSH sessions</p>
              </CardContent>
            </Card>
            
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-lg">Suspicious IPs</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">{attackDetection.suspicious_ips.length}</div>
                <p className="text-sm text-gray-500">Unauthorized successful logins</p>
              </CardContent>
            </Card>
            
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-lg">Brute Force Attempts</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">{Object.keys(attackDetection.brute_force_attempts).length}</div>
                <p className="text-sm text-gray-500">IPs with failed password attempts</p>
              </CardContent>
            </Card>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card>
              <CardHeader>
                <CardTitle>Threat Summary</CardTitle>
                <CardDescription>SSH connection threat assessment</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex justify-between items-center">
                    <span className="flex items-center">
                      <Badge className="bg-red-600 text-white mr-2">Critical</Badge>
                      Critical Threats
                    </span>
                    <span className="font-bold">{threatSummary.critical}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="flex items-center">
                      <Badge className="bg-red-500 text-white mr-2">High</Badge>
                      High Risk
                    </span>
                    <span className="font-bold">{threatSummary.high}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="flex items-center">
                      <Badge className="bg-orange-500 text-white mr-2">Medium</Badge>
                      Medium Risk
                    </span>
                    <span className="font-bold">{threatSummary.medium}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="flex items-center">
                      <Badge className="bg-yellow-500 text-white mr-2">Low</Badge>
                      Low Risk
                    </span>
                    <span className="font-bold">{threatSummary.low}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="flex items-center">
                      <Badge className="bg-green-500 text-white mr-2">Trusted</Badge>
                      Trusted IPs
                    </span>
                    <span className="font-bold">{threatSummary.trusted}</span>
                  </div>
                </div>
              </CardContent>
            </Card>
            
            <Card>
              <CardHeader>
                <CardTitle>Recent Activity</CardTitle>
                <CardDescription>Latest SSH connections</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {sshConnections.slice(0, 5).map((conn, index) => (
                    <div key={index} className="p-2 border rounded flex justify-between items-center">
                      <div>
                        <div className="font-medium cursor-pointer hover:underline" onClick={() => handleIPClick(conn.src_ip)}>
                          {conn.src_ip}
                        </div>
                        <div className="text-sm text-gray-500">To: {conn.dst_ip}</div>
                      </div>
                      <div className="flex items-center space-x-2">
                        {getThreatLevelBadge(getThreatLevel(conn.src_ip))}
                        <div className="text-xs text-gray-500">
                          {new Date(conn.timestamp).toLocaleTimeString()}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
          
          {threatSummary.critical > 0 && (
            <Alert className="bg-red-50 border-red-200">
              <ShieldAlert className="h-4 w-4 text-red-600" />
              <AlertTitle className="text-red-600">Critical SSH Threats Detected</AlertTitle>
              <AlertDescription>
                {threatSummary.critical} critical-level threats detected. These IPs have successfully logged in from untrusted sources and show brute force patterns.
              </AlertDescription>
            </Alert>
          )}
        </TabsContent>
        
        <TabsContent value="connections">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <Network className="mr-2 h-5 w-5" /> SSH Connections
              </CardTitle>
              <CardDescription>All detected SSH connection attempts</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <thead>
                  <tr>
                    <th className="text-left p-2">Source IP</th>
                    <th className="text-left p-2">Destination IP</th>
                    <th className="text-left p-2">Timestamp</th>
                    <th className="text-left p-2">Threat Level</th>
                    <th className="text-left p-2">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {sshConnections.map((conn, index) => (
                    <tr key={index} className="border-t">
                      <td className="p-2">
                        <span 
                          className="cursor-pointer hover:underline font-medium"
                          onClick={() => handleIPClick(conn.src_ip)}
                        >
                          {conn.src_ip}
                        </span>
                      </td>
                      <td className="p-2">{conn.dst_ip}</td>
                      <td className="p-2">{new Date(conn.timestamp).toLocaleString()}</td>
                      <td className="p-2">{getThreatLevelBadge(getThreatLevel(conn.src_ip))}</td>
                      <td className="p-2">
                        {trustedIPs.includes(conn.src_ip) ? (
                          <Badge className="bg-green-100 text-green-800">Authorized</Badge>
                        ) : attackDetection.suspicious_ips.includes(conn.src_ip) ? (
                          <Badge className="bg-red-100 text-red-800">Suspicious Login</Badge>
                        ) : (
                          <Badge className="bg-blue-100 text-blue-800">Connection</Badge>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
        
        <TabsContent value="threats">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <AlertTriangle className="mr-2 h-5 w-5" /> Detected Threats
              </CardTitle>
              <CardDescription>SSH brute force attempts and suspicious logins</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <thead>
                  <tr>
                    <th className="text-left p-2">IP Address</th>
                    <th className="text-left p-2">Failed Attempts</th>
                    <th className="text-left p-2">Successful Login</th>
                    <th className="text-left p-2">Threat Level</th>
                    <th className="text-left p-2">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {uniqueIPs.filter(ip => 
                    attackDetection.brute_force_attempts[ip] > 0 || 
                    attackDetection.suspicious_ips.includes(ip)
                  ).sort((a, b) => {
                    const levelA = getThreatLevel(a);
                    const levelB = getThreatLevel(b);
                    const levels = ['Critical', 'High', 'Medium', 'Low', 'None', 'Trusted'];
                    return levels.indexOf(levelA) - levels.indexOf(levelB);
                  }).map((ip, index) => (
                    <tr key={index} className="border-t">
                      <td className="p-2">
                        <span 
                          className="cursor-pointer hover:underline font-medium"
                          onClick={() => handleIPClick(ip)}
                        >
                          {ip}
                        </span>
                      </td>
                      <td className="p-2">{attackDetection.brute_force_attempts[ip] || 0}</td>
                      <td className="p-2">
                        {attackDetection.suspicious_ips.includes(ip) ? (
                          <Check className="text-red-500" />
                        ) : (
                          <span>-</span>
                        )}
                      </td>
                      <td className="p-2">{getThreatLevelBadge(getThreatLevel(ip))}</td>
                      <td className="p-2">
                        {trustedIPs.includes(ip) ? (
                          <Badge className="bg-green-100 text-green-800">Trusted IP</Badge>
                        ) : attackDetection.suspicious_ips.includes(ip) && attackDetection.brute_force_attempts[ip] > 20 ? (
                          <Badge className="bg-red-100 text-red-800">Lateral Movement</Badge>
                        ) : attackDetection.suspicious_ips.includes(ip) ? (
                          <Badge className="bg-red-100 text-red-800">Suspicious Access</Badge>
                        ) : attackDetection.brute_force_attempts[ip] > 20 ? (
                          <Badge className="bg-orange-100 text-orange-800">Heavy Brute Force</Badge>
                        ) : attackDetection.brute_force_attempts[ip] > 0 ? (
                          <Badge className="bg-yellow-100 text-yellow-800">Brute Force</Badge>
                        ) : (
                          <Badge className="bg-gray-100 text-gray-800">Normal</Badge>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
        
        {selectedIP && (
          <TabsContent value="ipDetails">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Server className="mr-2 h-5 w-5" /> IP Details: {selectedIP}
                  </CardTitle>
                  <CardDescription>
                    {trustedIPs.includes(selectedIP) ? (
                      <Badge className="bg-green-100 text-green-800">Trusted IP</Badge>
                    ) : (
                      getThreatLevelBadge(getThreatLevel(selectedIP))
                    )}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div>
                      <h3 className="font-medium">Status Summary</h3>
                      <div className="mt-2 space-y-2">
                        <div className="flex justify-between">
                          <span>Failed Login Attempts:</span>
                          <span className="font-bold">{attackDetection.brute_force_attempts[selectedIP] || 0}</span>
                        </div>
                        <div className="flex justify-between">
                          <span>Successful Unauthorized Login:</span>
                          <span className="font-bold">{attackDetection.suspicious_ips.includes(selectedIP) ? 'Yes' : 'No'}</span>
                        </div>
                        <div className="flex justify-between">
                          <span>Trusted IP:</span>
                          <span className="font-bold">{trustedIPs.includes(selectedIP) ? 'Yes' : 'No'}</span>
                        </div>
                        <div className="flex justify-between">
                          <span>Threat Level:</span>
                          <span>{getThreatLevelBadge(getThreatLevel(selectedIP))}</span>
                        </div>
                      </div>
                    </div>
                    
                    {!trustedIPs.includes(selectedIP) && attackDetection.suspicious_ips.includes(selectedIP) && (
                      <Alert className="bg-red-50 border-red-200">
                        <ShieldAlert className="h-4 w-4 text-red-600" />
                        <AlertTitle className="text-red-600">Potential Lateral Movement Detected</AlertTitle>
                        <AlertDescription>
                          This IP has successfully logged in despite not being in the trusted IPs list.
                          {attackDetection.brute_force_attempts[selectedIP] > 10 && 
                            " It has also performed multiple failed login attempts, suggesting brute force attacks."}
                        </AlertDescription>
                      </Alert>
                    )}
                  </div>
                </CardContent>
              </Card>
              
              <Card>
                <CardHeader>
                  <CardTitle>Connection History</CardTitle>
                  <CardDescription>SSH connections for this IP</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {sshConnections
                      .filter(conn => conn.src_ip === selectedIP)
                      .map((conn, index) => (
                        <div key={index} className="p-2 border rounded flex justify-between">
                          <div>
                            <div className="font-medium">To: {conn.dst_ip}</div>
                            <div className="text-sm text-gray-500">
                              {new Date(conn.timestamp).toLocaleString()}
                            </div>
                          </div>
                          <div>
                            {attackDetection.suspicious_ips.includes(selectedIP) ? (
                              <Badge className="bg-red-100 text-red-800">Suspicious</Badge>
                            ) : (
                              <Badge className="bg-blue-100 text-blue-800">Connection</Badge>
                            )}
                          </div>
                        </div>
                      ))}
                    {sshConnections.filter(conn => conn.src_ip === selectedIP).length === 0 && (
                      <p className="text-gray-500">No connection history available</p>
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>
            
            <div className="mt-4">
              <Card>
                <CardHeader>
                  <CardTitle>Recommended Actions</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {trustedIPs.includes(selectedIP) ? (
                      <Alert className="bg-green-50 border-green-200">
                        <Check className="h-4 w-4 text-green-600" />
                        <AlertTitle className="text-green-600">Trusted IP</AlertTitle>
                        <AlertDescription>
                          This IP is in the trusted IPs list and is authorized for SSH access.
                        </AlertDescription>
                      </Alert>
                    ) : getThreatLevel(selectedIP) === 'Critical' ? (
                      <>
                        <Alert className="bg-red-50 border-red-200">
                          <ShieldAlert className="h-4 w-4 text-red-600" />
                          <AlertTitle className="text-red-600">Critical Threat - Immediate Action Required</AlertTitle>
                          <AlertDescription>
                            This IP has successfully logged in and shows aggressive brute force patterns. Consider immediate blocking and investigation for potential breach.
                          </AlertDescription>
                        </Alert>
                        <div className="p-2 border rounded">
                          <h4 className="font-medium">Block this IP with iptables:</h4>
                          <code className="block bg-gray-100 p-2 mt-1 rounded text-sm">
                            sudo iptables -A INPUT -s {selectedIP} -j DROP
                          </code>
                        </div>
                      </>
                    ) : attackDetection.suspicious_ips.includes(selectedIP) ? (
                      <>
                        <Alert className="bg-red-50 border-red-200">
                          <AlertTriangle className="h-4 w-4 text-red-600" />
                          <AlertTitle className="text-red-600">Suspicious Login - Action Recommended</AlertTitle>
                          <AlertDescription>
                            This IP has successfully logged in but is not in the trusted IPs list. Verify if this access is legitimate or block if unauthorized.
                          </AlertDescription>
                        </Alert>
                        <div className="p-2 border rounded">
                          <h4 className="font-medium">Add to trusted IPs if legitimate:</h4>
                          <code className="block bg-gray-100 p-2 mt-1 rounded text-sm">
                            # Add to trusted_ips list in configuration
                            trusted_ips.append("{selectedIP}")
                          </code>
                        </div>
                      </>
                    ) : attackDetection.brute_force_attempts[selectedIP] > 10 ? (
                      <>
                        <Alert className="bg-orange-50 border-orange-200">
                          <AlertTriangle className="h-4 w-4 text-orange-600" />
                          <AlertTitle className="text-orange-600">Brute Force Attempts - Consider Blocking</AlertTitle>
                          <AlertDescription>
                            This IP has made multiple failed login attempts ({attackDetection.brute_force_attempts[selectedIP]}), indicating possible brute force attacks.
                          </AlertDescription>
                        </Alert>
                        <div className="p-2 border rounded">
                          <h4 className="font-medium">Temporarily block with fail2ban:</h4>
                          <code className="block bg-gray-100 p-2 mt-1 rounded text-sm">
                            sudo fail2ban-client set sshd banip {selectedIP}
                          </code>
                        </div>
                      </>
                    ) : (
                      <Alert className="bg-blue-50 border-blue-200">
                        <AlertTriangle className="h-4 w-4 text-blue-600" />
                        <AlertTitle className="text-blue-600">Low Risk - Monitor Activity</AlertTitle>
                        <AlertDescription>
                          This IP shows limited suspicious activity. Continue monitoring for any changes in behavior.
                        </AlertDescription>
                      </Alert>
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        )}
      </Tabs>
    </div>
  );
};