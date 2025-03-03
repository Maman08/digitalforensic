// import React, { useState } from 'react';
// import { Bell, Play, Cpu, Globe, Terminal, FileDigit } from 'lucide-react';
// import { Tree, TreeNode } from 'react-organizational-chart';
// import { Bar } from 'react-chartjs-2';
// import { Chart, registerables } from 'chart.js';
// import axios from 'axios';

// Chart.register(...registerables);

// // Define types for our data
// interface ProcessItem {
//   "OFFSET (V)": string;
//   PID: string;
//   TID: string;
//   PPID: string;
//   COMM: string;
// }

// interface IdtItem {
//   Index: string;
//   Address: string;
//   Module: string;
//   Symbol: string;
// }

// interface PsScanItem {
//   "OFFSET (P)": string;
//   PID: string;
//   TID: string;
//   PPID: string;
//   COMM: string;
//   EXIT_STATE: string;
// }

// interface CommandOption {
//   value: string;
//   label: string;
//   icon: React.ReactNode;
// }

// type ResultTypes = {
//   pslist: ProcessItem[];
//   pstree: ProcessItem[];
//   idtcheck: IdtItem[];
//   psscan: PsScanItem[];
// };

// export const MemoryForensic: React.FC = () => {
//   const [selectedCommand, setSelectedCommand] = useState<string>('pslist');
//   const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
//   const [results, setResults] = useState<ProcessItem[] | IdtItem[] | PsScanItem[] | null>(null);
//   const [modelResults, setModelResults] = useState<ProcessItem[] | IdtItem[] | PsScanItem[] | null>(null);

//   const volatilityCommands: CommandOption[] = [
//     { value: 'pslist', label: 'Process List', icon: <Cpu size={16} /> },
//     { value: 'pstree', label: 'Process Tree', icon: <Globe size={16} /> },
//     { value: 'idtcheck', label: 'Interrupt Descriptor Table', icon: <FileDigit size={16} /> },
//     { value: 'psscan', label: 'Process Scan', icon: <FileDigit size={16} /> },
//   ];

//   const handleCommandChange = (e: React.ChangeEvent<HTMLSelectElement>): void => {
//     setSelectedCommand(e.target.value);
//   };

//   const handleAnalyze = async (): Promise<void> => {
//     setIsAnalyzing(true);
//     setResults(null);

//     try {
//       const response = await axios.get(`http://localhost:8003/analyze/${selectedCommand}`);
//       const analyzedata=response.data.data;
//       const predictData = analyzedata.map((item: any) => ({
//         "OFFSET (V)": item["OFFSET (V)"],
//         PID: item.PID,
//         TID: item.TID,
//         PPID: item.PPID,
//         COMM: item.COMM,
//         UID: item.UID,
//         GID: item.GID,
//         EUID: item.EUID,
//         EGID: item.EGID,
//         "CREATION TIME": item["CREATION TIME"],
//         "File output": item["File output"],
//       }));
//       const predictResponse = await axios.post('http://127.0.0.1:5000/predict', predictData);

//       setModelResults(predictResponse.data);
//       console.log(predictResponse.data);
//       // console.log(response.data.data)
//       setResults(response.data.data);
//     } catch (error) {
//       console.error('Error analyzing memory dump:', error);
//     } finally {
//       setIsAnalyzing(false);
//     }
//   };

//   const renderResults = (): React.ReactNode => {
//     if (!results) return null;

//     switch (selectedCommand) {
//       case 'pslist':
//         return <RenderPsList data={results as ProcessItem[]} />;
//       case 'pstree':
//         return <RenderPsTree data={results as ProcessItem[]} />;
//       case 'idtcheck':
//         return <RenderCheckIdt data={results as IdtItem[]} />;
//       case 'psscan':
//         return <RenderPsScan data={results as PsScanItem[]} />;
//       default:
//         return <p>No renderer available for this command.</p>;
//     }
//   };

//   return (
//     <div className="flex flex-col min-h-screen bg-black-900 p-6">
//       {/* Header */}
//       <header className="bg-black-800 shadow-lg">
//         <div className="container mx-auto px-4 py-4">
//           <div className="flex items-center justify-between">
//             <div className="flex items-center">
//               <Bell className="text-blue-400 mr-2" size={24} />
//               <h1 className="text-2xl font-bold">Volatility Forensics Analyzer</h1>
//             </div>
//           </div>
//         </div>
//       </header>

//       {/* Main Content */}
//       <main className="container mx-auto px-4 py-8 flex-grow">
//         <div className="max-w-4xl mx-auto">
//           <div className="bg-gray-800 rounded-lg shadow-lg p-6 mb-6">
//             <h2 className="text-xl font-semibold mb-4">Memory Analysis Tool</h2>
//             <p className="mb-6 text-black-300">
//               Analyze memory dumps using Volatility to extract forensic artifacts. Select a command below to begin your investigation.
//             </p>

//             <div className="flex flex-col sm:flex-row gap-4">
//               <div className="relative w-full sm:w-64">
//                 <select
//                   className="w-full bg-black-700 border border-black-600 rounded-lg px-4 py-2 appearance-none focus:outline-none focus:ring-2 focus:ring-blue-500 cursor-pointer"
//                   value={selectedCommand}
//                   onChange={handleCommandChange}
//                 >
//                   {volatilityCommands.map(cmd => (
//                     <option key={cmd.value} value={cmd.value}>
//                       {cmd.label}
//                     </option>
//                   ))}
//                 </select>
//                 <div className="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none">
//                   <svg className="w-5 h-5 text-black-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
//                     <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7"></path>
//                   </svg>
//                 </div>
//               </div>

//               <button
//                 className="px-6 py-2 bg-cyan-500/10 text-cyan-400 rounded-lg transition-all duration-300 btn-glow flex items-center space-x-2 hover:bg-cyan-500/20 disabled:opacity-50 disabled:cursor-not-allowed"
//                 onClick={handleAnalyze}
//                 disabled={isAnalyzing}
//               >
//                 {isAnalyzing ? (
//                   <>
//                     <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
//                       <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
//                       <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
//                     </svg>
//                     Analyzing...
//                   </>
//                 ) : (
//                   <>
//                     <Play size={16} className="mr-2" />
//                     Run Analysis
//                   </>
//                 )}
//               </button>
//             </div>
//           </div>

//           {/* Results Section */}
//           {isAnalyzing ? (
//             <div className="flex flex-col items-center justify-center py-12">
//               <div className="w-16 h-16 border-t-4 border-b-4 border-blue-500 rounded-full animate-spin"></div>
//               <p className="mt-4 text-lg font-medium">Processing memory dump...</p>
//             </div>
//           ) : results ? (
//             <div className="bg-gray-800 rounded-lg shadow-lg p-6">
//               <h3 className="text-lg font-semibold mb-4">Analysis Results</h3>
//               {renderResults()}
//             </div>
//           ) : null}
//         </div>
//       </main>
//     </div>
//   );
// };

// // Component to render pslist results
// const RenderPsList = ({ data }: { data: ProcessItem[] }) => {
//   return (
//     <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
//       {data.map((process, index) => (
//         <div key={index} className="bg-cyan-500/10 p-4 rounded-lg shadow-md">
//           <h4 className="font-semibold">{process.COMM}</h4>
//           <p>PID: {process.PID}</p>
//           <p>PPID: {process.PPID}</p>
//           <p>Offset: {process['OFFSET (V)']}</p>
//         </div>
//       ))}
//     </div>
//   );
// };

// // Component to render pstree results

// const RenderPsTree = ({ data }: { data: ProcessItem[] }) => {
//     const [expandedNodes, setExpandedNodes] = useState<Set<string>>(new Set());
  
//     const toggleNode = (pid: string) => {
//       const newExpandedNodes = new Set(expandedNodes);
//       if (newExpandedNodes.has(pid)) {
//         newExpandedNodes.delete(pid);
//       } else {
//         newExpandedNodes.add(pid);
//       }
//       setExpandedNodes(newExpandedNodes);
//     };
  
//     const buildTree = (processes: ProcessItem[], ppid: string = "0") => {
//       return processes
//         .filter((process) => process.PPID === ppid)
//         .map((process) => (
//           <div key={process.PID}>
//             <div
//               className="bg-cyan-300/10  p-2 rounded mb-2 cursor-pointer"
//               onClick={() => toggleNode(process.PID)}
//             >
//               <h4 className="font-semibold">{process.COMM}</h4>
//               <p>PID: {process.PID}</p>
//               <p>Offset: {process['OFFSET (V)']}</p>
//             </div>
//             {expandedNodes.has(process.PID) && (
//               <div className="pl-5 bg-black-500/10 ">
//                 {buildTree(processes, process.PID)}
//               </div>
//             )}
//           </div>
//         ));
//     };
  
//     return (
//       <div className="bg-black-700 p-4 rounded-lg shadow-md">
//         <h3 className="text-lg font-semibold mb-4">Process Tree</h3>
//         {buildTree(data)}
//       </div>
//     );
//   };
// // Component to render idtcheck results
// const RenderCheckIdt = ({ data }: { data: IdtItem[] }) => {
//   return (
//     <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
//       {data.map((entry, index) => (
//         <div key={index} className=" bg-cyan-500/10 text-white-400 rounded-lg p-4 rounded-lg shadow-md">
//           <h4 className="font-semibold">{entry.Symbol}</h4>
//           <p>Index: {entry.Index}</p>
//           <p>Address: {entry.Address}</p>
//           <p>Module: {entry.Module}</p>
//         </div>
//       ))}
//     </div>
//   );
// };

// // Component to render psscan results
// const RenderPsScan = ({ data }: { data: PsScanItem[] }) => {
//   const chartData = {
//     labels: data.map((process) => process.COMM),
//     datasets: [
//       {
//         label: 'Process Count',
//         data: data.map(() => 1), // Each process counts as 1
//         backgroundColor: 'rgba(75, 192, 192, 0.6)',
//       },
//     ],
//   };

//   return (
//     <div>
//       <div className="mb-6">
//         <Bar data={chartData} />
//       </div>
//       <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
//         {data.map((process, index) => (
//           <div key={index} className="bg-black-700 p-4 rounded-lg shadow-md">
//             <h4 className="font-semibold">{process.COMM}</h4>
//             <p>PID: {process.PID}</p>
//             <p>PPID: {process.PPID}</p>
//             <p>Offset: {process['OFFSET (P)']}</p>
//             <p>Exit State: {process.EXIT_STATE}</p>
//           </div>
//         ))}
//       </div>
//     </div>
//   );
// };





import React, { useState } from 'react';
import { Bell, Play, Cpu, Globe, Terminal, FileDigit, Bold } from 'lucide-react';
import { Tree, TreeNode } from 'react-organizational-chart';
import { Bar } from 'react-chartjs-2';
import { Chart, registerables } from 'chart.js';
import axios from 'axios';

Chart.register(...registerables);

// Define types for our data
interface ProcessItem {
  "OFFSET (V)": string;
  PID: string;
  TID: string;
  PPID: string;
  COMM: string;
  UID?: string;
  GID?: string;
  EUID?: string;
  EGID?: string;
  "CREATION TIME"?: string;
  "File output"?: string;
  is_vulnerable?: number; // Added for vulnerability check
}

interface IdtItem {
  Index: string;
  Address: string;
  Module: string;
  Symbol: string;
}

interface PsScanItem {
  "OFFSET (P)": string;
  PID: string;
  TID: string;
  PPID: string;
  COMM: string;
  EXIT_STATE: string;
}

interface CommandOption {
  value: string;
  label: string;
  icon: React.ReactNode;
}

type ResultTypes = {
  pslist: ProcessItem[];
  pstree: ProcessItem[];
  idtcheck: IdtItem[];
  psscan: PsScanItem[];
};

export const MemoryForensic: React.FC = () => {
  const [selectedCommand, setSelectedCommand] = useState<string>('pslist');
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [results, setResults] = useState<ProcessItem[] | IdtItem[] | PsScanItem[] | null>(null);
  const [modelResults, setModelResults] = useState<any[] | null>(null);
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);
  const [modalMessage, setModalMessage] = useState<string>('');
  const [yaraMatches, setYaraMatches] = useState<string[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const volatilityCommands: CommandOption[] = [
    { value: 'pslist', label: 'Process List', icon: <Cpu size={16} /> },
    { value: 'pstree', label: 'Process Tree', icon: <Globe size={16} /> },
    { value: 'idtcheck', label: 'Interrupt Descriptor Table', icon: <FileDigit size={16} /> },
    { value: 'psscan', label: 'Process Scan', icon: <FileDigit size={16} /> },
  ];

  const handleCommandChange = (e: React.ChangeEvent<HTMLSelectElement>): void => {
    setSelectedCommand(e.target.value);
  };

  const handleAnalyze = async (): Promise<void> => {
    setIsAnalyzing(true);
    setResults(null);
    setModelResults(null);

    try {
      const response = await axios.get(`http://localhost:8004/analyze/${selectedCommand}`);
      const analyzedata = response.data.data;

      // Transform the data for the predict API
      const predictData = analyzedata.map((item: any) => ({
        "OFFSET (V)": item["OFFSET (V)"],
        PID: item.PID,
        TID: item.TID,
        PPID: item.PPID,
        COMM: item.COMM,
        UID: item.UID,
        GID: item.GID,
        EUID: item.EUID,
        EGID: item.EGID,
        "CREATION TIME": item["CREATION TIME"],
        "File output": item["File output"],
      }));

      // Call the predict API
      const predictResponse = await axios.post('http://127.0.0.1:5000/predict', predictData);
      const predictions = predictResponse.data.predictions || [];

      // Set the results
      setModelResults(predictions); // Store the model results
      setResults(response.data.data); // Store the raw analysis results
    } catch (error) {
      console.error('Error analyzing memory dump:', error);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleCheckVulnerability = (): void => {
    if (!modelResults) {
      setModalMessage("No analysis results available. Please run the analysis first.");
      setIsModalOpen(true);
      return;
    }

    // Check if any entry has a vulnerability (e.g., `is_vulnerable === 1`)
    const hasVulnerability = modelResults.some((item: any) => item.is_vulnerable === 1);

    // Display the result in a popup
    if (hasVulnerability) {
      setModalMessage("Vulnerability detected! Please review the results.");
    } else {
      setModalMessage("No vulnerabilities found.");
    }
    setIsModalOpen(true);
  };



  const handleScan = async () => {
    setLoading(true);
    setError(null);

    try {
      // Send a POST request to the FastAPI backend
      const response = await axios.post("http://localhost:8004/yarascan/");
      setYaraMatches(response.data.yara_matches);
    } catch (err) {
      setError("Failed to run YARA scan. Please try again.");
      console.error(err);
    } finally {
      setLoading(false);
    }
  };







  const renderResults = (): React.ReactNode => {
    if (!results) return null;

    switch (selectedCommand) {
      case 'pslist':
        return <RenderPsList data={results as ProcessItem[]} />;
      case 'pstree':
        return <RenderPsTree data={results as ProcessItem[]} />;
      case 'idtcheck':
        return <RenderCheckIdt data={results as IdtItem[]} />;
      case 'psscan':
        return <RenderPsScan data={results as PsScanItem[]} />;
      default:
        return <p>No renderer available for this command.</p>;
    }
  };

  return (
    <div className="flex flex-col min-h-screen bg-black-900 p-6">
      {/* Header */}
      <header className="bg-black-800 shadow-lg">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <Bell className="text-blue-400 mr-2" size={24} />
              <h1 className="text-2xl font-bold">Volatility Forensics Analyzer</h1>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-8 flex-grow">
        <div className="max-w-4xl mx-auto">
          <div className="bg-gray-800 rounded-lg shadow-lg p-6 mb-6">
            <h2 className="text-xl font-semibold mb-4">Memory Analysis Tool</h2>
            <p className="mb-6 text-black-300">
              Analyze memory dumps using Volatility to extract forensic artifacts. Select a command below to begin your investigation.
            </p>

            <div className="flex flex-col sm:flex-row gap-4">
              <div className="relative w-full sm:w-64">
                <select
                  className="w-full bg-black-700 border border-black-600 rounded-lg px-4 py-2 appearance-none focus:outline-none focus:ring-2 focus:ring-blue-500 cursor-pointer"
                  value={selectedCommand}
                  onChange={handleCommandChange}
                >
                  {volatilityCommands.map(cmd => (
                    <option key={cmd.value} value={cmd.value}>
                      {cmd.label}
                    </option>
                  ))}
                </select>
                <div className="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none">
                  <svg className="w-5 h-5 text-black-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7"></path>
                  </svg>
                </div>
              </div>

              <button
                className="px-6 py-2 bg-cyan-500/10 text-cyan-400 rounded-lg transition-all duration-300 btn-glow flex items-center space-x-2 hover:bg-cyan-500/20 disabled:opacity-50 disabled:cursor-not-allowed"
                onClick={handleAnalyze}
                disabled={isAnalyzing}
              >
                {isAnalyzing ? (
                  <>
                    <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Play size={16} className="mr-2" />
                    Run Analysis
                  </>
                )}
              </button>
            </div>
          </div>
          <div style={{ padding: "20px", fontFamily: "Arial, sans-serif" }} className='bg-cyan-500/10'>
      <h1 className='text-xl font-semibold mb-5" '>YARA Scan Tool</h1>
      <button
        onClick={handleScan}
        disabled={loading}
        className='bg-cyan-200/10'
        style={{
          padding: "10px 20px",
          fontSize: "16px",
          color: "#fff",
          border: "none",
          borderRadius: "5px",
          cursor: "pointer",
        }}
        
      >
        {loading ? "Scanning..." : "Start YARA Scan"}
      </button>

      {error && (
        <p style={{ color: "red", marginTop: "10px" }}>{error}</p>
      )}

      {yaraMatches.length > 0 && (
        <div style={{ marginTop: "20px" }} className='bg-dark-500/10'>
          <ul style={{ listStyleType: "none", padding: "0" }}>
            {yaraMatches.map((match, index) => (
              <li
                key={index}
                style={{
                  padding: "10px",
                  border: "1px solid #ddd",
                  marginBottom: "5px",
                  borderRadius: "5px",
                  
                }}
                className=' bg-dark-500/10 '
              >
                {match}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>


          {/* Results Section */}
          {isAnalyzing ? (
            <div className="flex flex-col items-center justify-center py-12">
              <div className="w-16 h-16 border-t-4 border-b-4 border-blue-500 rounded-full animate-spin"></div>
              <p className="mt-4 text-lg font-medium">Processing memory dump...</p>
            </div>
          ) : results ? (
            <div className="bg-gray-800 rounded-lg shadow-lg p-6">
              <h3 className="text-lg font-semibold mb-4">Analysis Results</h3>
              {renderResults()}

              {/* Check Vulnerability Button */}
              {modelResults && (
                <button
                  className="px-6 py-2 bg-red-500/10 text-red-400 rounded-lg transition-all duration-300 btn-glow flex items-center space-x-2 hover:bg-red-500/20 mt-4"
                  onClick={handleCheckVulnerability}
                >
                  Check Vulnerability
                </button>
              )}
            </div>
          ) : null}
        </div>
      </main>

      {/* Vulnerability Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center">
          <div className="bg-gray-800 rounded-lg p-6 max-w-md">
            <h2 className="text-xl font-semibold mb-4">Vulnerability Check</h2>
            <p>{modalMessage}</p>
            <button
              className="mt-4 px-4 py-2 bg-cyan-500/10 text-cyan-400 rounded-lg hover:bg-cyan-500/20"
              onClick={() => setIsModalOpen(false)}
            >
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

// Component to render pslist results
const RenderPsList = ({ data }: { data: ProcessItem[] }) => {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
      {data.map((process, index) => (
        <div key={index} className="bg-cyan-500/10 p-4 rounded-lg shadow-md">
          <h4 className="font-semibold">{process.COMM}</h4>
          <p>PID: {process.PID}</p>
          <p>PPID: {process.PPID}</p>
          <p>Offset: {process['OFFSET (V)']}</p>
          {process.is_vulnerable !== undefined && (
            <p>Vulnerable: {process.is_vulnerable === 1 ? 'Yes' : 'No'}</p>
          )}
        </div>
      ))}
    </div>
  );
};

// Component to render pstree results
const RenderPsTree = ({ data }: { data: ProcessItem[] }) => {
  const [expandedNodes, setExpandedNodes] = useState<Set<string>>(new Set());

  const toggleNode = (pid: string) => {
    const newExpandedNodes = new Set(expandedNodes);
    if (newExpandedNodes.has(pid)) {
      newExpandedNodes.delete(pid);
    } else {
      newExpandedNodes.add(pid);
    }
    setExpandedNodes(newExpandedNodes);
  };

  const buildTree = (processes: ProcessItem[], ppid: string = "0") => {
    return processes
      .filter((process) => process.PPID === ppid)
      .map((process) => (
        <div key={process.PID}>
          <div
            className="bg-cyan-300/10 p-2 rounded mb-2 cursor-pointer"
            onClick={() => toggleNode(process.PID)}
          >
            <h4 className="font-semibold">{process.COMM}</h4>
            <p>PID: {process.PID}</p>
            <p>Offset: {process['OFFSET (V)']}</p>
          </div>
          {expandedNodes.has(process.PID) && (
            <div className="pl-5 bg-black-500/10">
              {buildTree(processes, process.PID)}
            </div>
          )}
        </div>
      ));
  };

  return (
    <div className="bg-black-700 p-4 rounded-lg shadow-md">
      <h3 className="text-lg font-semibold mb-4">Process Tree</h3>
      {buildTree(data)}
    </div>
  );
};

// Component to render idtcheck results
const RenderCheckIdt = ({ data }: { data: IdtItem[] }) => {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
      {data.map((entry, index) => (
        <div key={index} className="bg-cyan-500/10 text-white-400 rounded-lg p-4 rounded-lg shadow-md">
          <h4 className="font-semibold">{entry.Symbol}</h4>
          <p>Index: {entry.Index}</p>
          <p>Address: {entry.Address}</p>
          <p>Module: {entry.Module}</p>
        </div>
      ))}
    </div>
  );
};

// Component to render psscan results
const RenderPsScan = ({ data }: { data: PsScanItem[] }) => {
  const chartData = {
    labels: data.map((process) => process.COMM),
    datasets: [
      {
        label: 'Process Count',
        data: data.map(() => 1), // Each process counts as 1
        backgroundColor: 'rgba(75, 192, 192, 0.6)',
      },
    ],
  };

  return (
    <div>
      <div className="mb-6">
        <Bar data={chartData} />
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {data.map((process, index) => (
          <div key={index} className="bg-black-700 p-4 rounded-lg shadow-md">
            <h4 className="font-semibold">{process.COMM}</h4>
            <p>PID: {process.PID}</p>
            <p>PPID: {process.PPID}</p>
            <p>Offset: {process['OFFSET (P)']}</p>
            <p>Exit State: {process.EXIT_STATE}</p>
          </div>
        ))}
      </div>
    </div>
  );
};