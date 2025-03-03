// import React, { useState, useRef, useEffect } from 'react';
// import { Terminal as TerminalIcon, Maximize2, Minus, X } from 'lucide-react';

// export function Terminal() {
//   const [commands, setCommands] = useState<{ input: string; output: string }[]>([]);
//   const [currentInput, setCurrentInput] = useState('');
//   const [minimized, setMinimized] = useState(false);
//   const [maximized, setMaximized] = useState(false);
//   const terminalRef = useRef<HTMLDivElement>(null);
//   const inputRef = useRef<HTMLInputElement>(null);

//   useEffect(() => {
//     if (terminalRef.current) {
//       terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
//     }
//   }, [commands]);

//   const handleCommand = (input: string) => {
//     const newCommand = { input, output: '' };

//     // Mock command processing
//     switch (input.toLowerCase()) {
//       case 'help':
//         newCommand.output = `Available commands:
//   help     - Show this help message
//   clear    - Clear terminal
//   scan     - Run security scan
//   status   - Show system status
//   version  - Show version info`;
//         break;
//       case 'clear':
//         setCommands([]);
//         return;
//       case 'scan':
//         newCommand.output = 'Initiating security scan...\nScanning network endpoints...\nScan complete. No vulnerabilities found.';
//         break;
//       case 'status':
//         newCommand.output = 'System Status:\n✓ Network: Online\n✓ Security: Active\n✓ Monitoring: Running';
//         break;
//       case 'version':
//         newCommand.output = 'NetGuardian Pro v1.0.0\nBuild: 2025.1.1';
//         break;
//       default:
//         newCommand.output = `Command not found: ${input}\nType 'help' for available commands.`;
//     }

//     setCommands([...commands, newCommand]);
//   };

//   const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
//     if (e.key === 'Enter' && currentInput.trim()) {
//       handleCommand(currentInput.trim());
//       setCurrentInput('');
//     }
//   };

//   const handleClick = () => {
//     inputRef.current?.focus();
//   };

//   return (
//     <div 
//       className={`fixed bottom-8 right-8 z-50 transition-all duration-300 ease-in-out
//         ${minimized ? 'h-12 w-64' : maximized ? 'inset-8 h-auto w-auto' : 'h-96 w-[32rem]'}
//         ${minimized ? 'overflow-hidden' : 'overflow-auto'}`}
//     >
//       <div className="bg-black/90 backdrop-blur-xl rounded-lg h-full flex flex-col border border-gray-800/50 shadow-2xl">
//         {/* Terminal Header */}
//         <div className="flex items-center justify-between px-4 py-2 bg-gray-900/50 border-b border-gray-800/50 rounded-t-lg">
//           <div className="flex items-center space-x-2">
//             <TerminalIcon className="w-4 h-4 text-gray-400" />
//             <span className="text-sm text-gray-400">Terminal</span>
//           </div>
//           <div className="flex items-center space-x-2">
//             <button 
//               onClick={() => setMinimized(!minimized)}
//               className="p-1 hover:bg-gray-700/50 rounded-full transition-colors"
//             >
//               <Minus className="w-4 h-4 text-gray-400" />
//             </button>
//             <button 
//               onClick={() => setMaximized(!maximized)}
//               className="p-1 hover:bg-gray-700/50 rounded-full transition-colors"
//             >
//               <Maximize2 className="w-4 h-4 text-gray-400" />
//             </button>
//             <button 
//               onClick={() => setMinimized(true)}
//               className="p-1 hover:bg-gray-700/50 rounded-full transition-colors"
//             >
//               <X className="w-4 h-4 text-gray-400" />
//             </button>
//           </div>
//         </div>

//         {/* Terminal Content */}
//         {!minimized && (
//           <div 
//             ref={terminalRef}
//             className="flex-1 p-4 font-mono text-sm overflow-auto"
//             onClick={handleClick}
//           >
//             {/* Welcome Message */}
//             <div className="text-gray-400 mb-4">
//               Welcome to NetGuardian Terminal
//               <br />
//               Type 'help' for available commands.
//             </div>

//             {/* Command History */}
//             {commands.map((cmd, index) => (
//               <div key={index} className="mb-4">
//                 <div className="flex items-center text-cyan-400">
//                   <span className="mr-2">❯</span>
//                   <span>{cmd.input}</span>
//                 </div>
//                 <div className="text-gray-300 ml-4 whitespace-pre-line">
//                   {cmd.output}
//                 </div>
//               </div>
//             ))}

//             {/* Current Input */}
//             <div className="flex items-center text-cyan-400">
//               <span className="mr-2">❯</span>
//               <input
//                 ref={inputRef}
//                 type="text"
//                 value={currentInput}
//                 onChange={(e) => setCurrentInput(e.target.value)}
//                 onKeyDown={handleKeyDown}
//                 className="flex-1 bg-transparent outline-none"
//                 autoFocus
//               />
//             </div>
//           </div>
//         )}
//       </div>
//     </div>
//   );
// }


import React, { useState, useRef, useEffect } from 'react';
import { Terminal as TerminalIcon, Maximize2, Minus, X } from 'lucide-react';

export function Terminal() {
  const [commands, setCommands] = useState<{ input: string; output: string }[]>([]);
  const [currentInput, setCurrentInput] = useState('');
  const [minimized, setMinimized] = useState(false);
  const [maximized, setMaximized] = useState(false);
  const terminalRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [commands]);

  const executeCommand = async (input: string) => {
    const newCommand = { input, output: '' };
    const args = input.split(' ');
    const command = args[0].toLowerCase();
    const param = args[1];

    switch (command) {
      case 'help':
        newCommand.output = `Available commands:
  help          - Show this help message
  clear         - Clear terminal
  scan          - Run security scan
  status        - Show system status
  version       - Show version info
  block <IP>    - Block an IP address
  unblock <IP>  - Unblock an IP address`;
        break;
      case 'clear':
        setCommands([]);
        return;
      case 'scan':
        newCommand.output = 'Initiating security scan...\nScanning network endpoints...\nScan complete. No vulnerabilities found.';
        break;
      case 'status':
        newCommand.output = 'System Status:\n✓ Network: Online\n✓ Security: Active\n✓ Monitoring: Running';
        break;
      case 'version':
        newCommand.output = 'NetGuardian Pro v1.0.0\nBuild: 2025.1.1';
        break;
      case 'block':
        if (!param) {
          newCommand.output = "Usage: block <IP>";
        } else {
          newCommand.output = await blockIP(param);
        }
        break;
      default:
        newCommand.output = `Command not found: ${input}\nType 'help' for available commands.`;
    }

    setCommands([...commands, newCommand]);
  };

  const blockIP = async (ip: string) => {
    try {
      const response = await fetch('http://localhost:8004/block', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip }),
      });

      const data = await response.json();
      return response.ok ? data.message : `Error: ${data.detail}`;
    } catch (error) {
      return 'Error: Unable to connect to server';
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && currentInput.trim()) {
      executeCommand(currentInput.trim());
      setCurrentInput('');
    }
  };

  const handleClick = () => {
    inputRef.current?.focus();
  };

  return (
    <div 
      className={`fixed bottom-8 right-8 z-50 transition-all duration-300 ease-in-out
        ${minimized ? 'h-12 w-64' : maximized ? 'inset-8 h-auto w-auto' : 'h-96 w-[32rem]'}
        ${minimized ? 'overflow-hidden' : 'overflow-auto'}`}
    >
      <div className="bg-black/90 backdrop-blur-xl rounded-lg h-full flex flex-col border border-gray-800/50 shadow-2xl">
        {/* Terminal Header */}
        <div className="flex items-center justify-between px-4 py-2 bg-gray-900/50 border-b border-gray-800/50 rounded-t-lg">
          <div className="flex items-center space-x-2">
            <TerminalIcon className="w-4 h-4 text-gray-400" />
            <span className="text-sm text-gray-400">Terminal</span>
          </div>
          <div className="flex items-center space-x-2">
            <button 
              onClick={() => setMinimized(!minimized)}
              className="p-1 hover:bg-gray-700/50 rounded-full transition-colors"
            >
              <Minus className="w-4 h-4 text-gray-400" />
            </button>
            <button 
              onClick={() => setMaximized(!maximized)}
              className="p-1 hover:bg-gray-700/50 rounded-full transition-colors"
            >
              <Maximize2 className="w-4 h-4 text-gray-400" />
            </button>
            <button 
              onClick={() => setMinimized(true)}
              className="p-1 hover:bg-gray-700/50 rounded-full transition-colors"
            >
              <X className="w-4 h-4 text-gray-400" />
            </button>
          </div>
        </div>

        {/* Terminal Content */}
        {!minimized && (
          <div 
            ref={terminalRef}
            className="flex-1 p-4 font-mono text-sm overflow-auto"
            onClick={handleClick}
          >
            {/* Welcome Message */}
            <div className="text-gray-400 mb-4">
              Welcome to NetGuardian Terminal
              <br />
              Type 'help' for available commands.
            </div>

            {/* Command History */}
            {commands.map((cmd, index) => (
              <div key={index} className="mb-4">
                <div className="flex items-center text-cyan-400">
                  <span className="mr-2">❯</span>
                  <span>{cmd.input}</span>
                </div>
                <div className="text-gray-300 ml-4 whitespace-pre-line">
                  {cmd.output}
                </div>
              </div>
            ))}

            {/* Current Input */}
            <div className="flex items-center text-cyan-400">
              <span className="mr-2">❯</span>
              <input
                ref={inputRef}
                type="text"
                value={currentInput}
                onChange={(e) => setCurrentInput(e.target.value)}
                onKeyDown={handleKeyDown}
                className="flex-1 bg-transparent outline-none"
                autoFocus
              />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
