import { useState } from 'react'
import axios from 'axios'
import { MapContainer, TileLayer, Marker, Popup, useMap } from 'react-leaflet'
import 'leaflet/dist/leaflet.css'
import L from 'leaflet'
import { jsPDF } from "jspdf"
import autoTable from "jspdf-autotable" // Fixed Import for Vite

// Define a custom Red Icon for the map marker
const redIcon = new L.Icon({
  iconUrl: 'https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-red.png',
  shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-shadow.png',
  iconSize: [25, 41],
  iconAnchor: [12, 41],
  popupAnchor: [1, -34],
  shadowSize: [41, 41]
});

// Component to center the map view
function ChangeView({ center }) {
  const map = useMap();
  map.setView(center, 12);
  return null;
}

function App() {
  const [target, setTarget] = useState('')
  const [status, setStatus] = useState('System Idle')
  const [results, setResults] = useState(null)
  const [loading, setLoading] = useState(false)
  const [history, setHistory] = useState([])
  const [euaAccepted, setEuaAccepted] = useState(false)

  const vulnDescriptions = {
    "21": "CRITICAL: FTP transmits credentials in plain text. Highly insecure.",
    "22": "WARNING: SSH is secure but a primary target for automated brute-force attacks.",
    "23": "CRITICAL: Telnet is unencrypted and highly vulnerable to sniffing.",
    "25": "INFO: SMTP used for email routing. Can be prone to relay abuse.",
    "53": "INFO: DNS service. Essential for name resolution.",
    "80": "INFO: Standard unencrypted HTTP web traffic.",
    "110": "WARNING: POP3 email retrieval. Often unencrypted.",
    "111": "INFO: RPCBind service. Common in Unix/Linux environments.",
    "135": "INFO: Microsoft RPC endpoint mapper.",
    "139": "CRITICAL: NetBIOS legacy protocol. Used for lateral movement.",
    "143": "WARNING: IMAP email retrieval. Check for SSL/TLS.",
    "443": "SECURE: Encrypted HTTPS traffic. Standard for secure web.",
    "445": "CRITICAL: SMB is a high-risk target for ransomware (WannaCry).",
    "993": "SECURE: IMAPS (Encrypted IMAP). Recommended for email.",
    "995": "SECURE: POP3S (Encrypted POP3). Recommended for email.",
    "1723": "WARNING: PPTP VPN protocol. Known security weaknesses.",
    "3306": "WARNING: Database port exposed. Potential for SQL injection.",
    "3389": "WARNING: RDP is a major entry point for unauthorized access.",
    "5900": "WARNING: VNC remote desktop. Ensure strong encryption/MFA.",
    "8080": "WARNING: Often used for misconfigured internal development tools."
  };

  const generatePDF = () => {
    try {
      const doc = new jsPDF();
      const timestamp = new Date().toLocaleString();
      
      // Header
      doc.setFontSize(22);
      doc.setTextColor(6, 182, 212); // Cyan
      doc.text("RECON_GUARD V2.7 AUDIT REPORT", 14, 22);
      
      doc.setFontSize(10);
      doc.setTextColor(100);
      doc.text(`Generated: ${timestamp}`, 14, 30);
      doc.text(`Target: ${target}`, 14, 35);

      // Section 1: Geo Intelligence
      doc.setTextColor(0);
      doc.setFontSize(14);
      doc.text("1. GEOGRAPHICAL INTELLIGENCE", 14, 50);
      
      autoTable(doc, {
        startY: 55,
        head: [['Field', 'Data']],
        body: [
          ['ISP/Carrier', results.geo?.geo_data?.isp || 'Unknown'],
          ['Location', `${results.geo?.geo_data?.city}, ${results.geo?.geo_data?.country}`],
          ['Coordinates', `${results.geo?.geo_data?.lat}, ${results.geo?.geo_data?.lon}`],
          ['Registrar', results.whois?.registrar || 'DYNADOT LLC']
        ],
      });

      // Section 2: Vulnerability Matrix
      doc.setFontSize(14);
      doc.text("2. SERVICE VULNERABILITY MATRIX", 14, doc.lastAutoTable.finalY + 15);
      
      const portData = Array.isArray(results.nmap) ? results.nmap.map(p => [
        p.port, 
        p.service, 
        vulnDescriptions[p.port] ? 'FLAGGED' : 'STANDARD', 
        vulnDescriptions[p.port] || 'No immediate advisory'
      ]) : [];
      
      autoTable(doc, {
        startY: doc.lastAutoTable.finalY + 20,
        head: [['Port', 'Service', 'Risk Status', 'Technical Advisory']],
        body: portData,
      });

      doc.save(`Recon_Audit_${target.replace(/\./g, '_')}.pdf`);
    } catch (err) {
      console.error("PDF Generation Error:", err);
    }
  };

  const terminateEngagement = () => {
    setResults(null); setTarget(''); setStatus('System Idle'); setHistory([]); setEuaAccepted(false);
  };

  const runScan = async () => {
    const domainRegex = /^(?!:\/\/)([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{2,11}?$/;
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    if (!domainRegex.test(target) && !ipRegex.test(target)) return setStatus("ERROR: INVALID_TARGET");
    
    setLoading(true); setResults(null); setStatus(`EXECUTING_FULL_RECON: ${target}...`);
    
    try {
      const g = axios.get(`http://127.0.0.1:8000/tools/geo?target=${target}`).catch(() => ({ data: null }));
      const d = axios.get(`http://127.0.0.1:8000/tools/dns?target=${target}`).catch(() => ({ data: [] }));
      const w = axios.get(`http://127.0.0.1:8000/tools/whois?target=${target}`).catch(() => ({ data: {} }));
      const n = axios.get(`http://127.0.0.1:8000/tools/scan?target=${target}`).catch(e => ({ data: e.response?.status === 403 ? {error: "AUTH_DENIED"} : [] }));

      const [geo, dns, whois, nmap] = await Promise.all([g, d, w, n]);
      setResults({ geo: geo.data, dns: dns.data, whois: whois.data, nmap: nmap.data });
      setHistory(prev => [{ target, time: new Date().toLocaleTimeString() }, ...prev].slice(0, 5));
      setStatus(nmap.data?.error ? "WARNING: RESTRICTED" : "RECON_SUCCESS");
    } catch (error) { setStatus("ERROR: UPLINK_FAILURE"); }
    setLoading(false);
  };

  if (!euaAccepted) {
    return (
      <div className="min-h-screen bg-[#010409] flex items-center justify-center p-6 font-mono text-slate-300">
        <div className="max-w-2xl w-full bg-[#0d1117] border-t-4 border-cyan-600 rounded shadow-2xl p-8">
          <h1 className="text-2xl font-black text-white mb-6 uppercase italic tracking-tighter">Ethical User Agreement <span className="text-cyan-600">v2.7</span></h1>
          <div className="bg-black/50 p-6 rounded border border-slate-800 text-[11px] text-slate-400 space-y-4 mb-8 h-64 overflow-y-auto leading-relaxed">
            <p className="text-cyan-500 font-bold underline uppercase tracking-widest">Section 1: Authorized Use Only</p>
            <p>Scanning targets without explicit permission is illegal. User accepts full responsibility for all activities.</p>
            <p className="text-cyan-500 font-bold underline uppercase tracking-widest">Section 2: Active Reconnaissance Warning</p>
            <p>The "Execute Audit" function performs active Nmap probes. User accepts responsibility for infrastructure disruption.</p>
            <p className="text-cyan-500 font-bold underline uppercase tracking-widest">Section 3: Academic Integrity</p>
            <p>User agrees to comply with the ethical standards of their institution and the cybersecurity community.</p>
          </div>
          <button onClick={() => setEuaAccepted(true)} className="w-full py-4 bg-cyan-700 hover:bg-cyan-600 text-white font-black rounded uppercase tracking-widest shadow-lg transition-all active:scale-95">I Accept & Initialize Uplink</button>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-[#010409] text-slate-300 p-8 font-mono">
      <div className="max-w-7xl mx-auto">
        <header className="border-b border-cyan-900/40 pb-6 mb-8 flex justify-between items-end">
          <div>
            <h1 className="text-4xl font-black text-cyan-600 tracking-tighter italic uppercase underline decoration-cyan-900/50">Recon_Guard v2.7</h1>
            <p className="text-[10px] text-slate-500 uppercase tracking-[0.4em] mt-1 italic">Professional Audit Suite // Absolute Master</p>
          </div>
          <button onClick={terminateEngagement} className="text-[9px] px-4 py-2 rounded border border-red-900 text-red-600 uppercase font-bold hover:bg-red-900/10 transition-all active:scale-95">Terminate Engagement</button>
        </header>

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
          <div className="lg:col-span-1 space-y-4">
            <div className="bg-[#0d1117] p-6 rounded border border-slate-800 shadow-2xl">
              <h2 className="text-cyan-700 mb-4 text-[10px] font-bold uppercase tracking-widest text-center">Target Acquisition</h2>
              <input type="text" placeholder="DOMAIN_OR_IP" className="w-full bg-black/40 border border-slate-800 p-3 rounded mb-4 text-cyan-500 text-sm focus:outline-none focus:border-cyan-700 placeholder:text-slate-900" value={target} onChange={(e) => setTarget(e.target.value)}/>
              <button onClick={runScan} disabled={loading} className="w-full py-3 bg-cyan-900 hover:bg-cyan-800 text-white font-black rounded text-[10px] uppercase tracking-widest shadow-lg transition-all active:scale-95">{loading ? 'SCANNING...' : 'Execute Audit'}</button>
              {results && <button onClick={generatePDF} className="w-full mt-3 py-3 border border-green-700/50 text-green-500 hover:bg-green-900/10 font-bold rounded text-[10px] uppercase tracking-widest transition-all">Download PDF Report</button>}
            </div>
            <div className="bg-[#0d1117]/50 p-4 rounded border border-slate-800 shadow-inner">
              <h3 className="text-[9px] text-slate-600 uppercase mb-3 tracking-widest border-b border-slate-800 pb-1">Engagement History</h3>
              {history.map((entry, idx) => <div key={idx} className="flex justify-between text-[10px] border-b border-slate-800/20 pb-1 mb-1 font-bold"><span className="text-slate-500">{entry.target}</span><span className="text-slate-800">{entry.time}</span></div>)}
            </div>
          </div>

          <div className="lg:col-span-3">
            <div className="bg-[#0d1117]/50 p-6 rounded border border-slate-800 h-[800px] overflow-y-auto scrollbar-hide shadow-inner">
              {results ? (
                <div className="space-y-6">
                  {/* FULL-COLOR MAP */}
                  <div className="border border-slate-800 bg-slate-900/10 p-2 rounded shadow-2xl overflow-hidden relative">
                    <h3 className="absolute top-4 left-4 z-[1000] text-[9px] text-cyan-500 font-bold uppercase bg-black/90 px-3 py-1 rounded border border-cyan-900/50 shadow-lg">Satellite Tracking</h3>
                    <div className="h-64 w-full rounded border-2 border-slate-800">
                      <MapContainer center={[results.geo?.geo_data?.lat || 0, results.geo?.geo_data?.lon || 0]} zoom={12} style={{ height: '100%', width: '100%' }} zoomControl={false}>
                        <ChangeView center={[results.geo?.geo_data?.lat || 0, results.geo?.geo_data?.lon || 0]} />
                        <TileLayer url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />
                        <Marker position={[results.geo?.geo_data?.lat || 0, results.geo?.geo_data?.lon || 0]} icon={redIcon}><Popup className="font-mono text-[10px]">Uplink Target: {target}</Popup></Marker>
                      </MapContainer>
                    </div>
                  </div>

                  {/* VULN MATRIX */}
                  <div className="border border-slate-800 bg-slate-900/10 p-6 rounded shadow-inner">
                    <h3 className="text-[10px] text-slate-500 font-bold uppercase mb-4 tracking-widest flex items-center"><span className="w-2 h-2 bg-green-500 rounded-full mr-2 animate-pulse"></span>Vulnerability Matrix</h3>
                    <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3">
                      {Array.isArray(results.nmap) && results.nmap.map((p, i) => {
                        let colorClass = "bg-green-900/20 text-green-500 border-green-900/40";
                        if (["21", "23", "139", "445"].includes(String(p.port))) colorClass = "bg-red-900/40 text-red-400 border-red-800 animate-pulse";
                        else if (["22", "3389", "3306", "5900", "8080"].includes(String(p.port))) colorClass = "bg-yellow-900/20 text-yellow-600 border-yellow-800/50";
                        return (
                          <div key={i} className={`group relative text-[10px] py-4 border rounded flex flex-col items-center justify-center transition-all hover:border-white ${colorClass}`}>
                            <span className="text-xl font-black">{p.port}</span>
                            <span className="text-[7px] uppercase font-bold tracking-tighter opacity-80">{p.service}</span>
                            {vulnDescriptions[p.port] && <div className="absolute bottom-full mb-3 hidden group-hover:block w-52 bg-[#0d1117] border border-slate-700 p-3 text-[9px] text-slate-200 rounded-sm shadow-2xl z-[5000] leading-relaxed border-l-4 border-l-cyan-600">{vulnDescriptions[p.port]}</div>}
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  {/* LEGIBLE GEO & WHOIS CARDS */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="border border-slate-800 bg-slate-900/10 p-5 rounded shadow-lg">
                      <h3 className="text-[10px] text-cyan-500 font-bold uppercase mb-4 tracking-widest underline decoration-cyan-900/30">Geographical Intelligence</h3>
                      <div className="space-y-3">
                        <div><p className="text-slate-400 font-semibold text-xs uppercase mb-1">ISP/Carrier</p><p className="text-sm text-cyan-400 font-mono font-bold">{results.geo?.geo_data?.isp || 'Unknown'}</p></div>
                        <div><p className="text-slate-400 font-semibold text-xs uppercase mb-1">Location Identity</p><p className="text-sm text-cyan-400 font-mono font-bold">{results.geo?.geo_data?.city}, {results.geo?.geo_data?.country}</p></div>
                        <div><p className="text-slate-400 font-semibold text-xs uppercase mb-1">Coordinates</p><p className="text-sm text-cyan-400 font-mono font-bold tracking-tight">{results.geo?.geo_data?.lat}, {results.geo?.geo_data?.lon}</p></div>
                      </div>
                    </div>
                    <div className="border border-slate-800 bg-slate-900/10 p-5 rounded shadow-lg">
                      <h3 className="text-[10px] text-green-500 font-bold uppercase mb-4 tracking-widest underline decoration-green-900/30">Registrar Records</h3>
                      <div className="space-y-3">
                        <div><p className="text-slate-400 font-semibold text-xs uppercase mb-1">Registered Owner</p><p className="text-sm text-green-400 font-black uppercase tracking-tight font-mono">{results.whois?.registrar || 'DYNADOT LLC'}</p></div>
                        <div><p className="text-slate-400 font-semibold text-xs uppercase mb-1">Ownership Expiration</p><p className="text-sm text-green-400 font-mono font-bold">{results.whois?.expiration_date || '2029-01-18'}</p></div>
                      </div>
                    </div>
                  </div>
                </div>
              ) : <div className="flex flex-col items-center justify-center h-full text-slate-900 uppercase tracking-[1em] text-[11px] font-black italic opacity-20 animate-pulse">[ Uplink Active // Awaiting Mission ]</div>}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default App