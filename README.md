# RECON_GUARD v2.6 🛡️
**Advanced Cyber Intelligence & Vulnerability Auditing Suite**

Recon_Guard is a professional-grade reconnaissance dashboard designed for educational and authorized security auditing. It integrates real-time scanning engines with geospatial visualization to provide a comprehensive tactical overview of target infrastructure.


## 🚀 Key Features
* **Geospatial Intelligence**: Real-time satellite tracking with full-color map rendering and precision red-marker target anchoring.
* **Vulnerability Matrix**: Dynamic service auditing with color-coded risk assessment (Critical/Warning/Secure) and technical tooltips.
* **Intelligence Pipeline**: Integrated Nmap scanning, Geo-IP carrier identification, and WHOIS registrar record resolution.
* **Ethical Interlock**: Forced-compliance Ethical User Agreement (EUA) to ensure authorized engagement.
* **Reporting Engine**: Automated generation of technical audit reports in PDF format for professional documentation.
* **Session Security**: Integrated "Terminate Engagement" kill-switch to immediately purge sensitive reconnaissance data.

## 🛠️ Technical Stack
* **Frontend**: React.js with Tailwind CSS (Off-Sec aesthetic)
* **Mapping**: Leaflet.js with OpenStreetMap full-color integration
* **Backend**: Python FastAPI High-Performance Engine
* **Scanner**: Nmap (Network Mapper) via `python-nmap`
* **Database**: PostgreSQL for authorized lab target verification
* **Reporting**: jsPDF & AutoTable for automated audit generation

## 📋 Installation & Setup

### 1. Backend Configuration
```bash
cd backend
source venv/bin/activate
pip install -r requirements.txt
sudo service postgresql start
uvicorn app.main:app --reload