# 🔍 Advanced Network Scanner+ by KeenenX

  <img src="https://i.imgur.com/l1sLAc1.png" alt="naabu" width="570px">
  <br>
</h1>

## ✨ Features
- Multiple Scan Modes: Choose from Ping Sweep, Basic Scan, Full Detection, or Vulnerability Scan.

- Scan Speed Profiles: Paranoid to Insane (T0–T5) for IDS evasion or aggressive scanning.

- Custom or Predefined Port Ranges: Top 100, Top 1000, All Ports, Well-Known Ports, or manual.

- Stealth Mode: Automatically configures safe scan options to evade detection.

- OS Detection: Determine the operating system of the target.

- Service Version Detection: Identify service versions running on open ports.

- Vulnerability Scripts: Run pre-defined vuln category scripts for weak point detection.

- Packet Fragmentation (Evasion): Attempt to bypass basic firewalls and filters.

- Output Format Support: TXT, XML, GUI View, or External Terminal.

- Dark Mode Toggle: Clean UI that adapts to your preference.

- Child-Friendly Output Format: Results are organized, labeled, and simplified.

<hr width="100%"/>

## 🛰️ Network Scanner


### _Fast host discovery without port scanning_

#### The Network Scanner mode performs fast and reliable host discovery using ICMP Echo (Ping Sweep). It is ideal for mapping out active machines in your network:

-  Uses nmap -sn for silent scanning.

-  Detects online/offline devices without probing open ports.

-  Recommended for initial reconnaissance.

### Use Case:

"Show me all active hosts in a /24 subnet without raising alarms."

<hr width="100%"/>

## 🌊 Port Scanner

### _Discover open ports and exposed services_

#### The Port Scanner mode gives you granular control over port-based scanning:

-  TCP SYN scan (-sS) for stealthy probing.

-  Choose from predefined port sets or input custom ones.

-  Supports fast scan (--top-ports) or full scan (-p 1-65535).

#### Scan Speed Tiers:

-  T0: Stealth (slow, IDS-safe)

-  T3: Balanced (default)

-  T5: Aggressive (fast, may trigger alarms)

### Use Case:

"Scan the top 1000 ports on a machine and identify which services are running."

<hr width="100%"/>

## 🛡 Vulnerability Scanner

### _Scan for known vulnerabilities with Nmap scripts_

#### The Vulnerability Scanner mode runs detection scripts from Nmap’s scripting engine:

-  Executes scripts from the vuln category.

-  Enables -sV and -O to identify versions and operating systems.

-  Useful for catching known vulnerabilities quickly.

#### Recommended Add-ons:

-  Enable Fragmentation (-f) for evasion.

-  Use XML output for feeding into other tools.

### Use Case:

"Quickly find outdated services and known CVEs on exposed ports."

<hr width="100%"/>






```yaml

  import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QTextEdit, QPushButton,
    QVBoxLayout, QHBoxLayout, QComboBox, QCheckBox, QFileDialog, QMessageBox, QDialog
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QMovie
import subprocess
from datetime import datetime
import os
import platform
import shlex

class OutputWindow(QDialog):
    def __init__(self, result_text):
        super().__init__()
        self.setWindowTitle("Scan Results - Advanced Network Scanner+")
        self.setMinimumSize(600, 400)
        layout = QVBoxLayout()
        label = QLabel("Scan Summary:")
        label.setStyleSheet("font-weight: bold; font-size: 16px")
        layout.addWidget(label)

        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        self.output_area.setText(result_text)
        layout.addWidget(self.output_area)
        self.setLayout(layout)

class NmapScannerGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced Network Scanner+ by KeenenX")
        self.resize(600, 600)
        self.dark_mode_enabled = False
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()

        self.target_input = QLineEdit()
        layout.addWidget(QLabel("Target IP/Domain:"))
        layout.addWidget(self.target_input)

        self.scan_type = QComboBox()
        self.scan_type.addItems([
            "Ping Sweep", "Basic Port Scan", "Port + Version + OS Detection", "Vulnerability Scan"
        ])
        layout.addWidget(QLabel("Scan Type:"))
        layout.addWidget(self.scan_type)

        self.speed_combo = QComboBox()
        self.speed_combo.addItems([
            "T0 - Paranoid 🐌 Extremely slow, avoids IDS",
            "T1 - Sneaky 🐢 Slower, still avoids detection",
            "T2 - Polite 🎩 Reduces bandwidth/CPU load",
            "T3 - Normal ⚖️ Default speed. Good balance",
            "T4 - Aggressive 🚀 Fast, might be detected",
            "T5 - Insane 🚨 Fastest, highly detectable"
        ])
        self.speed_combo.setCurrentIndex(3)  # Default to T3
        layout.addWidget(QLabel("Scan Speed (Aggressiveness):"))
        layout.addWidget(self.speed_combo)

        self.stealth_mode = QCheckBox("Enable Stealth Mode (slow, evasive)")
        layout.addWidget(self.stealth_mode)

        self.port_range_combo = QComboBox()
        self.port_range_combo.addItems([
            "Top 100 Ports (default) - Fastest. (--top-ports 100)",
            "Top 1000 Ports - Balanced. (--top-ports 1000)",
            "All Ports (1-65535) - Full, slow. (-p 1-65535)",
            "Well-Known Ports (1-1024) - Standard services",
            "Custom Ports - Input manually"
        ])
        layout.addWidget(QLabel("Port Scan Range:"))
        layout.addWidget(self.port_range_combo)
        self.port_range_combo.currentIndexChanged.connect(self.toggle_custom_port_input)

        self.port_input = QLineEdit()
        layout.addWidget(QLabel("Custom Ports (e.g., 21,22,80):"))
        layout.addWidget(self.port_input)
        self.port_input.setEnabled(False)

        self.os_detect = QCheckBox("Enable OS Detection")
        self.ver_detect = QCheckBox("Enable Service Version Detection")
        self.vuln_scan = QCheckBox("Run Vulnerability Scripts")
        self.evasion = QCheckBox("Enable Evasion (Fragment Packets)")

        layout.addWidget(self.os_detect)
        layout.addWidget(self.ver_detect)
        layout.addWidget(self.vuln_scan)
        layout.addWidget(self.evasion)

        self.output_format = QComboBox()
        self.output_format.addItems([
            "GUI Only",
            "Save as TXT",
            "Save as XML",
            "Show in External Terminal"
        ])
        layout.addWidget(QLabel("Output Format:"))
        layout.addWidget(self.output_format)

        self.dark_mode_toggle = QCheckBox("Dark Mode")
        self.dark_mode_toggle.stateChanged.connect(self.toggle_dark_mode)
        layout.addWidget(self.dark_mode_toggle)

        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.start_scan)
        layout.addWidget(self.scan_button)

        self.result_area = QTextEdit()
        self.result_area.setReadOnly(True)
        layout.addWidget(QLabel("Scan Output (raw):"))
        layout.addWidget(self.result_area)

        self.setLayout(layout)

    def toggle_dark_mode(self, state):
        if state == Qt.Checked:
            self.setStyleSheet("background-color: #2e2e2e; color: white;")
        else:
            self.setStyleSheet("")

    def toggle_custom_port_input(self):
        if self.port_range_combo.currentText().startswith("Custom Ports"):
            self.port_input.setEnabled(True)
        else:
            self.port_input.setEnabled(False)

    def start_scan(self):
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Error", "Target IP/Domain is required.")
            return

        cmd = ["nmap"]

        # Stealth mode overrides
        if self.stealth_mode.isChecked():
            self.speed_combo.setCurrentIndex(1)
            self.evasion.setChecked(True)
            self.ver_detect.setChecked(False)
            self.os_detect.setChecked(False)

        # Scan speed
        speed = self.speed_combo.currentIndex()
        cmd += [f"-T{speed}"]

        # Scan type
        scan_mode = self.scan_type.currentIndex()
        if scan_mode == 0:
            cmd += ["-sn"]
        else:
            port_range = self.port_range_combo.currentIndex()
            if port_range == 0:
                cmd += ["--top-ports", "100"]
            elif port_range == 1:
                cmd += ["--top-ports", "1000"]
            elif port_range == 2:
                cmd += ["-p", "1-65535"]
            elif port_range == 3:
                cmd += ["-p", "1-1024"]
            elif port_range == 4 and self.port_input.text():
                cmd += ["-p", self.port_input.text().strip()]

            cmd += ["-sS"]
            if self.ver_detect.isChecked():
                cmd.append("-sV")
            if self.os_detect.isChecked():
                cmd.append("-O")
            if self.vuln_scan.isChecked():
                cmd += ["--script", "vuln"]

        if self.evasion.isChecked():
            cmd.append("-f")

        cmd.append(target)

        output_mode = self.output_format.currentText()
        filename = None
        if output_mode == "Save as TXT":
            filename = f"scan_{target.replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            cmd += ["-oN", filename]
        elif output_mode == "Save as XML":
            filename = f"scan_{target.replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
            cmd += ["-oX", filename]
        elif output_mode == "Show in External Terminal":
            self.result_area.append("[+] Launching scan in external terminal...\n")
            if platform.system() == "Windows":
                subprocess.Popen(['start', 'cmd', '/k'] + cmd, shell=True)
            elif platform.system() == "Linux":
                subprocess.Popen(['x-terminal-emulator', '-e'] + cmd)
            elif platform.system() == "Darwin":
                cmd_str = ' '.join(shlex.quote(part) for part in cmd)
                subprocess.Popen(['osascript', '-e', f'tell app \"Terminal\" to do script \"{cmd_str}\"'])
            return

        self.result_area.append("[+] Running command: " + ' '.join(cmd) + "\n")
        QApplication.setOverrideCursor(Qt.WaitCursor)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            output_text = result.stdout
            self.result_area.append(output_text)
            if filename:
                self.result_area.append(f"\n[+] Output saved to: {os.path.abspath(filename)}")
            if output_mode == "GUI Only":
                out_window = OutputWindow(output_text)
                out_window.exec_()
        except subprocess.TimeoutExpired:
            self.result_area.append("[!] Scan timed out.")
        except Exception as e:
            self.result_area.append(f"[!] Error: {str(e)}")
        finally:
            QApplication.restoreOverrideCursor()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NmapScannerGUI()
    window.show()
    sys.exit(app.exec_())

```
