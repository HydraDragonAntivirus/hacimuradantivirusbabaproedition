import sys
import os
import logging
import yara
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QFileDialog,
    QListWidget, QStackedWidget, QMessageBox
)
from PySide6.QtCore import Qt, QObject, QThread, Signal
from PySide6.QtGui import QIcon

# Set script directory
script_dir = os.getcwd()

# Configure logging
log_directory = os.path.join(script_dir, "log")
log_file = os.path.join(log_directory, "antivirus.log")
if not os.path.exists(log_directory):
    os.makedirs(log_directory)

logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)

# Define YARA rule folder path
yara_folder_path = os.path.join(script_dir, "rules")

try:
    compiled_rule = yara.load(os.path.join(yara_folder_path, "antiviruspro.yrc"))
    print("YARA Rules Definitions loaded!")
except yara.Error as e:
    print(f"Error loading precompiled YARA rule: {e}")

class YaraScanner:
    def scan_data(self, file_path):
        matched_rules = []
        if os.path.exists(file_path):
            with open(file_path, 'rb') as file:
                data = file.read()
                if compiled_rule:
                    matches = compiled_rule.match(data=data)
                    if matches:
                        for match in matches:
                            matched_rules.append(match.rule)
        return matched_rules if matched_rules else None

yara_scanner = YaraScanner()

class FolderScanner(QThread):
    result_signal = Signal(str, bool, str)

    def __init__(self, folder_path):
        super().__init__()
        self.folder_path = folder_path

    def run(self):
        # Scan all files in the specified folder and its subfolders
        for root, _, files in os.walk(self.folder_path):  # Traverses all subdirectories
            for file in files:
                file_path = os.path.join(root, file)
                is_malicious, virus_name = self.scan_file(file_path)
                self.result_signal.emit(file_path, is_malicious, virus_name)

    def scan_file(self, file_path):
        logging.info(f"Started scanning file: {file_path}")
        yara_result = yara_scanner.scan_data(file_path)
        if yara_result:
            logging.warning(f"Infected file detected: {file_path} - Virus: {yara_result}")
            return True, ', '.join(yara_result)
        logging.info(f"Scanned file: {file_path} - No viruses detected")
        return False, "Clean"

class AntivirusUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Hacimurad Antivirus")
        self.setWindowIcon(QIcon("assets/shield-antivirus.png"))
        self.stacked_widget = QStackedWidget()
        self.main_widget = QWidget()
        self.setup_main_ui()
        self.stacked_widget.addWidget(self.main_widget)
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.stacked_widget)
        self.setLayout(main_layout)
        
    def setup_main_ui(self):
        layout = QVBoxLayout()
        self.folder_label = QLabel("No folder selected")
        
        # Scan Button
        self.scan_button = QPushButton("Select Folder to Scan")
        self.scan_button.clicked.connect(self.select_folder)
        
        # False Positive Scan Button
        self.false_positive_button = QPushButton("Select Folder for False Positive Scan")
        self.false_positive_button.clicked.connect(self.run_false_positive_scan)
        
        # Save Scan Results Button
        self.save_scan_results_button = QPushButton("Save Scan Results to File")
        self.save_scan_results_button.clicked.connect(self.save_scan_results)
        
        # Save False Positives Button
        self.save_false_positive_button = QPushButton("Save False Positives to File")
        self.save_false_positive_button.clicked.connect(self.save_false_positives)
        
        # Result Lists
        self.results_list = QListWidget()
        self.false_positives_list = QListWidget()
        
        # Layout
        layout.addWidget(self.folder_label)
        layout.addWidget(self.scan_button)
        layout.addWidget(self.false_positive_button)
        layout.addWidget(self.save_scan_results_button)
        layout.addWidget(self.save_false_positive_button)
        layout.addWidget(QLabel("Scan Results:"))
        layout.addWidget(self.results_list)
        layout.addWidget(QLabel("False Positives:"))
        layout.addWidget(self.false_positives_list)
        
        self.main_widget.setLayout(layout)

    def select_folder(self):
        folder_path = QFileDialog.getExistingDirectory(self, "Select Folder to Scan")
        if folder_path:
            self.folder_label.setText(f"Selected Folder: {folder_path}")
            self.results_list.clear()
            self.false_positives_list.clear()
            self.start_scan(folder_path)

    def start_scan(self, folder_path):
        self.scan_thread = FolderScanner(folder_path)
        self.scan_thread.result_signal.connect(self.display_result)
        self.scan_thread.start()

    def run_false_positive_scan(self):
        folder_path = QFileDialog.getExistingDirectory(self, "Select Folder for False Positive Scan")
        if folder_path:
            self.false_positives_list.clear()
            self.false_positive_thread = FolderScanner(folder_path)
            self.false_positive_thread.result_signal.connect(self.display_false_positive)
            self.false_positive_thread.start()

    def display_result(self, file_path, is_malicious, virus_name):
        result_text = f"{file_path}: {'Infected' if is_malicious else 'Clean'}"
        if is_malicious:
            result_text += f" - Virus: {virus_name}"
        self.results_list.addItem(result_text)

    def display_false_positive(self, file_path, is_malicious, virus_name):
        if is_malicious:
            false_positive_text = f"{file_path}: False Positive - Rules matched: {virus_name}"
            self.false_positives_list.addItem(false_positive_text)

    def save_false_positives(self):
        save_path = os.path.join(script_dir, "false_positives.txt")
        with open(save_path, "w") as file:
            for i in range(self.false_positives_list.count()):
                file.write(self.false_positives_list.item(i).text() + "\n")
        QMessageBox.information(self, "Save Complete", f"False positives saved to {save_path}")

    def save_scan_results(self):
        save_path = os.path.join(script_dir, "scan_results.txt")
        with open(save_path, "w") as file:
            for i in range(self.results_list.count()):
                file.write(self.results_list.item(i).text() + "\n")
        QMessageBox.information(self, "Save Complete", f"Scan results saved to {save_path}")

# Define styling for the UI
antivirus_style = """
QWidget {
    background-color: #2b2b2b;
    color: #e0e0e0;
    font-family: Arial, sans-serif;
    font-size: 14px;
}
QPushButton {
    background: qradialgradient(cx:0.5, cy:0.5, radius:0.5, fx:0.5, fy:0.5,
                                stop:0.2 #007bff, stop:0.8 #0056b3);
    color: white;
    border: 2px solid #007bff;
    padding: 4px 10px;
    border-radius: 8px;
    min-width: 70px;
    font-weight: bold;
}
QPushButton:hover {
    background: qradialgradient(cx:0.5, cy:0.5, radius:0.5, fx:0.5, fy:0.5,
                                stop:0.2 #0056b3, stop:0.8 #004380);
    border-color: #0056b3;
}
QPushButton:pressed {
    background: qradialgradient(cx:0.5, cy:0.5, radius:0.5, fx:0.5, fy:0.5,
                                stop:0.2 #004380, stop:0.8 #003d75);
    border-color: #004380;
}
QLabel, QListWidget {
    color: #e0e0e0;
}
"""

def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(antivirus_style)
    main_gui = AntivirusUI()
    main_gui.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
