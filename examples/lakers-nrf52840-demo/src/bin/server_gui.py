#!/usr/bin/env python3
import sys
import time
import logging
import threading
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QComboBox, QTextEdit, QProgressBar,
    QFrame, QGroupBox, QGridLayout, QMessageBox
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QColor, QPalette, QTextCursor

import serial
import serial.tools.list_ports
import lakers
from lakers import CredentialTransfer, EdhocResponder

# Logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

CRED_PSK = bytes.fromhex("A202686D79646F74626F7408A101A30104024110205050930FF462A77A3540CF546325DEA214")


class QTextEditLogger(logging.Handler):
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget
        self.text_widget.setReadOnly(True)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        self.setFormatter(formatter)

    def emit(self, record):
        msg = self.format(record)
        self.text_widget.append(msg)
        self.text_widget.moveCursor(QTextCursor.End)


class StatusIndicator(QWidget):
    def __init__(self, text, parent=None):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(5, 5, 5, 5)

        self.indicator = QFrame()
        self.indicator.setFixedSize(20, 20)
        self.indicator.setFrameShape(QFrame.Box)
        self.indicator.setFrameShadow(QFrame.Plain)
        self.setStatus(False)

        self.label = QLabel(text)
        self.label.setAlignment(Qt.AlignCenter)
        self.time_label = QLabel("Time: --")
        self.time_label.setAlignment(Qt.AlignCenter)

        self.layout.addWidget(self.indicator, 0, Qt.AlignCenter)
        self.layout.addWidget(self.label, 0, Qt.AlignCenter)
        self.layout.addWidget(self.time_label, 0, Qt.AlignCenter)

    def setStatus(self, completed, color=None):
        if color is None:
            color = QColor(0, 128, 0) if completed else QColor(128, 128, 128)

        palette = self.indicator.palette()
        palette.setColor(QPalette.Window, color)
        self.indicator.setPalette(palette)
        self.indicator.setAutoFillBackground(True)

    def setTime(self, elapsed):
        self.time_label.setText(f"Time: {elapsed:.4f}s")


class EdhocServerGUI(QMainWindow):
    update_signal = pyqtSignal(str, object)

    def __init__(self):
        super().__init__()
        self.init_ui()

        self.server = None
        self.server_thread = None
        self.running = False

        self.update_signal.connect(self.update_gui)

        self.start_time = None
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_timer)
        self.step_times = {}
        self.last_step_time = None
        
        # History tracking
        self.handshake_history = []
        self.current_run = None

        self.refresh_ports()

    def init_ui(self):
        self.setWindowTitle("EDHOC Server")
        self.setGeometry(100, 100, 800, 600)

        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)

        self.create_control_panel(main_layout)
        self.create_progress_display(main_layout)
        self.create_log_display(main_layout)

        self.show()

    def create_control_panel(self, parent_layout):
        group = QGroupBox("Server Controls")
        layout = QGridLayout()

        layout.addWidget(QLabel("Port:"), 0, 0)
        self.port_combo = QComboBox()
        layout.addWidget(self.port_combo, 0, 1)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_ports)
        layout.addWidget(refresh_btn, 0, 2)

        layout.addWidget(QLabel("Baud Rate:"), 0, 3)
        self.baud_combo = QComboBox()
        self.baud_combo.addItems(["9600", "19200", "38400", "57600", "115200"])
        layout.addWidget(self.baud_combo, 0, 4)

        self.start_btn = QPushButton("Start Server")
        self.start_btn.clicked.connect(self.toggle_server)
        layout.addWidget(self.start_btn, 1, 0, 1, 5, Qt.AlignCenter)

        layout.addWidget(QLabel("Status:"), 2, 0)
        self.status_label = QLabel("Stopped")
        self.status_label.setStyleSheet("color: red;")
        layout.addWidget(self.status_label, 2, 1, 1, 4)

        layout.addWidget(QLabel("Elapsed Time:"), 3, 0)
        self.timer_label = QLabel("00:00:00.0000")
        layout.addWidget(self.timer_label, 3, 1, 1, 4)

        group.setLayout(layout)
        parent_layout.addWidget(group)

    def create_progress_display(self, parent_layout):
        group = QGroupBox("Handshake Progress History")
        self.progress_layout = QVBoxLayout()
        
        # Container for all progress bars
        self.progress_scroll_widget = QWidget()
        self.progress_scroll_layout = QVBoxLayout(self.progress_scroll_widget)
        
        self.progress_layout.addWidget(self.progress_scroll_widget)
        
        # Control buttons
        button_layout = QHBoxLayout()
        self.clear_history_btn = QPushButton("Clear History")
        self.clear_history_btn.clicked.connect(self.clear_history)
        button_layout.addWidget(self.clear_history_btn)
        button_layout.addStretch()
        
        self.progress_layout.addLayout(button_layout)
        
        group.setLayout(self.progress_layout)
        parent_layout.addWidget(group)

    def create_log_display(self, parent_layout):
        group = QGroupBox("Server Log")
        layout = QVBoxLayout()

        self.log_text = QTextEdit()
        layout.addWidget(self.log_text)

        log_handler = QTextEditLogger(self.log_text)
        logger.addHandler(log_handler)

        group.setLayout(layout)
        parent_layout.addWidget(group)

    def create_new_progress_bar(self):
        """Create a new progress bar for the current handshake run"""
        run_number = len(self.handshake_history) + 1
        
        # Create container for this run
        run_widget = QWidget()
        run_layout = QVBoxLayout(run_widget)
        run_layout.setContentsMargins(5, 5, 5, 5)
        
        # Add run header
        header = QLabel(f"Run #{run_number}")
        header.setStyleSheet("font-weight: bold; color: #333;")
        run_layout.addWidget(header)
        
        # Progress bar
        progress_bar = QProgressBar()
        progress_bar.setRange(0, 100)
        run_layout.addWidget(progress_bar)
        
        # Status indicators
        status_indicators = {}
        status_layout = QHBoxLayout()
        
        steps = ["message_1", "message_2", "message_3", "message_4", "handshake_complete"]
        
        for step in steps:
            indicator = StatusIndicator(step)
            status_layout.addWidget(indicator)
            status_indicators[step] = indicator
        
        run_layout.addLayout(status_layout)
        
        # Add separator line
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        run_layout.addWidget(line)
        
        # Add to scroll layout
        self.progress_scroll_layout.addWidget(run_widget)
        
        # Create run data structure
        run_data = {
            'widget': run_widget,
            'progress_bar': progress_bar,
            'status_indicators': status_indicators,
            'run_number': run_number,
            'start_time': None,
            'step_times': {}
        }
        
        return run_data

    def clear_history(self):
        """Clear all progress bars from history"""
        while self.progress_scroll_layout.count():
            child = self.progress_scroll_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
        
        self.handshake_history.clear()
        self.current_run = None
        group = QGroupBox("Server Log")
        layout = QVBoxLayout()

        self.log_text = QTextEdit()
        layout.addWidget(self.log_text)

        log_handler = QTextEditLogger(self.log_text)
        logger.addHandler(log_handler)

        group.setLayout(layout)
        parent_layout.addWidget(group)

    def create_new_progress_bar(self):
        """Create a new progress bar for the current handshake run"""
        run_number = len(self.handshake_history) + 1
        
        # Create container for this run
        run_widget = QWidget()
        run_layout = QVBoxLayout(run_widget)
        run_layout.setContentsMargins(5, 5, 5, 5)
        
        # Add run header
        header = QLabel(f"Run #{run_number}")
        header.setStyleSheet("font-weight: bold; color: #333;")
        run_layout.addWidget(header)
        
        # Progress bar
        progress_bar = QProgressBar()
        progress_bar.setRange(0, 100)
        run_layout.addWidget(progress_bar)
        
        # Status indicators
        status_indicators = {}
        status_layout = QHBoxLayout()
        
        steps = ["message_1", "message_2", "message_3", "message_4", "handshake_complete"]
        
        for step in steps:
            indicator = StatusIndicator(step)
            status_layout.addWidget(indicator)
            status_indicators[step] = indicator
        
        run_layout.addLayout(status_layout)
        
        # Add separator line
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        run_layout.addWidget(line)
        
        # Add to scroll layout
        self.progress_scroll_layout.addWidget(run_widget)
        
        # Create run data structure
        run_data = {
            'widget': run_widget,
            'progress_bar': progress_bar,
            'status_indicators': status_indicators,
            'run_number': run_number,
            'start_time': None,
            'step_times': {}
        }
        
        return run_data
        self.port_combo.clear()
        ports = [port.device for port in serial.tools.list_ports.comports()]
        self.port_combo.addItems(ports)
        
        # Set default port to /dev/ttyACM0 if available, otherwise use first port
        default_port = "/dev/ttyACM0"
        if default_port in ports:
            index = ports.index(default_port)
            self.port_combo.setCurrentIndex(index)
        elif ports:
            self.port_combo.setCurrentIndex(0)

    def refresh_ports(self):
        self.port_combo.clear()
        ports = [port.device for port in serial.tools.list_ports.comports()]
        self.port_combo.addItems(ports)
        
        # Set default port to /dev/ttyACM0 if available, otherwise use first port
        default_port = "/dev/ttyACM0"
        if default_port in ports:
            index = ports.index(default_port)
            self.port_combo.setCurrentIndex(index)
        elif ports:
            self.port_combo.setCurrentIndex(0)


    def toggle_server(self):
        if not self.running:
            self.start_server()
        else:
            self.stop_server()

    def start_server(self):
        if self.port_combo.count() == 0:
            QMessageBox.critical(self, "Error", "No serial port available")
            return

        port = self.port_combo.currentText()
        baud_rate = int(self.baud_combo.currentText())

        # Create new progress bar for this run
        self.current_run = self.create_new_progress_bar()
        self.handshake_history.append(self.current_run)

        try:
            self.server = EdhocServer(port, baud_rate, self)
            self.server_thread = threading.Thread(target=self.server.run)
            self.server_thread.daemon = True
            self.server_thread.start()

            self.running = True
            self.start_btn.setText("Stop Server")
            self.status_label.setText("Running")
            self.status_label.setStyleSheet("color: green;")

            logger.info(f"Server started on {port} at {baud_rate} baud (Run #{self.current_run['run_number']})")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not start server: {str(e)}")
            logger.error(f"Failed to start server: {str(e)}")
            # Remove the progress bar if server failed to start
            if self.current_run:
                self.current_run['widget'].deleteLater()
                self.handshake_history.remove(self.current_run)
                self.current_run = None

    def stop_server(self):
        if self.server:
            self.server.stop()
            self.server = None

        self.running = False
        self.timer.stop()
        self.start_btn.setText("Start Server")
        self.status_label.setText("Stopped")
        self.status_label.setStyleSheet("color: red;")
        logger.info("Server stopped")

    def update_timer(self):
        if self.start_time:
            elapsed = time.time() - self.start_time
            h, rem = divmod(elapsed, 3600)
            m, rem = divmod(rem, 60)
            s, ms = divmod(rem, 1)
            self.timer_label.setText(f"{int(h):02d}:{int(m):02d}:{int(s):02d}.{int(ms * 10000):04d}")

    @pyqtSlot(str, object)
    def update_gui(self, action, data):
        if action == "progress" and self.current_run:
            step, completed = data
            status_indicators = self.current_run['status_indicators']
            
            if step in status_indicators:
                status_indicators[step].setStatus(completed)

                if step == "message_1":
                    self.current_run['start_time'] = time.time()
                    self.start_time = self.current_run['start_time']  # For timer display
                    self.timer.start(100)  # Update more frequently for better precision
                    self.last_step_time = self.start_time
                    # Set time for message_1 (cumulative time from start)
                    cumulative_time = time.time() - self.current_run['start_time']
                    status_indicators[step].setTime(cumulative_time)
                    self.current_run['step_times'][step] = cumulative_time
                elif self.current_run['start_time']:
                    # Calculate cumulative time from the start for all steps
                    cumulative_time = time.time() - self.current_run['start_time']
                    status_indicators[step].setTime(cumulative_time)
                    self.current_run['step_times'][step] = cumulative_time

                completed_steps = sum(1 for i in status_indicators.values()
                                      if i.indicator.palette().color(QPalette.Window) == QColor(0, 128, 0))
                total_steps = len(status_indicators)
                self.current_run['progress_bar'].setValue(int((completed_steps / total_steps) * 100))
                
                # Stop the timer once handshake is complete
                if step == "handshake_complete" and completed:
                    self.timer.stop()
                    total_time = self.current_run['step_times'].get('handshake_complete', 0)
                    logger.info(f"Handshake completed in {total_time:.4f}s (Run #{self.current_run['run_number']})")



    def log(self, message):
        logger.info(message)

    def closeEvent(self, event):
        if self.running:
            self.stop_server()
        event.accept()


class EdhocServer:
    def __init__(self, port, baud_rate, gui):
        self.gui = gui
        self.stop_flag = False

        self.ser = serial.Serial(port, baud_rate, timeout=1)
        self.responder = EdhocResponder(CRED_PSK)
        self.edhoc_connections = []

    def run(self):
        self.gui.log(f"Server listening on {self.ser.port}...")

        while not self.stop_flag:
            if self.ser.in_waiting:
                message_raw = []
                start_time = time.time()

                while time.time() - start_time < 0.5 and not self.stop_flag:
                    if self.ser.in_waiting:
                        message_raw.extend(self.ser.read(self.ser.in_waiting))

                if message_raw and not self.stop_flag:
                    try:
                        if message_raw[0] == 0xf5:
                            self.gui.log(f"Received message_1: {list(message_raw)}")
                            self.gui.update_signal.emit("progress", ("message_1", True))
                            c_i, ead_1 = self.responder.process_message_1(message_raw[1:])
                            c_r = [0xA]
                            msg2 = self.responder.prepare_message_2(c_r, ead_1)
                            self.gui.log(f"Send message_2: {list(msg2)}")
                            self.ser.write(b"\xf5" + msg2)
                            self.ser.flush()
                            self.edhoc_connections.append((c_r, self.responder))
                            self.gui.update_signal.emit("progress", ("message_2", True))

                        else:
                            self.gui.log(f"Received message_3: {list(message_raw)}")
                            self.gui.update_signal.emit("progress", ("message_3", True))
                            c_r_rcvd = [message_raw[0]]
                            id_cred_i, ead_3 = self.responder.parse_message_3(message_raw[1:])
                            self.responder = self.take_state(c_r_rcvd)
                            valid_cred_i = lakers.credential_check_or_fetch(id_cred_i, CRED_PSK)
                            self.responder.verify_message_3(valid_cred_i)
                            self.gui.update_signal.emit("progress", ("message_4", True))
                            message_4, prk_out = self.responder.prepare_message_4()
                            self.gui.log(f"Send message_4: {list(message_4)}")
                            self.ser.write(message_4)
                            self.ser.flush()
                            self.gui.update_signal.emit("progress", ("handshake_complete", True))

                    except Exception as e:
                        self.gui.log(f"EDHOC Error: {e}")

            time.sleep(0.1)

    def take_state(self, c_r_rcvd):
        for i, (c_r, responder) in enumerate(self.edhoc_connections):
            if c_r == c_r_rcvd:
                return self.edhoc_connections.pop(i)[1]
        raise ValueError("No stored state for that Connection Identifier")

    def stop(self):
        self.stop_flag = True
        if self.ser and self.ser.is_open:
            self.ser.close()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    ex = EdhocServerGUI()
    sys.exit(app.exec_())