# coding: utf-8
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext, font as tkFont
import re
from collections import Counter # For CLI info mode counts
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
import calendar
import os
import csv
import json
import configparser
import argparse
import sys
import traceback # For detailed error printing

# --- Optional Dependencies ---
try:
    import Evtx.Evtx as evtx
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False

try:
    import sv_ttk
    SVTTK_AVAILABLE = True
except ImportError:
    SVTTK_AVAILABLE = False

try:
    import colorama
    COLORAMA_AVAILABLE = True
    # Auto-reset color changes after each print in CLI
    colorama.init(autoreset=True)
except ImportError:
    COLORAMA_AVAILABLE = False

# --- Constants ---
LOG_FORMATS = ["Auto-Detect", "Windows EVTX", "Windows XML Event", "Linux Syslog", "macOS Log Show"]
BASE_COLUMNS = ['Timestamp', 'Level', 'System', 'Component', 'EventID', 'Message']
DEFAULT_THEME = "dark" # Default to dark mode
PREFS_DIR = os.path.join(os.path.expanduser("~"), ".ultimate_log_viewer_pro") # App-specific dir
CONFIG_FILE = os.path.join(PREFS_DIR, "prefs.ini")
# Default font preference with fallbacks (common fixed-width fonts)
DEFAULT_FONT_FAMILY = 'Consolas, Courier New, DejaVu Sans Mono, Monaco, TkFixedFont'
#Sort Constants
SORT_INDICATOR_ASC = " ▲"
SORT_INDICATOR_DESC = " ▼"
# --- Helper & Parsing Functions ---

def _get_cli_sort_key(entry, column):
    """Generates a key for CLI sorting (similar to GUI)."""
    value = entry.get(column)
    # Order: None -> datetime -> number -> string
    if value is None:
        return (0, '')
    if isinstance(value, datetime):
        return (1, value)
    # Try converting common ID fields to int for numeric sort
    if column in ['EventID', 'PID', 'EventRecordID', 'Task', 'Version']:
         try:
             return (2, int(value))
         except (ValueError, TypeError):
             return (3, str(value).lower()) # Fallback string sort
    # Default to case-insensitive string sort
    return (3, str(value).lower())

# (Include the final versions of normalize_level, parse_timestamp,
#  parse_windows_event_xml, parse_linux_syslog_line, parse_macos_log_line
#  from the previous responses - ensuring RawXML/RawLine is included)
def normalize_level(level_str, log_format, keywords=None):
    """Maps various level representations to a standard set."""
    level_str = str(level_str).upper()
    # Default level based on numeric value or macOS text
    if log_format in ["Windows XML Event", "Windows EVTX"]:
        level_map = {'0': 'AUDIT/INFO', '1': 'CRITICAL', '2': 'ERROR', '3': 'WARNING', '4': 'INFO', '5': 'VERBOSE'}
        norm_level = level_map.get(level_str, 'UNKNOWN')
    elif log_format == "macOS Log Show":
        if level_str in ['DEFAULT', 'INFO', 'DEBUG', 'NOTICE', 'WARNING', 'ERROR', 'CRITICAL', 'FAULT', 'ALERT']:
             norm_level = level_str
        else:
            norm_level = 'UNKNOWN'
    elif log_format == "Linux Syslog":
        # Linux needs inference based on message content (passed as level_str here initially)
        msg_lower = level_str.lower()
        if 'error' in msg_lower or 'fail' in msg_lower: norm_level = 'ERROR'
        elif 'warn' in msg_lower: norm_level = 'WARNING'
        elif 'crit' in msg_lower or 'emerg' in msg_lower: norm_level = 'CRITICAL'
        elif 'accepted' in msg_lower or 'session opened' in msg_lower or 'session closed' in msg_lower : norm_level = 'AUDIT' # Crude audit inference
        elif 'new session' in msg_lower or 'info' in msg_lower: norm_level = 'INFO'
        elif 'debug' in msg_lower: norm_level = 'DEBUG'
        else: norm_level = 'INFO' # Default for syslog if no keywords match
    else: # Fallback for unknown formats
        norm_level = 'UNKNOWN'

    # Refinements (especially for Windows)
    rendered_level = None
    if log_format in ["Windows XML Event", "Windows EVTX"]:
        # Check if 'keywords' actually contains the RenderInfo Level text
        if isinstance(keywords, str):
            kw_upper = keywords.upper()
            # Check against known level text values
            if kw_upper in ['CRITICAL','ERROR','WARNING','INFORMATION','VERBOSE','SUCCESS','FAILURE','SUCCESS AUDIT','FAILURE AUDIT']:
                 rendered_level = kw_upper
                 # Standardize names
                 if rendered_level == 'INFORMATION': rendered_level = 'INFO'
                 if rendered_level == 'SUCCESS AUDIT': rendered_level = 'AUDIT_SUCCESS'
                 if rendered_level == 'FAILURE AUDIT': rendered_level = 'AUDIT_FAILURE'
                 # Override the numeric level if text level is more specific or available
                 norm_level = rendered_level

        # If no text level found, check if keywords is a hex bitmask for audit status
        if not rendered_level and isinstance(keywords, str) and keywords.startswith('0x'):
            try:
                kw_int = int(keywords, 0)
                # *** CORRECTED INDENTATION BELOW ***
                if kw_int & 0x8020000000000000: # Audit Success bit
                    norm_level = 'AUDIT_SUCCESS'
                elif kw_int & 0x8010000000000000: # Audit Failure bit
                    norm_level = 'AUDIT_FAILURE'
            except (ValueError, TypeError):
                pass # Ignore if keywords is not a valid hex number

        # Disambiguate Level 0 if it wasn't identified as AUDIT
        if norm_level == 'AUDIT/INFO' and 'AUDIT' not in norm_level:
            norm_level = 'INFO'

    return norm_level

def parse_timestamp(ts_str, log_format):
    if not ts_str or ts_str == 'N/A': return None
    try:
        if log_format in ["Windows XML Event", "Windows EVTX"]:
            ts_str = ts_str.replace('Z', '+00:00')
            if '.' in ts_str:
                 parts = ts_str.split('.')
                 base = parts[0]
                 frac_tz = parts[1]
                 frac = frac_tz.split('+')[0].split('-')[0]
                 tz_part = frac_tz[len(frac):]
                 frac = frac[:6]
                 ts_str = f"{base}.{frac}{tz_part}"
                 dt = datetime.fromisoformat(ts_str)
                 return dt.astimezone(timezone.utc)
            else:
                dt = datetime.fromisoformat(ts_str)
                return dt.astimezone(timezone.utc)
        elif log_format == "Linux Syslog":
            try:
                now = datetime.now()
                try:
                    dt_naive = datetime.strptime(f"{now.year} {ts_str}", "%Y %b %d %H:%M:%S")
                except ValueError:
                    dt_naive = datetime.strptime(f"{now.year} {ts_str}", "%Y %b %d %H:%M:%S.%f")
                if abs((datetime.now() - dt_naive).days) > 180:
                    if dt_naive > now:
                        dt_naive = dt_naive.replace(year=now.year - 1)
                dt_aware = dt_naive.astimezone(); return dt_aware.astimezone(timezone.utc)
            except ValueError: return None
        elif log_format == "macOS Log Show":
            try:
                dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S.%f%z")
                return dt.astimezone(timezone.utc)
            except ValueError:
                try:
                    dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S%z")
                    return dt.astimezone(timezone.utc)
                except ValueError:
                     try:
                         dt_naive = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S.%f")
                         return dt_naive.astimezone().astimezone(timezone.utc)
                     except ValueError:
                          try:
                              dt_naive = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                              return dt_naive.astimezone().astimezone(timezone.utc)
                          except ValueError:
                              return None
    except Exception:
        return None
    return None

def parse_windows_event_xml(xml_string, is_evtx=False):
    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError:
        return None

    def find_elem(parent, tag):
        ns_tag = f'.//{{http://schemas.microsoft.com/win/2004/08/events/event}}{tag}'
        elem = parent.find(ns_tag)
        return elem if elem is not None else parent.find(f'.//{tag}')

    def find_text(parent, tag, default='N/A'):
        elem = find_elem(parent, tag);
        return elem.text if elem is not None and elem.text is not None else default

    def find_attrib(parent, tag, attrib, default='N/A'):
        elem = find_elem(parent, tag);
        return elem.attrib.get(attrib) if elem is not None else default

    system = find_elem(root, 'System');
    event_data = find_elem(root, 'EventData');
    rendering_info = find_elem(root, 'RenderingInfo')
    if system is None:
        return None
    entry = {'OriginalFormat': 'Windows EVTX' if is_evtx else 'Windows XML Event'}
    entry['ProviderName'] = find_attrib(system, 'Provider', 'Name'); entry['ProviderGuid'] = find_attrib(system, 'Provider', 'Guid')
    entry['EventID'] = find_text(system, 'EventID'); entry['Version'] = find_text(system, 'Version')
    entry['LevelValue'] = find_text(system, 'Level'); entry['Task'] = find_text(system, 'Task')
    entry['Opcode'] = find_text(system, 'Opcode'); entry['Keywords'] = find_text(system, 'Keywords')
    entry['TimeCreated'] = find_attrib(system, 'TimeCreated', 'SystemTime'); entry['EventRecordID'] = find_text(system, 'EventRecordID')
    entry['CorrelationActivityID'] = find_attrib(system, 'Correlation', 'ActivityID'); entry['ExecutionProcessID'] = find_attrib(system, 'Execution', 'ProcessID')
    entry['ExecutionThreadID'] = find_attrib(system, 'Execution', 'ThreadID'); entry['Channel'] = find_text(system, 'Channel')
    entry['System'] = find_text(system, 'Computer')
    if event_data is not None:
        for data in event_data.findall('.//{*}Data'):
            name = data.attrib.get('Name');
            value = data.text
            if name and value is not None:
                col_name = name.replace(" ", "_").strip();
                entry[col_name] = value.strip()
    rendered_message = None;
    rendered_level_text = None
    if rendering_info is not None:
        rendered_message = find_text(rendering_info, 'Message', default=None);
        rendered_level_text = find_text(rendering_info, 'Level', default=None)
    entry['Timestamp'] = parse_timestamp(entry['TimeCreated'], entry['OriginalFormat']);
    entry['RawTimestamp'] = entry['TimeCreated']
    entry['Level'] = normalize_level(entry['LevelValue'], entry['OriginalFormat'], rendered_level_text or entry.get('Keywords'))
    entry['Component'] = entry['ProviderName']
    if rendered_message:
        entry['Message'] = rendered_message.strip()
    else:
        data_keys = [k for k, v in entry.items() if k.startswith('Data_') or (k not in BASE_COLUMNS and k not in ['ProviderGuid', 'LevelValue', 'Version', 'Task', 'Opcode', 'Keywords', 'TimeCreated', 'EventRecordID', 'CorrelationActivityID', 'ExecutionProcessID', 'ExecutionThreadID', 'Channel', 'RawTimestamp', 'OriginalFormat','RawXML'])]
        event_data_summary = ", ".join([f"{k}: {entry.get(k, '')}" for k in sorted(data_keys)])
        entry['Message'] = f"EvtID {entry['EventID']}: {event_data_summary}" if event_data_summary else f"EvtID {entry['EventID']}"
    entry['RawXML'] = xml_string
    return entry

def parse_linux_syslog_line(line):
    rfc3164_match = re.match(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$', line)
    if rfc3164_match:
        timestamp_str, host, process, pid, message = rfc3164_match.groups();
        log_format = "Linux Syslog"
    else:
        parts = line.split(maxsplit=4)
        if len(parts) >= 5:
            timestamp_str = " ".join(parts[:3]);
            host = parts[3];
            process_part = parts[4].split(':', 1)
            process = process_part[0].split('[')[0].strip();
            pid = None;
            message = parts[4];
            log_format = "Linux Syslog (Fallback)"
        else:
            return None
    message = message.strip();
    parsed_ts = parse_timestamp(timestamp_str, log_format);
    level = normalize_level(message, log_format)
    entry = { 'Timestamp': parsed_ts, 'RawTimestamp': timestamp_str, 'Level': level, 'System': host, 'Component': process, 'PID': pid if pid else 'N/A', 'Message': message, 'OriginalFormat': log_format, 'RawLine': line.strip(), 'EventID': 'N/A'}
    m_user = re.search(r'(?:user|for)\s+(\S+)', message, re.IGNORECASE);
    if m_user:
        entry['User'] = m_user.group(1).strip('\'"')
    m_ip = re.search(r'from\s+((?:\d{1,3}\.){3}\d{1,3})', message);
    if m_ip:
        entry['SourceIP'] = m_ip.group(1)
    m_port = re.search(r'port\s+(\d+)', message);
    if m_port:
        entry['SourcePort'] = m_port.group(1)
    return entry

def parse_macos_log_line(line):
    match = re.match(r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+(?:[+-]\d{2}:?\d{2})?)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(?:(\S+?):\s+)?(.*)$', line)
    if match:
        timestamp_str, thread, level_str, activity, pid, subsystem, message = match.groups()
        parsed_ts = parse_timestamp(timestamp_str, "macOS Log Show");
        level = normalize_level(level_str, "macOS Log Show")
        message = message.strip();
        component = subsystem if subsystem else f"PID:{pid}"
        entry = { 'Timestamp': parsed_ts, 'RawTimestamp': timestamp_str, 'Level': level, 'System': 'macOS', 'Component': component, 'PID': pid, 'ThreadID': thread, 'ActivityID': activity, 'Message': message, 'OriginalFormat': 'macOS Log Show', 'RawLine': line.strip(), 'EventID': 'N/A'}
        m_user = re.search(r'user\s+(\S+)', message, re.IGNORECASE);
        if m_user:
            entry['User'] = m_user.group(1).strip('()')
        m_net = re.search(r'network:\s+"([^"]+)"', message);
        if m_net:
            entry['NetworkName'] = m_net.group(1)
        return entry
    return None

# --- Preferences Window Class ---
class PreferencesWindow(tk.Toplevel):
    """
    A Toplevel window for managing application preferences (e.g., appearance, fonts).
    """
    def __init__(self, master, app_instance):
        """
        Initializes the Preferences window.

        Args:
            master: The parent widget (usually the main application root window).
            app_instance: The instance of the main LogViewerApp.
        """
        super().__init__(master) # Initialize the Toplevel window
        self.app = app_instance # Store reference to the main application instance

        self.title("Preferences")
        self.geometry("450x300") # Adjust size as needed
        self.resizable(False, False) # Optional: Prevent resizing

        # Make window appear on top of the main window and modal
        self.transient(master)
        self.grab_set()

        # --- Create Tabs using Notebook ---
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(pady=10, padx=10, fill="both", expand=True)

        # Create tabs (add more tabs here later if needed)
        self.create_appearance_tab()
        # self.create_other_tab() # Example for future tabs

        # --- Create Action Buttons ---
        self.create_action_buttons()

        # Center the window relative to the parent (optional)
        self.center_window(master)

    def create_appearance_tab(self):
        """Creates the widgets for the 'Appearance' tab."""
        self.appearance_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.appearance_frame, text='Appearance')

        # --- Font Settings Section ---
        font_labelframe = ttk.LabelFrame(self.appearance_frame, text="Log View Font", padding="10")
        font_labelframe.pack(fill="x", pady=5, padx=5)

        # Grid padding for consistency
        GRID_PADDING = {"padx": 5, "pady": 5, "sticky": "w"}

        # Font Family Dropdown
        ttk.Label(font_labelframe, text="Family:").grid(row=0, column=0, **GRID_PADDING)
        # Get the first font from the potentially comma-separated list in prefs
        current_families = self.app.prefs.get('Font', 'family', fallback=DEFAULT_FONT_FAMILY)
        current_family = current_families.split(',')[0].strip() # Use only the first as default selection
        self.font_family_var = tk.StringVar(value=current_family)
        available_fonts = sorted(tkFont.families()) # Get system fonts
        self.font_family_combo = ttk.Combobox(
            font_labelframe,
            textvariable=self.font_family_var,
            values=available_fonts,
            state="readonly", # Prevent typing arbitrary names
            width=25
        )
        self.font_family_combo.grid(row=0, column=1, columnspan=3, padx=5, pady=5, sticky="ew") # Span 3 columns

        # Font Size Spinbox
        ttk.Label(font_labelframe, text="Size:").grid(row=1, column=0, **GRID_PADDING)
        self.font_size_var = tk.IntVar(value=self.app.prefs.getint('Font', 'size', fallback=10))
        self.font_size_spinbox = ttk.Spinbox(
            font_labelframe,
            from_=7, to=72, # Reasonable size range
            textvariable=self.font_size_var,
            width=5
        )
        self.font_size_spinbox.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        # Font Style Checkboxes
        self.font_bold_var = tk.BooleanVar(value=self.app.prefs.getboolean('Font', 'bold', fallback=False))
        self.font_italic_var = tk.BooleanVar(value=self.app.prefs.getboolean('Font', 'italic', fallback=False))

        self.bold_check = ttk.Checkbutton(font_labelframe, text="Bold", variable=self.font_bold_var)
        self.italic_check = ttk.Checkbutton(font_labelframe, text="Italic", variable=self.font_italic_var)

        self.bold_check.grid(row=1, column=2, padx=5, pady=5, sticky="w")
        self.italic_check.grid(row=1, column=3, padx=5, pady=5, sticky="w")

        # Add Theme selection here if desired (using Radiobuttons)
        # ttk.Label(self.appearance_frame, text="Theme:").pack(pady=(10,0))
        # ... create radio buttons linked to self.app.theme_var ...

    def create_action_buttons(self):
        """Creates the OK, Cancel, Apply buttons at the bottom."""
        # Use a frame to group buttons and allow right-alignment
        button_frame = ttk.Frame(self)
        # Pack below the notebook, fill horizontally
        button_frame.pack(pady=(0, 10), padx=10, fill="x")

        # Add buttons, packing them to the right side of the button_frame
        self.apply_button = ttk.Button(button_frame, text="Apply", command=self.apply_changes)
        self.apply_button.pack(side="right", padx=(5, 0)) # Add padding only to the left

        self.ok_button = ttk.Button(button_frame, text="OK", command=self.ok_and_close)
        self.ok_button.pack(side="right", padx=5)

        self.cancel_button = ttk.Button(button_frame, text="Cancel", command=self.destroy)
        self.cancel_button.pack(side="right", padx=5)

    def apply_changes(self):
        """Applies the selected preferences without closing the window."""
        try:
            # Apply Font Settings
            new_font_family = self.font_family_var.get()
            new_font_size = self.font_size_var.get()
            new_font_bold = self.font_bold_var.get()
            new_font_italic = self.font_italic_var.get()

            # Call the main app's method to handle font application and validation
            self.app.apply_font_preferences(
                family=new_font_family,
                size=new_font_size,
                bold=new_font_bold,
                italic=new_font_italic
            )

            # Apply other settings here (e.g., theme if radio buttons were added)
            # self.app.apply_and_save_theme(self.app.theme_var.get())

            print("Preferences applied.") # Optional feedback

        except Exception as e:
             messagebox.showerror("Apply Error", f"Failed to apply preferences:\n{e}", parent=self)
             traceback.print_exc()


    def ok_and_close(self):
        """Applies changes, saves all preferences, and closes the window."""
        self.apply_changes() # Apply first
        self.app.save_preferences() # Tell main app to save all current settings
        self.destroy() # Close the preferences window

    def center_window(self, parent):
        """Centers the preference window over its parent."""
        self.update_idletasks() # Ensure window size is calculated
        parent_x = parent.winfo_rootx()
        parent_y = parent.winfo_rooty()
        parent_width = parent.winfo_width()
        parent_height = parent.winfo_height()

        my_width = self.winfo_width()
        my_height = self.winfo_height()

        x_pos = parent_x + (parent_width // 2) - (my_width // 2)
        y_pos = parent_y + (parent_height // 2) - (my_height // 2)

        # Ensure the window is not placed off-screen
        x_pos = max(0, x_pos)
        y_pos = max(0, y_pos)

        self.geometry(f"+{x_pos}+{y_pos}")

# --- Main Application Class ---
class LogViewerApp:
    def __init__(self, root): # self is defined here!
        self.root = root
        self.root.title("Ultimate Log Viewer Pro")
        self.prefs = configparser.ConfigParser() # Initialize ConfigParser for this instance

        # *** MOVED PREFERENCE LOADING AND FONT SETUP INSIDE __init__ ***
        self.load_preferences() # Now self.prefs exists

        # Get initial settings from prefs
        self.current_theme = self.prefs.get('Appearance', 'theme', fallback=DEFAULT_THEME)
        initial_width = self.prefs.getint('Window', 'width', fallback=1200)
        initial_height = self.prefs.getint('Window', 'height', fallback=750)
        self.root.geometry(f"{initial_width}x{initial_height}")

        # Apply theme based on prefs
        self.apply_theme(self.current_theme, initial_load=True)

        self.log_file_path = "";
        self.current_log_format = None
        self.all_log_entries = [];
        self.displayed_log_entries = []
        self.all_found_fields = set(BASE_COLUMNS);
        self.available_columns = list(BASE_COLUMNS)
        self.column_visibility_vars = {};
        self.filter_widgets = {}
        # --- Sorting State ---
        self.sort_column = None
        self.sort_reverse = False

        # --- Font Setup (uses self.prefs) ---
        pref_families = self.prefs.get('Font', 'family', fallback=DEFAULT_FONT_FAMILY).split(',')
        actual_font_family = 'TkDefaultFont' # Ultimate fallback
        available_families = tkFont.families()
        for family_candidate in pref_families:
            family = family_candidate.strip() # Process family name
            if family in available_families:
                actual_font_family = family
                break # Found a preferred font, exit loop

        self.log_font = tkFont.Font(
            family=actual_font_family,
            size=self.prefs.getint('Font', 'size', fallback=10),
            weight='bold' if self.prefs.getboolean('Font', 'bold', fallback=False) else 'normal',
            slant='italic' if self.prefs.getboolean('Font', 'italic', fallback=False) else 'roman'
        )
        self.details_font = tkFont.Font(
             family=actual_font_family, # Use same family for details
             size=self.prefs.getint('Font', 'size', fallback=10), # Use same size
             weight='normal', # Details often better non-bold
             slant='roman'
        )
        # --- End of Moved Block ---

        # Initialize other instance variables
        self.log_file_path = "";
        self.current_log_format = None
        self.all_log_entries = [];
        self.displayed_log_entries = []
        self.all_found_fields = set(BASE_COLUMNS);
        self.available_columns = list(BASE_COLUMNS)
        self.column_visibility_vars = {}
        self.filter_widgets = {}
        self.level_colors = self.get_level_colors(self.current_theme)

        # --- UI Creation ---
        self.create_menus()
        self.create_widgets()
        self.update_filter_ui(None)
        self.apply_font_to_widgets() # Apply initial font
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        # Inside LogViewerApp.__init__(self, root), add this AT THE END:
        print(f"DEBUG: End of __init__: type(self.sort_column) = {type(self.sort_column)}, callable = {callable(getattr(self, 'sort_column', None))}")

    # --- Preference Handling ---
    def load_preferences(self):
        # ... (rest of the load_preferences method) ...
        os.makedirs(PREFS_DIR, exist_ok=True); self.prefs.read(CONFIG_FILE)
        if 'Appearance' not in self.prefs: self.prefs['Appearance'] = {}
        if 'Font' not in self.prefs: self.prefs['Font'] = {}
        if 'Window' not in self.prefs: self.prefs['Window'] = {}
        if 'family' not in self.prefs['Font']: self.prefs['Font']['family'] = DEFAULT_FONT_FAMILY

    # --- Sorting Logic ---
    def _get_sort_key(self, entry, column):
        """Generates a key suitable for sorting based on column type."""
        value = entry.get(column)

        # 1. Handle None values consistently (e.g., treat as lowest)
        if value is None:
            return (0, '') # Sort Nones first

        # 2. Handle specific types
        if isinstance(value, datetime):
            return (1, value) # Sort datetimes after None, using the object itself
        # Treat common ID/numeric fields as numbers if possible
        if column in ['EventID', 'PID', 'EventRecordID', 'Task', 'Version']:
            try:
                # Attempt integer conversion for numeric sorting
                return (2, int(value)) # Sort numbers after datetimes
            except (ValueError, TypeError):
                # If conversion fails, treat as string (but sort after numbers)
                return (3, str(value).lower())
        # 3. Default to case-insensitive string comparison
        return (3, str(value).lower()) # Sort strings last

    def _perform_sort(self, data_list, column, reverse):
        """Sorts the provided list in-place using the generated sort key."""
        try:
            data_list.sort(key=lambda entry: self._get_sort_key(entry, column), reverse=reverse)
        except Exception as e:
            print(f"Error during sort: {e}")
            # Optionally show a message box, but might be annoying if sorting fails often
            messagebox.showerror("Sort Error", f"Could not sort by column '{column}':\n{e}")

    def reset_sort_indicators(self):
        """Removes sort indicators from all column headings."""
        # Check if tree exists before proceeding
        if not hasattr(self, 'tree') or not self.tree.winfo_exists():
            return
        for col in self.tree['columns']:
            try:
                current_text = self.tree.heading(col, 'text')
                # Ensure current_text is a string before replace
                if isinstance(current_text, str):
                    new_text = current_text.replace(SORT_INDICATOR_ASC, "").replace(SORT_INDICATOR_DESC, "")
                    self.tree.heading(col, text=new_text)
            except tk.TclError: # Handle cases where heading might not exist temporarily
                pass

    def sort_column(self, col):
        """Callback for Treeview heading click to sort data."""
        print(f"DEBUG: sort_column called for '{col}'")
        messagebox.showinfo("Sort Clicked", f"Sort requested for column: {col}\n(Full sort logic temporarily disabled)")
        if not self.displayed_log_entries:
            print(f"DEBUG: No displayed entries to sort.")
            return # Nothing to sort

        reverse=False
        # Determine sort order
        if self.sort_column == col:
            # If clicking the same column, reverse the order
            reverse = not self.sort_reverse
            print(f"DEBUG: Reversing sort order for '{col}'. New reverse={reverse}")
        else:
            # Clicking a new column, sort ascending
            reverse = False
            print(f"DEBUG: Sorting new column '{col}' ascending.")
        # Remove indicators from previous column
        self.reset_sort_indicators()
        
        # Store new sort state
        self.sort_column = col
        self.sort_reverse = reverse
        
        # Add indicator to current column
        indicator = SORT_INDICATOR_DESC if reverse else SORT_INDICATOR_ASC
        try: # Add try-except for safety when modifying heading
            if col in self.tree['columns']:
                self.tree.heading(col, text=col + indicator)
            else:
                print(f"Warning: Column '{col}' not found in tree columns during sort indicator update.")
        except tk.TclError:
            print(f"Warning: Could not update heading text for column '{col}' during sort.")

        # Perform the sort on the *currently displayed* data
        print(f"DEBUG: Performing sort on {len(self.displayed_log_entries)} entries...")
        self._perform_sort(self.displayed_log_entries, col, reverse)

        # Redisplay the sorted data
        print("DEBUG: Redisplaying sorted logs...")
        self.display_logs(self.displayed_log_entries)
        print("DEBUG: Sorting complete.")

    # ... (rest of the LogViewerApp class methods: save_preferences, on_closing, apply_theme, etc.) ...
    def save_preferences(self):
        try:
            os.makedirs(PREFS_DIR, exist_ok=True);
            self.prefs['Appearance']['theme'] = self.current_theme
            self.prefs['Font']['family'] = self.prefs.get('Font', 'family', fallback=DEFAULT_FONT_FAMILY) # Save pref list
            self.prefs['Font']['size'] = str(self.log_font.cget('size'));
            self.prefs['Font']['bold'] = str(self.log_font.cget('weight') == 'bold');
            self.prefs['Font']['italic'] = str(self.log_font.cget('slant') == 'italic')
            if self.root.winfo_exists():
                self.prefs['Window']['width'] = str(self.root.winfo_width());
                self.prefs['Window']['height'] = str(self.root.winfo_height())
            with open(CONFIG_FILE, 'w') as configfile: self.prefs.write(configfile)
        except Exception as e:
            print(f"Error saving preferences: {e}")

    def on_closing(self):
        self.save_preferences(); self.root.destroy()

    # --- Theme & Appearance ---
    def apply_theme(self, theme_name, initial_load=False):
         if SVTTK_AVAILABLE:
             try:
                 sv_ttk.set_theme(theme_name)
             except Exception as e:
                 print(f"Failed to set sv_ttk theme '{theme_name}': {e}");
                 return
         else:
             style = ttk.Style();
             bg = "#F0F0F0" if theme_name == "light" else "#333333";
             fg = "black" if theme_name == "light" else "white"
             try:
                 style.configure(".", background=bg, foreground=fg);
                 style.configure("Treeview", background=bg, foreground=fg, fieldbackground=bg);
                 style.map("Treeview", background=[('selected', style.lookup('TCombobox', 'selectbackground'))])
             except tk.TclError:
                 pass
         self.current_theme = theme_name;
         self.level_colors = self.get_level_colors(self.current_theme);
         self.configure_level_tags()

    def get_level_colors(self, theme):
        if theme == "dark":
            return { 'ERROR': ('#FF6B6B', 'white'), 'CRITICAL': ('#FF4D4D', 'white'), 'AUDIT_FAILURE': ('#FFA07A', 'black'), 'WARNING': ('#FFD700', 'black'), 'INFO': (None, None), 'AUDIT_SUCCESS': ('#90EE90', 'black'), 'DEBUG': ('#808080', 'white'), 'VERBOSE': ('#A9A9A9', 'black'), 'DEFAULT': (None, None), 'NOTICE': (None, None), 'FAULT': ('#FF4D4D', 'white'), 'ALERT': ('#FF4D4D', 'white'), 'UNKNOWN': ('#D3D3D3', 'black') }
        else:
            return { 'ERROR': ('#FFCCCC', 'black'), 'CRITICAL': ('#FF9999', 'black'), 'AUDIT_FAILURE': ('#FFDAB9', 'black'), 'WARNING': ('#FFFACD', 'black'), 'INFO': (None, None), 'AUDIT_SUCCESS': ('#D0F0C0', 'black'), 'DEBUG': ('#E0E0E0', 'black'), 'VERBOSE': ('#F0F0F0', 'black'), 'DEFAULT': (None, None), 'NOTICE': (None, None), 'FAULT': ('#FF9999', 'black'), 'ALERT': ('#FF9999', 'black'), 'UNKNOWN': ('#F5F5F5', 'black') }

    def configure_level_tags(self):
        if hasattr(self, 'tree'):
            for level, (bg, fg) in self.level_colors.items():
                tag_name = f"level_{level.replace('_', '').lower()}";
                opts = {}
                if bg:
                    opts['background'] = bg
                if fg:
                    opts['foreground'] = fg
                self.tree.tag_configure(tag_name, **opts)

    def apply_and_save_theme(self, theme_name):
        self.apply_theme(theme_name)

    def open_preferences(self):
        PreferencesWindow(self.root, self)

    def apply_font_preferences(self, family, size, bold, italic):
        weight = 'bold' if bold else 'normal';
        slant = 'italic' if italic else 'roman'
        try:
            if family not in tkFont.families():
                raise tk.TclError(f"Font family '{family}' not found.")
            self.log_font.config(family=family, size=size, weight=weight, slant=slant)
            self.details_font.config(family=family, size=size, weight='normal', slant='roman')
            self.apply_font_to_widgets(); self.prefs['Font']['family'] = family # Store requested family
        except tk.TclError as e:
            messagebox.showerror("Font Error", f"Could not apply font '{family}' ({size}pt):\n{e}\nPlease choose an available font.")

    def apply_font_to_widgets(self):
        style = ttk.Style();
        style.configure("Treeview", font=self.log_font, rowheight=int(self.log_font.metrics("linespace")*1.5))

    
    # --- Menus ---
    def create_menus(self):
        self.menu_bar = tk.Menu(self.root);
        self.root.config(menu=self.menu_bar)
        # File Menu
        self.file_menu = tk.Menu(self.menu_bar, tearoff=0);
        self.menu_bar.add_cascade(label="File", menu=self.file_menu)
        self.file_menu.add_command(label="Open Log File...", command=self.load_log_file, accelerator="Ctrl+O")
        self.file_menu.add_separator();
        self.export_menu = tk.Menu(self.file_menu, tearoff=0);
        self.file_menu.add_cascade(label="Export", menu=self.export_menu)
        self.export_menu.add_command(label="Export Selected Rows...", command=lambda: self.export_logs(selected_only=True), state=tk.DISABLED)
        self.export_menu.add_command(label="Export All Displayed Rows...", command=lambda: self.export_logs(selected_only=False), state=tk.DISABLED)
        self.file_menu.add_separator();
        self.file_menu.add_command(label="Exit", command=self.on_closing)
        # Edit Menu
        self.edit_menu = tk.Menu(self.menu_bar, tearoff=0);
        self.menu_bar.add_cascade(label="Edit", menu=self.edit_menu)
        self.edit_menu.add_command(label="Preferences...", command=self.open_preferences)
        # View Menu
        self.view_menu = tk.Menu(self.menu_bar, tearoff=0);
        self.menu_bar.add_cascade(label="View", menu=self.view_menu)
        if SVTTK_AVAILABLE:
            self.theme_var = tk.StringVar(value=self.current_theme);
            self.view_menu.add_radiobutton(label="Light Mode", variable=self.theme_var, value="light", command=lambda: self.apply_and_save_theme("light")); self.view_menu.add_radiobutton(label="Dark Mode", variable=self.theme_var, value="dark", command=lambda: self.apply_and_save_theme("dark"))
        else:
            self.view_menu.add_command(label="Theme Switcher (Requires sv_ttk)", state=tk.DISABLED)
        self.view_menu.add_separator()
        self.columns_menu = tk.Menu(self.view_menu, tearoff=0);
        self.view_menu.add_cascade(label="Columns", menu=self.columns_menu, state=tk.DISABLED)
        # Help Menu
        self.help_menu = tk.Menu(self.menu_bar, tearoff=0);
        self.menu_bar.add_cascade(label="Help", menu=self.help_menu)
        self.help_menu.add_command(label="Usage...", command=self.show_gui_usage);
        self.help_menu.add_command(label="About...", command=self.show_about)
        # Bindings
        self.root.bind_all("<Control-o>", lambda e: self.load_log_file())

    def create_widgets(self):
        """Creates and lays out the main GUI widgets."""
        # Top Frame (Format, Open, Label)
        top_frame = ttk.Frame(self.root, padding="10");
        top_frame.pack(fill=tk.X)
        ttk.Label(top_frame, text="Log Format:").pack(side=tk.LEFT, padx=(0, 5))
        self.format_var = tk.StringVar(value=LOG_FORMATS[0]);
        formats_available = LOG_FORMATS[:];
        if not EVTX_AVAILABLE:
            formats_available.remove("Windows EVTX")
        self.format_combo = ttk.Combobox(top_frame, textvariable=self.format_var, values=formats_available, state="readonly", width=18); self.format_combo.pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(top_frame, text="Open Log File", command=self.load_log_file).pack(side=tk.LEFT, padx=(0, 10))
        self.file_path_label = ttk.Label(top_frame, text="No file loaded.");
        self.file_path_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Filter Frame
        self.filter_frame = ttk.LabelFrame(self.root, text="Filters", padding="10");
        self.filter_frame.pack(fill=tk.X, padx=10, pady=5)
        row_num = 0;
        GRID_PADDING = {"padx":5, "pady":2, "sticky":"w"}

        # -- Row 0: Static Filters (Labels AND Widgets Gridded Here Permanently) --
        # Keyword
        ttk.Label(self.filter_frame, text="Keyword:").grid(row=row_num, column=0, **GRID_PADDING)
        self.keyword_var = tk.StringVar();
        keyword_entry = ttk.Entry(self.filter_frame, textvariable=self.keyword_var, width=25)
        keyword_entry.grid(row=row_num, column=1, **GRID_PADDING)
        # Store ref to widget, None for label as it's static
        self.filter_widgets['keyword_entry'] = (None, keyword_entry)

        # Regex Checkbox
        self.regex_var = tk.BooleanVar(value=False)
        self.regex_check = ttk.Checkbutton(self.filter_frame, text="Regex", variable=self.regex_var)
        self.regex_check.grid(row=row_num, column=2, padx=(0,5), pady=2, sticky="w")

        # Level Combobox
        ttk.Label(self.filter_frame, text="Level:").grid(row=row_num, column=3, **GRID_PADDING)
        self.level_var = tk.StringVar();
        # *** Define self.level_combo HERE ***
        self.level_combo = ttk.Combobox(self.filter_frame, textvariable=self.level_var, state="readonly", width=12);
        self.level_combo['values'] = [''] # Initial empty value list
        self.level_combo.grid(row=row_num, column=4, **GRID_PADDING)
        self.level_combo.set('') # Initial empty selection
        # Store ref to widget
        self.filter_widgets['level_combo'] = (None, self.level_combo)

        # System Entry
        ttk.Label(self.filter_frame, text="System:").grid(row=row_num, column=5, **GRID_PADDING)
        self.system_var = tk.StringVar();
        system_entry = ttk.Entry(self.filter_frame, textvariable=self.system_var, width=15)
        system_entry.grid(row=row_num, column=6, **GRID_PADDING)
        self.filter_widgets['system_entry'] = (None, system_entry)

        # Component Entry
        ttk.Label(self.filter_frame, text="Component:").grid(row=row_num, column=7, **GRID_PADDING)
        self.component_var = tk.StringVar();
        component_entry = ttk.Entry(self.filter_frame, textvariable=self.component_var, width=20)
        component_entry.grid(row=row_num, column=8, **GRID_PADDING)
        self.filter_widgets['component_entry'] = (None, component_entry)

        # -- Row 1 onwards: OS Specific Filters (Define, but DON'T grid here) --
        # Store tuples as (label_widget, entry_widget, *os_tags)
        self.event_id_var = tk.StringVar();
        lbl_eid = ttk.Label(self.filter_frame, text="EventID:");
        ent_eid = ttk.Entry(self.filter_frame, textvariable=self.event_id_var, width=8);
        self.filter_widgets['event_id'] = (lbl_eid, ent_eid, 'Windows')
        self.target_user_var = tk.StringVar();
        lbl_tuser = ttk.Label(self.filter_frame, text="TargetUser:");
        ent_tuser = ttk.Entry(self.filter_frame, textvariable=self.target_user_var, width=15);
        self.filter_widgets['target_user'] = (lbl_tuser, ent_tuser, 'Windows')
        self.source_ip_var = tk.StringVar();
        lbl_sip = ttk.Label(self.filter_frame, text="Src IP:");
        ent_sip = ttk.Entry(self.filter_frame, textvariable=self.source_ip_var, width=15);
        self.filter_widgets['source_ip'] = (lbl_sip, ent_sip, 'Windows', 'Linux')
        self.pid_var = tk.StringVar();
        lbl_pid = ttk.Label(self.filter_frame, text="PID:");
        ent_pid = ttk.Entry(self.filter_frame, textvariable=self.pid_var, width=8);
        self.filter_widgets['pid'] = (lbl_pid, ent_pid, 'Linux', 'macOS')
        self.activity_id_var = tk.StringVar();
        lbl_aid = ttk.Label(self.filter_frame, text="ActivityID:");
        ent_aid = ttk.Entry(self.filter_frame, textvariable=self.activity_id_var, width=10);
        self.filter_widgets['activity_id'] = (lbl_aid, ent_aid, 'macOS')
        self.thread_id_var = tk.StringVar();
        lbl_tid = ttk.Label(self.filter_frame, text="ThreadID:");
        ent_tid = ttk.Entry(self.filter_frame, textvariable=self.thread_id_var, width=10);
        self.filter_widgets['thread_id'] = (lbl_tid, ent_tid, 'macOS')

        # -- Row 2 (or dynamic): Filter Buttons Frame (Gridded initially, repositioned later) --
        initial_button_row = 1 # Start below static filters
        self.button_frame = ttk.Frame(self.filter_frame) # Store reference
        self.button_frame.grid(row=initial_button_row, column=0, columnspan=9, pady=10, sticky=tk.W)
        self.apply_filter_button = ttk.Button(self.button_frame, text="Apply Filters", command=self.apply_filters, state=tk.DISABLED); self.apply_filter_button.pack(side=tk.LEFT, padx=5)
        self.clear_filter_button = ttk.Button(self.button_frame, text="Clear Filters", command=self.clear_filters, state=tk.DISABLED); self.clear_filter_button.pack(side=tk.LEFT, padx=5)

        # --- Log Display Frame / Status Bar / etc. ---
        log_frame = ttk.Frame(self.root, padding="10");
        log_frame.pack(fill=tk.BOTH, expand=True)
        self.tree = ttk.Treeview(log_frame, columns=BASE_COLUMNS, show='headings', selectmode='extended');
        self.update_treeview_columns(list(BASE_COLUMNS))
        vsb = ttk.Scrollbar(log_frame, orient="vertical", command=self.tree.yview);
        vsb.pack(side='right', fill='y');
        hsb = ttk.Scrollbar(log_frame, orient="horizontal", command=self.tree.xview);
        hsb.pack(side='bottom', fill='x')
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set);
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<Double-1>", self.show_log_details);
        self.tree.bind("<<TreeviewSelect>>", self.update_status_and_menu)
        self.tree.bind("<Button-3>", self.show_context_menu)
        self.configure_level_tags()
        status_frame = ttk.Frame(self.root);
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        self.progress_bar = ttk.Progressbar(status_frame, orient='horizontal', mode='determinate');
        self.progress_bar.pack(fill=tk.X, padx=5, pady=(0,2), side=tk.BOTTOM);
        self.progress_bar.pack_forget()
        self.status_bar = ttk.Label(status_frame, relief=tk.SUNKEN, anchor=tk.W, padding="2 5");
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_var = tk.StringVar(); self.status_bar.config(textvariable=self.status_var);
        self.status_var.set("Ready. Select log format and open a file.")
        
    # --- Context Menu (Right Click) ---
    def show_context_menu(self, event):
        """Displays the right-click context menu on the Treeview."""
        selection = self.tree.selection()
        if not selection: return # Only show if an item is selected

        context_menu = tk.Menu(self.root, tearoff=0)
        context_menu.add_command(label="Copy Row Data (TSV)", command=self.copy_selected_row)
        # Add more options here later if needed (e.g., Copy Cell, Filter on Value)

        # Display the menu at the cursor's position
        context_menu.tk_popup(event.x_root, event.y_root)

    def copy_selected_row(self):
        """Copies the visible data of the first selected row to the clipboard."""
        selection = self.tree.selection()
        if not selection: return
        item_iid = selection[0] # Get the IID of the first selected item

        try:
            item_data = self.tree.item(item_iid)
            visible_columns = self.tree['displaycolumns']
            if visible_columns == ('',): # Handle case where displaycolumns might be empty tuple
                 visible_columns = self.tree['columns']

            # Get data only for visible columns
            row_values = []
            original_values = item_data['values']
            all_columns = self.tree['columns']

            for col_id in visible_columns:
                try:
                    # Find the index of the visible column in the full column list
                    idx = all_columns.index(col_id)
                    row_values.append(str(original_values[idx]))
                except (ValueError, IndexError):
                    row_values.append("") # Append empty string if column not found or index error

            # Join with tabs (TSV - Tab Separated Values)
            clipboard_text = "\t".join(row_values)

            self.root.clipboard_clear()
            self.root.clipboard_append(clipboard_text)
            self.status_var.set("Row data copied to clipboard.")
        except Exception as e:
            self.status_var.set("Failed to copy row data.")
            print(f"Error copying row: {e}")

    # --- Core Logic (Loading, Displaying, Filtering, Exporting, Details) ---
    def update_status_and_menu(self, event=None):
        self.update_status_bar();
        self.update_export_menu_state()

    def update_export_menu_state(self, event=None):
        has_displayed = bool(self.displayed_log_entries);
        has_selection = bool(self.tree.selection())
        try:
            self.export_menu.entryconfig("Export Selected Rows...", state=tk.NORMAL if has_selection else tk.DISABLED); self.export_menu.entryconfig("Export All Displayed Rows...", state=tk.NORMAL if has_displayed else tk.DISABLED)
        except tk.TclError:
            pass # Menu might not exist yet

    def update_status_bar(self):
        """Updates the status bar with Total, Displayed, and Selected counts."""
        total = len(self.all_log_entries)
        shown = len(self.displayed_log_entries)
        selected_count = len(self.tree.selection())

        # Build the status message string
        status_msg = f"Total: {total} | Displayed: {shown}"
        if shown < total: # Add '(Filtered)' only if filtering is active
            status_msg += " (Filtered)"
        if selected_count > 0: # Add selection count if items are selected
            status_msg += f" | Selected: {selected_count}"

        self.status_var.set(status_msg)

    def update_filter_ui(self, log_format):
        """Shows/hides OS-specific filters based on the loaded format and repositions buttons."""
        GRID_PADDING = {"padx": 5, "pady": 2, "sticky": "w"}
        # --- Grid/Forget OS-Specific Filters ---
        current_col_os = 0
        current_row_os = 1 # Start OS filters on row 1 (below static filters on row 0)
        max_cols_os = 9    # Max widgets (label+entry pairs) per row

        for name, widget_data in self.filter_widgets.items():
            # Skip the basic filters - they are handled in create_widgets
            if name in ['keyword_entry', 'level_combo', 'system_entry', 'component_entry']:
                continue

            if len(widget_data) > 2: # Check if it's an OS-specific filter tuple (label, entry, *tags)
                label, entry, *os_tags = widget_data
                show_widget = False
                if log_format and any(tag.lower() in log_format.lower() for tag in os_tags):
                    show_widget = True

                if show_widget:
                    # Grid both label and entry if they should be visible
                    label.grid(row=current_row_os, column=current_col_os, **GRID_PADDING)
                    entry.grid(row=current_row_os, column=current_col_os + 1, **GRID_PADDING)
                    current_col_os += 2 # Move to next position for label+entry pair
                    # Check if we need to wrap to the next row
                    if current_col_os >= max_cols_os:
                        current_col_os = 0 # Reset column index
                        current_row_os += 1 # Move to next row
                else:
                    # Forget (hide) both label and entry if not applicable
                    label.grid_forget()
                    entry.grid_forget()

        # --- Reposition Button Frame ---
        # Calculate the row number below the last OS filter row
        button_row = current_row_os if current_col_os == 0 else current_row_os + 1

        # Explicitly re-grid the button frame to the calculated row
        if hasattr(self, 'button_frame'): # Ensure button frame exists
             self.button_frame.grid(row=button_row, column=0, columnspan=max_cols_os, pady=10, sticky=tk.W)
        else:
             print("Warning: Could not find button frame to reposition.")
             
    def detect_log_format(self, file_path):
        """
        Detects log format based on file extension and content analysis of the first few lines.
        Returns the format name string (e.g., "Windows EVTX") or None if detection fails.
        """
        # --- Step 1: Check file extension first (quickest check) ---
        try:
            _, ext = os.path.splitext(file_path)
            ext = ext.lower()
        except Exception: # Handle potential errors with path splitting
             ext = ""

        if ext == '.evtx':
            # If it's an EVTX file, we rely solely on the extension (and library availability)
            # Content analysis of binary EVTX is not feasible here.
            return "Windows EVTX" if EVTX_AVAILABLE else None

        # --- Step 2: Content analysis for text-based formats ---
        first_lines = []
        try:
            # Read the first ~10 lines for content sniffing
            # Use 'utf-8' with error handling for broader compatibility
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for _ in range(10):
                    line = f.readline()
                    if not line: # Stop if EOF is reached early
                        break
                    first_lines.append(line)

            if not first_lines:
                # File is empty or couldn't be read
                return None

            # Combine lines for easier searching, convert to lowercase
            content_sample = "".join(first_lines).lower()

            # --- Check for Windows XML Event Log signature ---
            # Look for the specific XML namespace declaration
            if '<event ' in content_sample and \
               ('xmlns="http://schemas.microsoft.com/win/2004/08/events/event"' in content_sample or \
                'xmlns=\'http://schemas.microsoft.com/win/2004/08/events/event\'' in content_sample):
                return "Windows XML Event"

            # --- Check for macOS Unified Log (log show output) pattern ---
            # Pattern: YYYY-MM-DD HH:MM:SS.ffffff+/-ZZZZ ThreadID Type ActivityID PID ...
            # Relaxed the PID part slightly from previous versions
            macos_pattern = r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+(?:[+-]\d{2}:?\d{2})?\s+0x[0-9a-f]+\s+\S+\s+0x[0-9a-f]+\s+\d+'
            # Check if *any* of the first lines match the pattern
            if any(re.search(macos_pattern, line, re.IGNORECASE) for line in first_lines if line.strip()):
                return "macOS Log Show"

            # --- Check for common Linux Syslog (RFC3164) pattern ---
            # Pattern: MMM DD HH:MM:SS hostname process[pid]: message
            syslog_pattern = r'^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+?(?:\[\d+\])?:\s+'
             # Check if *any* of the first lines match the pattern at the beginning
            if any(re.match(syslog_pattern, line, re.IGNORECASE) for line in first_lines if line.strip()):
                return "Linux Syslog"

            # Add checks for other specific formats here if needed

        except FileNotFoundError:
             print(f"Warning: File not found during format detection: {file_path}")
             return None # File doesn't exist
        except IOError as e:
             print(f"Warning: Could not read file for format detection: {file_path} ({e})")
             return None # Permission error, etc.
        except Exception as e:
             # Catch other potential errors (e.g., regex compilation on weird patterns)
             print(f"Warning: Error during format detection: {e}")
             # Pass and return None below

        # --- Step 3: Fallback ---
        # If none of the specific patterns matched
        return None

    def _heading_click_command(col_name):
        print(col_name)
        self.sort_column(col_name)
        
    def update_treeview_columns(self, column_names):
        """ Reconfigures the treeview with the given column names and properties. """
        self.tree.delete(*self.tree.get_children()) # Clear existing items first
        self.tree['columns'] = tuple(column_names)
        # Ensure displaycolumns is set, even if empty initially (avoids potential Tcl errors)
        self.tree['displaycolumns'] = tuple(column_names) if column_names else ()
        for col in column_names:
            # Set heading first
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_column(c))

            # --- CORRECTED: Set default properties clearly ---
            width = 150         # Default width
            anchor = tk.W       # Default anchor (West/Left)
            stretch = False     # Default no stretch

            # --- CORRECTED: Use standard if/elif structure ---
            if col == 'Timestamp':
                width = 170
            elif col == 'Level':
                width = 100
                anchor = tk.CENTER
            elif col == 'System':
                width = 120
            elif col == 'Component':
                width = 150
            elif col == 'EventID':
                width = 70
                anchor = tk.CENTER
            elif col == 'PID':
                width = 60
                anchor = tk.CENTER
            elif col == 'Message':
                width = 400
                stretch = True # Allow Message column to stretch
            elif 'IP' in col: # Heuristic for IP address columns
                width = 120
            elif 'User' in col: # Heuristic for User columns
                width = 100
            elif 'ID' in col and col != 'EventID' and col != 'PID': # Other ID columns
                width = 80
                anchor = tk.CENTER
            # Add more elif conditions for other specific columns if needed

            # Apply the determined properties to the column
            self.tree.column(col, width=width, anchor=anchor, stretch=stretch)

    def populate_columns_menu(self):
        """
        Clears and populates the View->Columns menu with checkbuttons
        for all currently available columns found in the loaded log file.
        """
        # Clear existing menu items first
        self.columns_menu.delete(0, tk.END)
        # Clear the dictionary holding the Tkinter variables for checkboxes
        self.column_visibility_vars.clear()

        # Check if any columns were actually found/defined
        if not self.available_columns:
             # If no columns available (e.g., error during load), disable the menu
             self.view_menu.entryconfig("Columns", state=tk.DISABLED)
             return

        # Create a checkbutton for each available column
        for col_name in self.available_columns:
             # Create a Tkinter BooleanVar for this column's visibility state
             # Initialize it to True (visible by default)
             var = tk.BooleanVar(value=True)
             # Store the variable, keyed by column name, for later access
             self.column_visibility_vars[col_name] = var
             # Add the checkbutton to the menu
             self.columns_menu.add_checkbutton(
                 label=col_name,        # Text displayed on the menu item
                 variable=var,          # Link the checkbox state to this variable
                 command=self.update_displayed_columns # Call this when checked/unchecked
             )

        # Enable the "Columns" cascade menu now that it's populated
        self.view_menu.entryconfig("Columns", state=tk.NORMAL)

    def update_displayed_columns(self):
        """
        Updates the visible columns in the Treeview based on the current
        state of the checkbuttons in the View->Columns menu.
        Ensures at least one column remains visible.
        """
        # Build a list of column names where the corresponding BooleanVar is True
        visible_columns = [
            col for col, var in self.column_visibility_vars.items() if var.get()
        ]

        # --- Ensure at least one column is always visible ---
        if not visible_columns:
            # If the user unchecked everything, force at least one column back on
            if 'Timestamp' in self.column_visibility_vars:
                 # Prefer 'Timestamp' if it exists
                 self.column_visibility_vars['Timestamp'].set(True)
                 visible_columns = ['Timestamp']
                 messagebox.showinfo("Column Visibility", "At least one column must be visible. Showing 'Timestamp'.")
            elif self.available_columns:
                 # Otherwise, show the very first available column
                 first_col = self.available_columns[0]
                 if first_col in self.column_visibility_vars:
                     self.column_visibility_vars[first_col].set(True)
                     visible_columns = [first_col]
                     messagebox.showinfo("Column Visibility", f"At least one column must be visible. Showing '{first_col}'.")
                 else:
                     # This case should ideally not happen if available_columns is synced
                     print("Error: Cannot enforce minimum column visibility.")
                     return # Cannot proceed
            else:
                 # No columns available at all? Very unlikely if menu was populated.
                 print("Warning: No available columns to display.")
                 return # Cannot proceed

        # --- Update the Treeview's displaycolumns property ---
        # This tuple tells the Treeview which columns from its 'columns' list to actually render
        try:
            self.tree['displaycolumns'] = tuple(visible_columns)
        except tk.TclError as e:
             print(f"Error setting displaycolumns: {e}")
             # This might happen if the Treeview widget state is inconsistent

    def load_log_file(self):
        path = filedialog.askopenfilename( title="Select Log File", filetypes=(("Log files", "*.log *.xml *.txt *.evtx"), ("All files", "*.*")))
        if not path: return
        # Format detection/validation
        selected_format_req = self.format_var.get();
        detected_format = self.detect_log_format(path);
        log_format_to_use = None
        if selected_format_req == "Auto-Detect":
            if detected_format:
                log_format_to_use = detected_format;
                self.format_var.set(detected_format)
            else:
                messagebox.showwarning("Detection Failed", "Could not auto-detect log format."); return
        else:
            if selected_format_req == "Windows EVTX" and not path.lower().endswith(".evtx"):
                 if not messagebox.askyesno("Format Mismatch?", f"Selected EVTX, but file is '{os.path.basename(path)}'. Continue?"):
                    return
            log_format_to_use = selected_format_req
        if log_format_to_use == "Windows EVTX" and not EVTX_AVAILABLE:
            messagebox.showerror("Dependency Missing", "Cannot parse EVTX files. Install 'python-evtx'.");
            return
        if not log_format_to_use:
            messagebox.showerror("Error", "Log format not determined or unsupported.");
            return

        self.log_file_path = path;
        self.current_log_format = log_format_to_use
        self.file_path_label.config(text=f"File: {os.path.basename(path)} ({self.current_log_format})")
        self.status_var.set(f"Analyzing {os.path.basename(path)}...");
        self.root.update_idletasks()
        self.all_log_entries = [];
        self.displayed_log_entries = [];
        self.all_found_fields = set(BASE_COLUMNS)
        self.clear_filters(clear_ui_only=True)

        # --- Progress Bar Setup ---
        self.progress_bar.pack(fill=tk.X, padx=5, pady=(0,2), side=tk.BOTTOM) # Show progress bar
        self.progress_bar['value'] = 0
        self.progress_bar['maximum'] = 100 # Percentage based

        parsing_errors = 0
        processed_lines_or_records = 0
        try:
            file_size = os.path.getsize(path) if os.path.exists(path) else 0 # Get file size for progress

            # --- Parsing Logic with Progress Update ---
            # Inside load_log_file method:
            # --- Parsing Logic with Progress Update ---
            update_interval = 500 # Update progress bar/status every N lines/records

            if self.current_log_format == "Windows EVTX":
                # --- CORRECTED EVTX Handling ---
                # Remove pre-counting and seek
                # Use indeterminate progress or just status updates
                self.progress_bar['mode'] = 'indeterminate' # Show moving bar
                self.progress_bar.start(10) # Start animation (interval in ms)

                with evtx.Evtx(self.log_file_path) as log:
                    for i, record in enumerate(log.records()): # Iterate directly
                        try:
                            parsed = parse_windows_event_xml(record.xml(), is_evtx=True)
                        except Exception as xml_err:
                            # Handle potential errors getting XML from record
                            # print(f"Warning: Could not get XML for EVTX record {i}: {xml_err}")
                            parsed = None
                            parsing_errors += 1 # Count as error if XML fails

                        if parsed:
                            self.all_log_entries.append(parsed)
                            self.all_found_fields.update(parsed.keys())
                        # Don't increment parsing_errors if parse_windows_event_xml returns None,
                        # as that function handles internal XML parse errors. Only count if record.xml() fails.

                        processed_lines_or_records += 1
                        if i % update_interval == 0 and i > 0: # Update status periodically
                             self.status_var.set(f"Loading... Processed {i} EVTX records")
                             self.root.update_idletasks() # Keep GUI responsive

                self.progress_bar.stop() # Stop animation
                self.progress_bar['mode'] = 'determinate' # Reset mode

            # --- Text-based formats (XML, Syslog, macOS) ---
            elif self.current_log_format in ["Windows XML Event", "Linux Syslog", "macOS Log Show"]:
                # Use determinate progress based on file size
                self.progress_bar['mode'] = 'determinate'
                file_size = os.path.getsize(path) if os.path.exists(path) else 0
                self.progress_bar['maximum'] = 100 # Use percentage

                if self.current_log_format == "Windows XML Event":
                    # Read all for splitting, estimate progress based on events processed
                    with open(self.log_file_path, 'r', encoding='utf-8', errors='ignore') as f: xml_content = f.read()
                    event_texts = re.split(r'(?=<Event[\s>])', xml_content)
                    total_events = len([t for t in event_texts if t.strip().startswith('<Event')]) # Estimate total
                    current_event_num = 0
                    for event_text in event_texts:
                       if event_text.strip().startswith('<Event'):
                            current_event_num += 1
                            parsed = parse_windows_event_xml(event_text, is_evtx=False)
                            if parsed:
                                self.all_log_entries.append(parsed);
                                self.all_found_fields.update(parsed.keys())
                            else:
                                parsing_errors += 1
                            if current_event_num % update_interval == 0 and total_events > 0:
                                 progress = (current_event_num / total_events) * 100
                                 self.progress_bar['value'] = progress
                                 self.status_var.set(f"Loading... {int(progress)}% ({current_event_num}/{total_events} events)")
                                 self.root.update_idletasks()
                else: # Linux Syslog or macOS Log Show
                    with open(self.log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for i, line in enumerate(f):
                            if self.current_log_format == "macOS Log Show" and (line.strip().startswith("Timestamp") or not line.strip()):
                                continue
                            parsed = parse_linux_syslog_line(line) if self.current_log_format == "Linux Syslog" else parse_macos_log_line(line)
                            if parsed:
                                self.all_log_entries.append(parsed);
                                self.all_found_fields.update(parsed.keys())
                            processed_lines_or_records += 1
                            if i % update_interval == 0 and file_size > 0:
                                 progress = (f.tell() / file_size) * 100
                                 self.progress_bar['value'] = progress
                                 self.status_var.set(f"Loading... {int(progress)}% ({i+1} lines)")
                                 self.root.update_idletasks()


            # --- Post Load ---
            self.progress_bar.pack_forget() # Hide progress bar
            # ... (rest of post-load logic remains the same) ...
            status_msg = f"Loaded {len(self.all_log_entries)} entries."
            if parsing_errors > 0: status_msg += f" ({parsing_errors} parsing errors)"
            self.status_var.set(status_msg)
            # (Rest of post-load logic: columns, menus, display)
            self.available_columns = [col for col in BASE_COLUMNS if col in self.all_found_fields]
            other_columns = sorted([f for f in self.all_found_fields if f not in BASE_COLUMNS and f not in ['RawLine', 'RawXML', 'RawTimestamp']])
            self.available_columns.extend(other_columns)
            self.update_treeview_columns(self.available_columns)
            self.populate_columns_menu()
            self.update_displayed_columns()
            self.display_logs(self.all_log_entries)
            unique_levels = sorted(list(set(entry.get('Level', 'N/A') for entry in self.all_log_entries)))
            self.level_combo['values'] = [''] + unique_levels
            self.update_filter_ui(self.current_log_format)
            self.update_status_and_menu()
            if self.all_log_entries:
                self.apply_filter_button.config(state=tk.NORMAL)
                self.clear_filter_button.config(state=tk.NORMAL)
            else:
                self.apply_filter_button.config(state=tk.DISABLED)
                self.clear_filter_button.config(state=tk.DISABLED)

        except FileNotFoundError:
            messagebox.showerror("Error", f"File not found: {self.log_file_path}");
            self.status_var.set("Error loading file.");
            self.file_path_label.config(text="No file loaded.");
            self.progress_bar.pack_forget()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read or parse file:\n{e}");
            self.status_var.set(f"Critical error: {e}");
            self.file_path_label.config(text="No file loaded.");
            traceback.print_exc();
            self.progress_bar.pack_forget()

    def display_logs(self, log_entries_to_display):
        """ Populates the treeview with the given list AND updates self.displayed_log_entries """
        try:
            self.tree.delete(*self.tree.get_children()) # Clear existing items first
            # Make sure columns are valid before proceeding
            current_columns = self.tree['columns']
            if not isinstance(current_columns, (list, tuple)) or not current_columns:
                 print("Warning: Treeview columns are not properly set.")
                 # Handle error state? Maybe return or use default columns?
                 # For now, just prevent iterating if columns are bad.
                 # If available_columns exists, maybe reset to that?
                 # if hasattr(self, 'available_columns') and self.available_columns:
                 #    current_columns = tuple(self.available_columns)
                 #    self.tree['columns'] = current_columns
                 # else:
                 current_columns = () # Set to empty tuple to avoid error below

            self.displayed_log_entries = log_entries_to_display # Update the internal list

            for i, entry in enumerate(self.displayed_log_entries):
                values_tuple = [] # Initialize list for this row's values
                try:
                    # Get the level for color tagging
                    level = entry.get('Level', 'UNKNOWN')
                    # Ensure level is a string before replace (handles potential non-string values)
                    tag_name = f"level_{str(level).replace('_', '').lower()}"

                    # Iterate through the columns the Treeview expects
                    for col_name in current_columns:
                        raw_value = entry.get(col_name, '') # Get value safely

                        # Format the value nicely for display
                        if isinstance(raw_value, datetime):
                            try:
                                # Format timezone-aware datetime to ISO UTC string
                                display_val = raw_value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " Z"
                            except (ValueError, TypeError): # Catch specific errors for datetime formatting
                                display_val = str(raw_value) # Fallback to simple string representation
                        elif raw_value is None:
                            display_val = '' # Display None as empty string
                        else:
                            display_val = str(raw_value) # Convert other types to string

                        values_tuple.append(display_val) # Add formatted value

                    # Insert the row into the Treeview
                    self.tree.insert('', tk.END, iid=i, values=tuple(values_tuple), tags=(tag_name,))

                except Exception as e:
                    # Print error if processing/inserting a specific row fails
                    print(f"Error processing/inserting row {i} into treeview: {e}")
                    # traceback.print_exc() # Uncomment for more detail during debugging

            # Update status bar and menus after populating
            self.update_status_and_menu()

        except tk.TclError as e:
             print(f"Error during Treeview operation in display_logs: {e}")
             # This might happen if the treeview widget is destroyed or columns mismatch badly
        except Exception as e:
             print(f"Unexpected error in display_logs: {e}")
             traceback.print_exc() # Print full traceback for unexpected errors


    def show_log_details(self, event):
        """Callback for double-click. Shows log details in a new window."""
        try:
            selection = self.tree.selection()
            if not selection:
                # No item selected, do nothing
                return

            selected_item_iid_str = selection[0] # Get the IID of the clicked item

            # Convert IID (which is the index in displayed_log_entries) to integer
            # and retrieve the corresponding log entry dictionary
            item_index = int(selected_item_iid_str)
            if 0 <= item_index < len(self.displayed_log_entries):
                log_entry = self.displayed_log_entries[item_index] # Get the full data dict
            else:
                 print(f"Error: Invalid item index {item_index} retrieved from selection.")
                 return # Invalid index

            # --- Create Details Window ---
            details_window = tk.Toplevel(self.root)
            # Try to make title more informative using EventRecordID or index
            record_id = log_entry.get('EventRecordID')
            title_id = record_id if record_id and record_id != 'N/A' else f"Index {item_index}"
            details_window.title(f"Log Details ({title_id})")
            details_window.geometry("700x500")
            details_window.transient(self.root) # Associate with main window
            # details_window.grab_set() # Optional: Makes the window modal

            # Use ScrolledText for better handling of long content and copying
            details_text = scrolledtext.ScrolledText(
                details_window,
                wrap=tk.WORD,
                height=20,
                width=80,
                font=self.details_font # Apply the configured details font
            )
            details_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

            # Populate the text area
            details_text.config(state=tk.NORMAL) # Enable editing to insert text
            details_text.delete('1.0', tk.END) # Clear previous content (if any)

            # Define preferred order for displaying fields
            display_order = [
                'Timestamp', 'Level', 'System', 'Component', 'EventID',
                'Message', 'RawTimestamp', 'OriginalFormat', 'Channel',
                'ProviderName', 'Task', 'Keywords', 'EventRecordID'
            ]
            # Get keys in preferred order + remaining keys sorted alphabetically
            # Exclude raw data fields which are handled separately
            sorted_keys = [k for k in display_order if k in log_entry] + \
                          sorted([k for k in log_entry if k not in display_order and k not in ['RawXML', 'RawLine']])

            # Insert formatted key-value pairs
            for key in sorted_keys:
                value = log_entry.get(key, 'N/A') # Default to 'N/A' if key missing

                # Format datetime objects nicely
                if isinstance(value, datetime):
                     try:
                         formatted_value = value.astimezone(timezone.utc).isoformat()
                     except (ValueError, TypeError): # Handle potential errors with naive datetimes etc.
                         formatted_value = str(value)
                elif value is None:
                     formatted_value = "<None>" # Explicitly show None
                else:
                     formatted_value = str(value) # Convert others to string

                details_text.insert(tk.END, f"{key}:\n", ('field_name',)) # Tag for styling field name
                details_text.insert(tk.END, f"  {formatted_value}\n\n") # Indent value

            # Add Raw XML or Raw Line if available, at the end
            raw_data = log_entry.get('RawXML') or log_entry.get('RawLine')
            if raw_data:
                details_text.insert(tk.END, "--- Raw Data ---\n", ('field_name',))
                details_text.insert(tk.END, raw_data)

            # Configure tags (use details font for boldness)
            details_text.tag_configure('field_name', font=(self.details_font.cget('family'), self.details_font.cget('size'), 'bold'))

            # Make the text area read-only again
            details_text.config(state=tk.DISABLED)

            # Add a close button
            close_button = ttk.Button(details_window, text="Close", command=details_window.destroy)
            close_button.pack(pady=5)

        except (ValueError, IndexError) as e:
            # Error converting IID or accessing displayed_log_entries
            print(f"Error retrieving log entry for details view: {e}")
            # Optionally show a message box to the user
            # messagebox.showerror("Details Error", f"Could not retrieve log details:\n{e}")
        except tk.TclError as e:
             # Error related to Tkinter widgets (e.g., window destroyed)
             print(f"Error creating details window: {e}")
        except Exception as e:
             # Catch any other unexpected errors during details display
             print(f"Unexpected error in show_log_details: {e}")
             traceback.print_exc() # Print full traceback for debugging
             
    def apply_filters(self):
        if not self.all_log_entries: return
        filters = {}
        keyword = self.keyword_var.get().strip() # Keep case for regex
        use_regex = self.regex_var.get()
        if keyword: filters['keyword'] = keyword # Store raw keyword
        filters['Level'] = self.level_var.get().upper().strip()
        filters['System'] = self.system_var.get().lower().strip()
        filters['Component'] = self.component_var.get().lower().strip()
        # OS Specific Filters
        os_filter_map = { 'event_id': ('EventID', self.event_id_var), 'target_user': ('TargetUserName', self.target_user_var), 'source_ip': ('SourceIP', self.source_ip_var), 'pid': ('PID', self.pid_var), 'activity_id': ('ActivityID', self.activity_id_var), 'thread_id': ('ThreadID', self.thread_id_var), }
        for fw_name, (dict_key, str_var) in os_filter_map.items():
             if fw_name in self.filter_widgets and self.filter_widgets[fw_name][1].winfo_viewable():
                 filter_val = str_var.get().strip();
                 if filter_val:
                     filters[dict_key] = filter_val.lower() # Lowercase for non-regex

        filtered_entries = self.all_log_entries
        current_display_columns = self.tree['displaycolumns']

        try: # Add try-except for potential regex errors
            for key, value in filters.items():
                if not value: continue
                if key == 'keyword':
                    if use_regex:
                        # Compile regex for efficiency if used multiple times (here it's once per filter run)
                        try:
                             regex = re.compile(value, re.IGNORECASE) # Case-insensitive regex
                        except re.error as e:
                             messagebox.showerror("Regex Error", f"Invalid regular expression:\n{e}")
                             return # Stop filtering on regex error
                        filtered_entries = [
                            entry for entry in filtered_entries
                            if any(regex.search(str(entry.get(col, ''))) for col in current_display_columns)
                        ]
                    else: # Normal keyword search (case-insensitive substring)
                        value_lower = value.lower()
                        filtered_entries = [
                            entry for entry in filtered_entries
                            if any(value_lower in str(entry.get(col, '')).lower() for col in current_display_columns)
                        ]
                else: # Specific field filter (case-insensitive substring)
                    filtered_entries = [
                        entry for entry in filtered_entries
                        if value in str(entry.get(key, '')).lower()
                    ]
            # --- ADDED: Sort before displaying if a sort column is set ---
            if self.sort_column:
                self._perform_sort(filtered_entries, self.sort_column, self.sort_reverse) # Use internal sort method
            # --- END ADDED ---

            self.display_logs(filtered_entries)
        except Exception as e:
             messagebox.showerror("Filter Error", f"An unexpected error occurred during filtering:\n{e}")
             traceback.print_exc()


    def clear_filters(self, clear_ui_only=False):
        """
        Clears all filter input fields in the GUI.
        If clear_ui_only is False (default), it also refreshes the
        log view to show all loaded log entries.
        """
        # --- Step 1: Reset all filter variable values ---
        self.keyword_var.set('')      # Clear keyword input
        self.regex_var.set(False)     # Uncheck regex box
        self.level_var.set('')      # Reset level dropdown selection
        self.system_var.set('')     # Clear system input
        self.component_var.set('')  # Clear component input

        # Clear OS-specific filter inputs
        self.event_id_var.set('')
        self.target_user_var.set('')
        self.source_ip_var.set('')
        self.pid_var.set('')
        self.activity_id_var.set('')
        self.thread_id_var.set('')

        # --- Step 2: Refresh log display (unless only clearing UI) ---
        if not clear_ui_only:

            #Reset Sort State
            self.reset_sort_indicators()
            self.sort_column = None
            self.sort_reverse = False
            
            if self.all_log_entries:
                # If logs are loaded, display all of them again
                self.display_logs(self.all_log_entries)
                # Status bar update is handled within display_logs
            else:
                # If no logs are loaded, just update status
                self.status_var.set("Filters cleared. Load a file to begin.")
                # Ensure export menus are disabled if no logs
                self.update_export_menu_state()

    def export_logs(self, selected_only=False):
        """Exports logs (either selected or all currently displayed) to CSV or JSON."""

        # --- Step 1: Check if there's anything to export ---
        if not self.displayed_log_entries:
            messagebox.showwarning("Export Error", "No logs are currently displayed to export.")
            return

        # --- Step 2: Determine which logs to export ---
        logs_to_export = []
        if selected_only:
            selected_iids = self.tree.selection() # Get tuple of selected item IDs (indices)
            if not selected_iids:
                messagebox.showwarning("Export Error", "No logs selected to export.")
                return
            try:
                # Retrieve the full dictionaries for selected items using their index (iid)
                for iid in selected_iids:
                    item_index = int(iid)
                    if 0 <= item_index < len(self.displayed_log_entries):
                        logs_to_export.append(self.displayed_log_entries[item_index])
                    else:
                         print(f"Warning: Invalid index {item_index} found in selection during export.")
                if not logs_to_export: # Check if retrieval failed for all selected
                    messagebox.showerror("Export Error", "Failed to retrieve data for selected logs.")
                    return
            except (ValueError, IndexError) as e:
                 messagebox.showerror("Export Error", f"Error retrieving selected log data:\n{e}")
                 return
        else:
            # Export all logs currently shown in the Treeview
            logs_to_export = self.displayed_log_entries

        # --- Step 3: Get file path and type from user ---
        file_path = filedialog.asksaveasfilename(
            title="Export Logs As",
            defaultextension=".csv", # Default to CSV
            filetypes=(("CSV files (*.csv)", "*.csv"),
                       ("JSON files (*.json)", "*.json"),
                       ("All files (*.*)", "*.*"))
        )
        if not file_path:
            # User cancelled the dialog
            return

        # --- Step 4: Get the columns to export (currently visible ones) ---
        columns_to_export = list(self.tree['displaycolumns'])
        # Handle edge case where displaycolumns might be empty/invalid
        if not columns_to_export or columns_to_export == ('',):
            columns_to_export = list(self.tree['columns']) # Fallback to all defined columns
        if not columns_to_export:
            messagebox.showerror("Export Error", "Cannot determine columns to export.")
            return

        # --- Step 5: Perform the export ---
        self.status_var.set(f"Exporting {len(logs_to_export)} logs to {os.path.basename(file_path)}...")
        self.root.update_idletasks() # Update GUI to show status

        try:
            file_ext = os.path.splitext(file_path)[1].lower()

            # --- CSV Export Logic ---
            if file_ext == ".csv":
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    # Use only the selected columns as fieldnames
                    writer = csv.DictWriter(f,
                                            fieldnames=columns_to_export,
                                            extrasaction='ignore') # Ignore fields not in columns_to_export
                    writer.writeheader() # Write the header row

                    for entry in logs_to_export:
                        row = {} # Prepare the dictionary for this row
                        for col in columns_to_export:
                            val = entry.get(col) # Get value for the column
                            # Format specific types for CSV compatibility
                            if isinstance(val, datetime):
                                try:
                                    row[col] = val.isoformat() # Standard ISO format
                                except (ValueError, TypeError):
                                    row[col] = str(val) # Fallback
                            elif val is None:
                                row[col] = '' # Represent None as empty string
                            else:
                                row[col] = str(val) # Convert others to string
                        writer.writerow(row) # Write the formatted row

            # --- JSON Export Logic ---
            elif file_ext == ".json":
                # Custom JSON encoder to handle datetime objects correctly
                class DateTimeEncoder(json.JSONEncoder):
                    def default(self, obj):
                        if isinstance(obj, datetime):
                            try:
                                return obj.isoformat() # Use ISO format
                            except (ValueError, TypeError):
                                return str(obj) # Fallback
                        # Let the base class default method raise the TypeError
                        return json.JSONEncoder.default(self, obj)

                # Create a list of dictionaries containing only the selected columns
                export_data = []
                for entry in logs_to_export:
                    filtered_entry = {col: entry.get(col) for col in columns_to_export}
                    export_data.append(filtered_entry)

                # Write the list of dictionaries to the JSON file
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(export_data, f, cls=DateTimeEncoder, indent=2) # Use indent for pretty printing

            # --- Unsupported Format ---
            else:
                 messagebox.showerror("Export Error", f"Unsupported file extension: '{file_ext}'.\nPlease choose .csv or .json.")
                 self.status_var.set("Export failed (unsupported format).")
                 return # Stop execution

            # --- Success Message ---
            self.status_var.set(f"Successfully exported {len(logs_to_export)} logs to {os.path.basename(file_path)}.")

        # --- General Error Handling ---
        except Exception as e:
            messagebox.showerror("Export Error", f"An error occurred during export:\n{e}")
            self.status_var.set("Export failed.")
            traceback.print_exc() # Print detailed error to console for debugging
            
    # --- GUI Help/About ---
    def show_gui_usage(self):
        """Displays GUI usage information in a messagebox."""
        usage_text = """
Ultimate Log Viewer Pro - GUI Usage:

1.  File -> Open Log File... (Ctrl+O): Load a log file (.log, .txt, .xml, .evtx).
2.  Format Dropdown: Select the log format or use Auto-Detect.
3.  Filters:
    - Enter text/pattern in Keyword (check 'Regex' for regex matching).
    - Enter text in System, Component, EventID, etc. fields.
    - Select a Level from the dropdown.
    - Click "Apply Filters".
    - Click "Clear Filters" to reset.
4.  Log View:
    - Double-click a row to see full details.
    - Select rows (Shift/Ctrl+click for multi-select).
    - Right-click a selected row to copy its data (TSV format).
5.  View Menu:
    - Change theme (Light/Dark) if sv_ttk is installed.
    - Show/Hide specific columns after loading a file.
6.  File -> Export:
    - Export Selected Rows... (exports visible columns of selected rows).
    - Export All Displayed Rows... (exports visible columns of current view).
7.  Edit -> Preferences:
    - Change the font family, size, and style for the log view.
8.  CLI Mode: Run from terminal with `--cli` for command-line operation (use `--help` for CLI options).
"""
        messagebox.showinfo("GUI Usage", usage_text.strip())
    def show_about(self):
        # ... (Keep existing about text) ...
        about_text = """
Ultimate Log Viewer Pro
Version: 1.3 (Pro Edition)

A versatile log file viewer with support for multiple formats,
filtering (incl. regex), preferences, export, context copy,
progress bar, CLI mode, and themes.

Dependencies:
- python-evtx (optional, for .evtx files)
- sv_ttk (optional, for dark/light themes)
- colorama (optional, for colored CLI output)
"""
        messagebox.showinfo("About Ultimate Log Viewer Pro", about_text.strip())


# --- CLI Mode Functions ---
def get_cli_colors():
    """Returns color codes for CLI output if colorama is available."""
    if not COLORAMA_AVAILABLE:
        return {level: '' for level in ['ERROR', 'CRITICAL', 'WARNING', 'INFO', 'DEBUG', 'AUDIT_SUCCESS', 'AUDIT_FAILURE', 'UNKNOWN']}
    return {
        'ERROR': colorama.Fore.RED + colorama.Style.BRIGHT,
        'CRITICAL': colorama.Back.RED + colorama.Fore.WHITE + colorama.Style.BRIGHT,
        'WARNING': colorama.Fore.YELLOW + colorama.Style.BRIGHT,
        'AUDIT_FAILURE': colorama.Fore.LIGHTRED_EX,
        'AUDIT_SUCCESS': colorama.Fore.GREEN,
        'INFO': colorama.Style.NORMAL, # Default terminal color
        'DEBUG': colorama.Fore.CYAN,
        'VERBOSE': colorama.Fore.MAGENTA,
        'UNKNOWN': colorama.Style.DIM,
    }

def run_cli(args):
    """Handles Command Line Interface execution."""
    print("--- Log Viewer CLI Mode ---")

    # --- Argument Validation ---
    if not args.file:
        print("Error: --file argument is required in CLI mode.")
        print("\nUse --help for usage details.")
        sys.exit(1)
    if not os.path.exists(args.file):
        print(f"Error: File not found: {args.file}")
        sys.exit(1)

    # --- 1. Determine Format ---
    log_format = args.format
    if log_format == "Auto-Detect":
        # Temporarily create instance for detection (requires tkinter, not ideal for pure CLI)
        # Consider refactoring detect_log_format to be static if possible later
        temp_root = None
        try:
            temp_root = tk.Tk()
            temp_root.withdraw() # Hide the dummy window
            # Create a dummy LogViewerApp instance just for detection method
            # It won't actually run the full GUI setup
            app_instance_for_detect = LogViewerApp(temp_root)
            log_format = app_instance_for_detect.detect_log_format(args.file)
        except Exception as e:
            print(f"Warning: Could not initialize Tkinter for auto-detection: {e}")
            log_format = None # Fallback if Tkinter fails
        finally:
            if temp_root:
                temp_root.destroy() # Clean up dummy window

        if not log_format:
            print(f"Error: Could not auto-detect format for {args.file}. Specify with --format.")
            sys.exit(1)
        print(f"Auto-detected format: {log_format}")

    # Check EVTX dependency if needed
    if log_format == "Windows EVTX" and not EVTX_AVAILABLE:
         print("Error: Cannot parse EVTX. 'python-evtx' library not found (pip install python-evtx).")
         sys.exit(1)

    # --- 2. Load and Parse Logs ---
    all_log_entries = []
    parsing_errors = 0
    print(f"Loading and parsing {args.file} as {log_format}...")
    try: # Wrap all parsing in a try-except block
        if log_format == "Windows EVTX":
            with evtx.Evtx(args.file) as log:
                for record in log.records():
                    try:
                        parsed = parse_windows_event_xml(record.xml(), is_evtx=True)
                    except Exception: # Catch errors getting XML from record itself
                        parsed = None
                        parsing_errors += 1
                    if parsed:
                        all_log_entries.append(parsed)
                    # else: # Don't count errors if parse_windows_event_xml returned None, it handles its own issues
        elif log_format == "Windows XML Event":
             with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
                 xml_content = f.read()
             # Split carefully, trying to preserve event structure
             event_texts = re.split(r'(?=<Event[\s>])', xml_content)
             for event_text in event_texts:
                if event_text.strip().startswith('<Event'):
                     parsed = parse_windows_event_xml(event_text, is_evtx=False)
                     if parsed:
                         all_log_entries.append(parsed)
                     else:
                         parsing_errors += 1 # Count if parser returns None
        elif log_format == "Linux Syslog":
            with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    parsed = parse_linux_syslog_line(line)
                    if parsed:
                        all_log_entries.append(parsed)
                    # Optionally count unparseable lines as errors?
                    # elif line.strip(): parsing_errors += 1
        elif log_format == "macOS Log Show":
             with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                     # Skip header or empty lines
                     if line.strip().startswith("Timestamp") or not line.strip(): continue
                     parsed = parse_macos_log_line(line)
                     if parsed:
                         all_log_entries.append(parsed)
                     # Optionally count unparseable lines as errors?
                     # elif line.strip(): parsing_errors += 1
        else:
            print(f"Error: Unsupported format '{log_format}' encountered in parsing logic.")
            sys.exit(1)

    except FileNotFoundError:
        print(f"Error: File not found during parsing: {args.file}")
        sys.exit(1)
    except Exception as e:
        print(f"Error during parsing: {e}")
        traceback.print_exc()
        sys.exit(1)

    print(f"Parsed {len(all_log_entries)} entries.", end="")
    if parsing_errors > 0: print(f" ({parsing_errors} parsing errors or unparseable records)")
    else: print()
    if not all_log_entries:
        print("No logs found or parsed.")
        sys.exit(0)

    # --- 3. Apply Filters ---
    filters = {}
    # Map CLI arg names to internal dictionary keys used by parsers
    cli_filter_map = {
        'keyword': 'keyword', # Special case
        'level': 'Level',
        'system': 'System',
        'component': 'Component',
        'eventid': 'EventID',
        'target_user': 'TargetUserName',
        'source_ip': 'SourceIP',
        'pid': 'PID',
        'activity_id': 'ActivityID',
        'thread_id': 'ThreadID',
    }

    # Populate filters dictionary from provided args
    for cli_arg, internal_key in cli_filter_map.items():
        value = getattr(args, cli_arg, None) # Get value from argparse Namespace
        if value:
            filters[internal_key] = value # Store raw value (lowercase happens during check)

    filtered_entries = all_log_entries
    if filters:
        print("Applying filters...")
        try: # Wrap filtering in try-except for regex errors
            temp_filtered = all_log_entries
            for key, value in filters.items():
                if not value: continue # Skip empty filter values

                current_filtered_count = len(temp_filtered)
                if key == 'keyword':
                    # Fields to search for keyword (adjust as needed)
                    search_cols = ['Message', 'System', 'Component', 'Level', 'EventID', 'ProviderName', 'TargetUserName', 'SourceIP']
                    if args.regex:
                         regex = re.compile(value, re.IGNORECASE)
                         temp_filtered = [
                             entry for entry in temp_filtered
                             if any(regex.search(str(entry.get(col, ''))) for col in search_cols if col in entry)
                         ]
                    else:
                         value_lower = value.lower()
                         temp_filtered = [
                             entry for entry in temp_filtered
                             if any(value_lower in str(entry.get(col, '')).lower() for col in search_cols if col in entry)
                         ]
                else:
                     # Specific field filtering (case-insensitive substring match)
                     value_lower = value.lower()
                     temp_filtered = [
                        entry for entry in temp_filtered
                        if value_lower in str(entry.get(key, '')).lower()
                    ]
                print(f"  - Filter '{key}={value}' {'(regex)' if key=='keyword' and args.regex else ''}: {current_filtered_count} -> {len(temp_filtered)} entries")

            filtered_entries = temp_filtered
            print(f"Filtering complete: {len(filtered_entries)} entries match.")

        except re.error as e:
             print(f"\nError: Invalid regular expression provided for keyword: {e}")
             sys.exit(1)
        except Exception as e:
             print(f"\nError during filtering: {e}"); traceback.print_exc(); sys.exit(1)

    # --- 4. Sorting (CLI) ---
    if args.sort_by:
        sort_col = args.sort_by
        # Simple validation: Check if the key exists in at least one entry
        if filtered_entries and not any(sort_col in entry for entry in filtered_entries):
             print(f"Warning: Sort column '{sort_col}' may not exist in all filtered entries.")
             # Decide whether to continue or exit? For now, continue.

        print(f"Sorting by '{sort_col}' ({args.sort_order})...")
        reverse_order = args.sort_order.lower() == 'desc'
        try:
            # Use the helper function for the sort key
            filtered_entries.sort(key=lambda entry: _get_cli_sort_key(entry, sort_col), reverse=reverse_order)
        except Exception as e:
            print(f"Error during CLI sort: {e}") # Prevent crash on bad sort data

    # --- 5. Display Results or Info ---
    if args.info:
        # --- Basic Info Mode ---
        print("\n--- Log Information Summary ---")
        total_loaded = len(all_log_entries)
        total_filtered = len(filtered_entries)
        print(f"Total Logs Loaded: {total_loaded}")
        print(f"Matching Filters: {total_filtered}")

        if total_filtered > 0:
            # Level Counts
            print("\nCounts by Level:")
            level_counts = Counter(entry.get('Level', 'UNKNOWN') for entry in filtered_entries)
            # Sort levels alphabetically for consistent output
            for level, count in sorted(level_counts.items()):
                print(f"  - {level:<15}: {count}")

            # Component Counts (Top N)
            top_n_components = 10
            print(f"\nTop {top_n_components} Components:")
            comp_counts = Counter(entry.get('Component', 'UNKNOWN') for entry in filtered_entries)
            # Sort by count descending, then alphabetically for ties
            for comp, count in sorted(comp_counts.most_common(top_n_components), key=lambda item: (-item[1], item[0])):
                print(f"  - {comp:<25}: {count}")

            # Time Range
            timestamps = [entry.get('Timestamp') for entry in filtered_entries if isinstance(entry.get('Timestamp'), datetime)]
            if timestamps:
                # Make sure min/max work even with single timestamp
                min_ts_dt = min(timestamps)
                max_ts_dt = max(timestamps)
                min_ts = min_ts_dt.strftime("%Y-%m-%d %H:%M:%S %Z") if min_ts_dt else "N/A"
                max_ts = max_ts_dt.strftime("%Y-%m-%d %H:%M:%S %Z") if max_ts_dt else "N/A"
                print(f"\nTime Range (UTC): {min_ts}  ->  {max_ts}")
            else:
                print("\nTime Range: Not available (no valid timestamps found in filtered results)")
        else:
             print("\n(No logs match filters to provide summary details)")

    else:
        # --- Detailed Log Output Mode ---
        print("\n--- Filtered Log Entries ---")
        if not filtered_entries:
            print("(No entries match filters)")
        else:
            cli_colors = get_cli_colors()
            # Calculate padding width for index number dynamically
            max_index_len = len(str(args.limit if args.limit and args.limit < len(filtered_entries) else len(filtered_entries)))

            output_count = 0
            for i, entry in enumerate(filtered_entries):
                ts = entry.get('Timestamp')
                level = entry.get('Level', 'UNKNOWN')
                # Fallback to RawLine if Message is empty/missing
                msg = entry.get('Message') or entry.get('RawLine', 'N/A')
                # Format timestamp safely
                ts_str = ts.isoformat() if isinstance(ts, datetime) else entry.get('RawTimestamp', 'N/A')
                # Get color, handle potential missing levels in color dict
                level_color = cli_colors.get(level, cli_colors.get('UNKNOWN', ''))
                # Pad level string for alignment
                level_display = f"{level:<15}"

                # Print colored output if colorama available
                print(f"[{i+1:>{max_index_len}}] {ts_str} | {level_color}{level_display}{colorama.Style.RESET_ALL if COLORAMA_AVAILABLE else ''} | {msg}")
                output_count += 1

                if args.limit and output_count >= args.limit:
                    print(f"\nOutput limited to first {args.limit} entries.")
                    break # Stop after reaching limit

    print("--- CLI Mode End ---")

# --- Main Execution & CLI Argument Parsing ---
# --- Main Execution & CLI Argument Parsing ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Ultimate Log Viewer Pro: GUI/CLI tool.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  GUI Mode (default): python %(prog)s
  CLI Info Mode: python %(prog)s --cli -f <file> --info [--filter options]
  CLI Log Output: python %(prog)s --cli -f <file> [--filter options] [--sort-by Col] [--limit N]
  CLI Help: python %(prog)s --help
""")
    # General Arguments
    parser.add_argument('--cli', action='store_true', help="Run in Command Line Interface (CLI) mode.")
    parser.add_argument('--info', action='store_true', help="In CLI mode, show summary info instead of log entries.")
    parser.add_argument('-f', '--file', help="Path to the log file (required in CLI mode).")
    parser.add_argument('--format', choices=LOG_FORMATS, default="Auto-Detect", help="Log format (default: Auto-Detect).")

    # Filtering Group
    filter_group = parser.add_argument_group('CLI Filtering Options')
    filter_group.add_argument('-k', '--keyword', help="Keyword/pattern to search.")
    filter_group.add_argument('--regex', action='store_true', help="Treat --keyword as Python Regex.")
    filter_group.add_argument('-l', '--level', help="Filter by log level.")
    filter_group.add_argument('-s', '--system', help="Filter by system/hostname.")
    filter_group.add_argument('-c', '--component', help="Filter by component/process.")
    filter_group.add_argument('-e', '--eventid', help="Filter by EventID (Windows).")
    filter_group.add_argument('--source-ip', help="Filter by source IP.")
    filter_group.add_argument('--target-user', help="Filter by target user name (Windows).")
    filter_group.add_argument('--pid', help="Filter by Process ID.")
    filter_group.add_argument('--activity-id', help="Filter by Activity ID (macOS).")
    filter_group.add_argument('--thread-id', help="Filter by Thread ID (macOS).")

    # Sorting Group
    sort_group = parser.add_argument_group('CLI Sorting Options')
    sort_group.add_argument('--sort-by', help="Column name to sort by (e.g., Timestamp, Level, EventID). Case-sensitive.")
    sort_group.add_argument('--sort-order', choices=['asc', 'desc'], default='asc', help="Sort order: 'asc' or 'desc' (default: asc).")

    # Output Group
    output_group = parser.add_argument_group('CLI Output Options')
    # *** ENSURE --limit IS DEFINED ONLY HERE ***
    output_group.add_argument('--limit', type=int, help="Limit CLI log entry output to the first N matching entries.")
    # *** REMOVE ANY OTHER output_group.add_argument('--limit', ...) or parser.add_argument('--limit', ...) lines ***

    args = parser.parse_args()

    # --- Mode Execution ---
    if args.cli:
        run_cli(args)
    else:
        # --- GUI Mode ---
        # (Dependency warnings)
        if not EVTX_AVAILABLE:
            print("--- WARNING: 'python-evtx' not found. EVTX support disabled. (pip install python-evtx) ---")
        if not SVTTK_AVAILABLE:
            print("--- WARNING: 'sv_ttk' not found. Theme switching disabled. (pip install sv_ttk) ---")
        if not COLORAMA_AVAILABLE:
            print("--- INFO: 'colorama' not found. CLI output will not be colored. (pip install colorama) ---")
        # (Start GUI)
        root = tk.Tk()
        app = LogViewerApp(root)
        root.mainloop()
