# Ultimate Log Viewer Pro
```
   __  __    __   __     _                        __                  __                         _    __    _                               
  / / / /   / /  / /_   (_)   ____ ___   ____ _  / /_  ___           / /   ____    ____ _       | |  / /   (_)  ___  _      __  ___    _____
 / / / /   / /  / __/  / /   / __ `__ \ / __ `/ / __/ / _ \         / /   / __ \  / __ `/       | | / /   / /  / _ \| | /| / / / _ \  / ___/
/ /_/ /   / /  / /_   / /   / / / / / // /_/ / / /_  /  __/        / /___/ /_/ / / /_/ /        | |/ /   / /  /  __/| |/ |/ / /  __/ / /    
\____/   /_/   \__/  /_/   /_/ /_/ /_/ \__,_/  \__/  \___/        /_____/\____/  \__, /         |___/   /_/   \___/ |__/|__/  \___/ /_/     
                                                                                /____/                                                      
```
**Ultimate Log Viewer Pro** is a powerful and flexible Python tool designed for parsing, viewing, filtering, and analyzing various log file formats. It provides both a feature-rich Graphical User Interface (GUI) and a versatile Command-Line Interface (CLI) to cater to different user preferences and workflows.

Analyze Windows EVTX, XML exports, Linux Syslog, macOS logs, and more with advanced filtering (including regex), column sorting, customizable views, and export capabilities.


## Features

**Core:**
*   **GUI & CLI Modes:** Use the familiar graphical interface or operate directly from the terminal.
*   **Multi-Format Support:** Parses common log formats:
    *   Windows EVTX (`.evtx`) - Requires `python-evtx`
    *   Windows XML Event Log Exports (`.xml`)
    *   Standard Linux Syslog (`/var/log/syslog`, `auth.log`, etc.) - Handles common RFC3164 style.
    *   macOS Unified Log (`log show` text output)
*   **Auto-Detect Format:** Attempts to automatically identify the log format based on extension and content.
*   **Log Normalization:** Maps fields from different formats into a consistent set of display columns (Timestamp, Level, System, Component, EventID, Message, etc.), including dynamically extracted fields (e.g., from EventData).
*   **Error Handling:** Gracefully handles parsing errors and optional dependency issues.

**GUI Specific:**
*   **Advanced Filtering:** Keyword (substring/regex), Level, System, Component, OS-specific fields.
*   **Column Sorting:** Click headers to sort displayed logs (toggle direction).
*   **Column Visibility:** Show/Hide columns via `View -> Columns`.
*   **Log Details View:** Double-click row for full data + raw log/XML.
*   **Context Menu:** Right-click row to copy visible data (TSV).
*   **Export:** Export selected/displayed rows (visible columns) to CSV/JSON.
*   **Theming:** Light/Dark modes (requires `sv_ttk`). Defaults to Dark.
*   **Font Preferences:** Customize log view font via `Edit -> Preferences`.
*   **Loading Progress Bar:** Visual feedback for large files.
*   **Persistent Preferences:** Remembers theme, font, window size.
*   **Enhanced Status Bar:** Shows Total | Displayed | Selected counts.
*   **Help Menu:** Usage guide and About info.

**CLI Specific:**
*   **Full Filtering:** All GUI filter options available via flags.
*   **Sorting:** Sort output via `--sort-by` and `--sort-order`.
*   **Info/Summary Mode:** Use `--info` for statistical summary instead of logs.
*   **Output Limiting:** Use `--limit` to restrict the number of displayed entries.
*   **Colored Output:** Color-coded levels if `colorama` is installed.
*   **Help:** Detailed help available via `--help`.

## Prerequisites

*   **Python:** Version 3.7 or higher recommended.
*   **pip:** Python's package installer.

## Installation / Dependencies

1.  **Save the Script:** Save the Python code as a `.py` file (e.g., `log_viewer_pro.py`).
2.  **Install Optional Dependencies:** These enhance functionality but are not strictly required for basic text log viewing. Open your terminal or command prompt and run:

    *   **For EVTX Support:**
        ```bash
        pip install python-evtx
        ```
    *   **For GUI Themes (Light/Dark):**
        ```bash
        pip install sv_ttk
        ```
    *   **For Colored CLI Output:**
        ```bash
        pip install colorama
        ```

## Usage

This tool can be used in two primary modes: GUI (default) and CLI.

### Workflow: GUI Mode

This is the default mode when running the script without specific flags.

1.  **Launch:**
    ```bash
    python log_viewer_pro.py
    ```
2.  **Open Log File:**
    *   Go to `File -> Open Log File...` (or press `Ctrl+O`).
    *   Select your log file (`.evtx`, `.xml`, `.log`, `.txt`, etc.).
    *   Choose the format from the **Log Format** dropdown or leave it as "Auto-Detect". The application will load and parse the file, showing a progress bar for larger files.
3.  **Explore Data:**
    *   Scroll through the logs in the main table.
    *   **Sort:** Click a column header (e.g., "Timestamp") to sort. Click again to reverse the order.
    *   **View Details:** Double-click any log row to see all its fields in a separate window.
    *   **Adjust Columns:** Go to `View -> Columns` and check/uncheck columns to customize the display.
    *   **Copy Row:** Right-click a row and select "Copy Row Data (TSV)".
4.  **Filter Logs:**
    *   Enter terms in the filter fields (Keyword, Level, System, Component, etc.). Note that OS-specific filters like EventID only appear after loading a compatible file (e.g., EVTX).
    *   Check the **Regex** box if your Keyword input is a regular expression.
    *   Click **Apply Filters**. The view updates to show only matching logs.
    *   Click **Clear Filters** to reset the view to all loaded logs.
5.  **Export Data:**
    *   (Optional) Select specific rows you want to export using Shift+click or Ctrl+click.
    *   Go to `File -> Export`.
    *   Choose `Export Selected Rows...` or `Export All Displayed Rows...`.
    *   Select a file name, choose CSV or JSON format, and save. Only currently visible columns are exported.
6.  **Customize Appearance:**
    *   Go to `Edit -> Preferences...` to change the font settings for the log view.
    *   Go to `View` menu to switch between Light and Dark themes (if `sv_ttk` is installed).
7.  **Exit:** Close the window or go to `File -> Exit`. Preferences are saved.

### Workflow: CLI Mode (Viewing Log Entries)

Use this mode to view filtered/sorted log entries directly in your terminal.

1.  **Launch with `--cli` and `-f`:**
    ```bash
    # Basic usage, auto-detect format
    python log_viewer_pro.py --cli -f /path/to/logfile.log

    # Specify format explicitly
    python log_viewer_pro.py --cli -f security.evtx --format "Windows EVTX"
    ```
2.  **Add Filters (Optional):** Append filter arguments to narrow down results.
    ```bash
    # Filter by level and component
    python log_viewer_pro.py --cli -f /var/log/syslog -l WARNING -c CRON

    # Filter by EventID and keyword (using regex)
    python log_viewer_pro.py --cli -f security.evtx -e 4625 --keyword "Account Name:\s+(\S+)" --regex
    ```
3.  **Control Output (Optional):** Use sorting and limiting flags.
    ```bash
    # Sort by Timestamp descending and limit to 50 lines
    python log_viewer_pro.py --cli -f system.log --sort-by Timestamp --sort-order desc --limit 50
    ```
4.  **Review Output:** The script will print the parsed, filtered, and sorted log entries to the console (Timestamp | Level | Message format, potentially colored).

### Workflow: CLI Mode (Information Summary)

Use this mode to get statistics about the logs instead of the entries themselves.

1.  **Launch with `--cli`, `-f`, and `--info`:**
    ```bash
    python log_viewer_pro.py --cli -f /path/to/logfile.log --info
    ```
2.  **Add Filters (Optional):** Apply filters to get statistics only for the matching logs.
    ```bash
    python log_viewer_pro.py --cli -f security.evtx --format "Windows EVTX" -e 4624 --info
    ```
3.  **Review Output:** The script will print:
    *   Total logs loaded.
    *   Number of logs matching filters.
    *   Counts for each Log Level found in the filtered results.
    *   Top 10 Components/Providers found in the filtered results.
    *   The earliest and latest timestamps (UTC) found in the filtered results.

### CLI Output Control Options

These arguments modify the output in CLI mode (when **not** using `--info`):

*   `--sort-by COLUMN_NAME`: Specifies the field key (e.g., `Timestamp`, `Level`, `EventID`, `System`) to sort the output by. Note: This is case-sensitive and must match a key present in the parsed log dictionaries.
*   `--sort-order asc|desc`: Sets the sorting direction. Defaults to `asc` (ascending).
*   `--limit N`: Restricts the detailed log output to the first `N` entries after filtering and sorting.

### CLI Help

For a complete list of all CLI arguments and their descriptions, run:

```bash
python log_viewer_pro.py --help
```

### Configuration
Preferences (Theme, Font, Window Size) for the GUI mode are saved automatically in:
   *  Directory: ~/.ultimate_log_viewer_pro/ (will be created if it doesn't exist)
   *  File: prefs.ini


### Known Issues / Limitations
  * Large Files: GUI loading of multi-GB files can be slow/memory-intensive.
  * Complex Formats: Highly irregular or custom log formats might require parser modifications.
  * CLI Auto-Detect: Auto-detection in CLI might briefly initialize Tkinter; use --format to avoid this.
