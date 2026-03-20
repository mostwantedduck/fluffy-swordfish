# -*- coding: utf-8 -*-
"""
LowHangingFruits Burp Grabber
A Burp Suite extension for detecting secrets, endpoints, URLs, files, and emails in HTTP responses.

Author: Daniel
Version: 1.0.0
"""

from burp import IBurpExtender, IHttpListener, ITab, IContextMenuFactory, IMessageEditorController, IScanIssue
from javax.swing import (
    JPanel, JTable, JScrollPane, JSplitPane, JLabel, JComboBox, JCheckBox,
    JButton, JTextField, JTextArea, JTabbedPane, JFileChooser, JOptionPane,
    SwingConstants, BorderFactory, BoxLayout, Box, ListSelectionModel,
    JPopupMenu, JMenuItem, DefaultCellEditor, SwingUtilities, JDialog,
    JList, DefaultListModel
)
from javax.swing.text import DefaultHighlighter, JTextComponent
from javax.swing.table import AbstractTableModel, DefaultTableCellRenderer
from javax.swing.event import ListSelectionListener
from javax.swing.filechooser import FileNameExtensionFilter
from java.awt import BorderLayout, FlowLayout, GridBagLayout, GridBagConstraints, Insets, Dimension, Color, Font, Desktop, Toolkit
from java.awt.event import ActionListener, MouseAdapter
from java.awt.datatransfer import StringSelection
from java.io import File, BufferedReader, InputStreamReader
from java.net import URI, URL, HttpURLConnection
from java.lang import Runnable, Thread as JThread
import re
import json
import os
import threading
import math


class BurpExtender(IBurpExtender, IHttpListener, ITab, IContextMenuFactory, IMessageEditorController):
    """Main Burp Suite extension class."""
    
    EXTENSION_NAME = "LowHangingFruits"
    VERSION = "1.0.1"
    
    # Media types to skip
    MEDIA_TYPES = [
        'image/', 'video/', 'audio/', 'font/',
        'application/octet-stream', 'application/pdf',
        'application/zip', 'application/x-gzip',
        'application/x-rar', 'application/x-7z'
    ]
    
    # Extensions to analyze
    ANALYZE_EXTENSIONS = ['.js', '.json', '.map']
    
    # Content types to analyze
    ANALYZE_CONTENT_TYPES = ['javascript', 'json', 'ecmascript']
    
    # Severity classification for findings
    SEVERITY_RULES = {
        'secrets': 'High',
        'files': 'Medium',
        'configurations': 'Medium',
        'urls': 'Info',
        'endpoints': 'Info',
        'emails': 'Low'
    }
    HIGH_SECRET_PATTERNS = [
        'AKIA', 'ASIA', 'sk_live_', 'pk_live_', 'rk_live_',
        'ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_', 'github_pat_',
        'glpat-', 'xoxb-', 'xoxp-', 'xoxa-', 'xoxr-', 'xoxs-',
        '-----BEGIN', 'eyJ',
        'shpat_', 'shpss_', 'shpca_', 'shppa_',
        'hvs.', 'hvb.', 'hvp.',
        'sk-proj-', 'sk-ant-api03-',
        'GOCSPX-', 'FwoGZX', 'PMAK-',
        'dp.st.', 'dp.ct.',
        'atlasv1-'
    ]
    # Phase E: Patterns indicating test/dev/sandbox secrets (demote to Medium)
    TEST_SECRET_INDICATORS = [
        '_test_', '_dev_', '_staging_', '_sandbox_',
        'test_', 'dev_', 'staging_', 'sandbox_',
        'sk_test_', 'pk_test_', 'rk_test_',
        'example', 'dummy', 'fake', 'sample'
    ]
    # Phase D: Minimum entropy threshold for generic secret patterns
    ENTROPY_THRESHOLD = 3.0
    MEDIUM_URL_PATTERNS = [
        'localhost', '127.0.0.1', '10.', '172.16.', '172.17.',
        '172.18.', '172.19.', '172.2', '172.3', '192.168.',
        'password=', 'token=', 'secret=', 'key=', 'auth=',
        's3.amazonaws.com', '.blob.core.windows.net'
    ]
    
    def registerExtenderCallbacks(self, callbacks):
        """Initialize the extension."""
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Set extension name
        callbacks.setExtensionName(self.EXTENSION_NAME)
        
        # Initialize data structures
        self._results = []
        self._seen_match_only = set()
        self._seen_match_and_url = set()
        self._lock = threading.Lock()
        self._current_request = None
        self._current_response = None
        
        # Initialize exclusions (false positives)
        self._exclusions = {'matches': [], 'urls': []}
        
        # Initialize whiteboard
        self._whiteboard = {
            'Domains': [], 'Secrets': [], 'Files': [], 'Paths': [],
            'Emails': [], 'URLs': [], 'Configurations': [], 'Other': []
        }
        self._wb_status_cache = {}
        self._wb_status_lock = threading.Lock()
        self._wb_status_running = False
        
        # Initialize source maps collector
        self._source_maps = []
        self._source_maps_seen = set()
        
        # Load patterns and settings
        self._load_patterns()
        self._load_settings()
        self._load_exclusions()
        self._load_whiteboard()
        
        # Build UI
        self._build_ui()
        
        # Register callbacks
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        
        # Print banner
        self._print_banner()
    
    def _print_banner(self):
        """Print extension banner to output."""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                    LowHangingFruits v{}                    ║
║         Passive Secrets & Endpoints Detector                 ║
╠══════════════════════════════════════════════════════════════╣
║  Categories: Endpoints | URLs | Secrets | Files | Emails    ║
╚══════════════════════════════════════════════════════════════╝
        """.format(self.VERSION)
        print(banner)
    
    def _get_extension_dir(self):
        """Get the directory where the extension is located."""
        try:
            # Try to get the extension file location
            extension_file = self._callbacks.getExtensionFilename()
            if extension_file:
                return os.path.dirname(extension_file)
        except:
            pass
        return os.path.dirname(os.path.abspath(__file__))
    
    def _load_patterns(self):
        """Load regex patterns from JSON files."""
        ext_dir = self._get_extension_dir()
        patterns_dir = os.path.join(ext_dir, "patterns")
        
        # Default patterns
        self._patterns = {
            "endpoints": [],
            "urls": [],
            "secrets": [],
            "files": [],
            "emails": [],
            "configurations": []
        }
        
        # Default noise filters
        self._noise_filters = {
            "domains": [],
            "strings": [],
            "paths": []
        }
        
        # Load default patterns
        patterns_file = os.path.join(patterns_dir, "default_patterns.json")
        if os.path.exists(patterns_file):
            try:
                with open(patterns_file, 'r') as f:
                    self._patterns = json.load(f)
                print("[+] Loaded default patterns from: {}".format(patterns_file))
            except Exception as e:
                print("[-] Error loading patterns: {}".format(str(e)))
        
        # Load noise filters
        noise_file = os.path.join(patterns_dir, "noise_filters.json")
        if os.path.exists(noise_file):
            try:
                with open(noise_file, 'r') as f:
                    self._noise_filters = json.load(f)
                print("[+] Loaded noise filters from: {}".format(noise_file))
            except Exception as e:
                print("[-] Error loading noise filters: {}".format(str(e)))
        
        # Load custom patterns from Burp settings
        self._load_custom_patterns()
        
        # Compile patterns and noise filters
        self._compile_patterns()
        self._compile_noise_filters()
    
    def _load_custom_patterns(self):
        """Load custom patterns from Burp's extension settings."""
        try:
            custom_json = self._callbacks.loadExtensionSetting("custom_patterns")
            if custom_json:
                custom = json.loads(custom_json)
                for category, patterns in custom.items():
                    if category in self._patterns:
                        self._patterns[category].extend(patterns)
                print("[+] Loaded custom patterns from settings")
        except Exception as e:
            print("[-] Error loading custom patterns: {}".format(str(e)))
        
        try:
            custom_noise_json = self._callbacks.loadExtensionSetting("custom_noise")
            if custom_noise_json:
                custom_noise = json.loads(custom_noise_json)
                for filter_type, filters in custom_noise.items():
                    if filter_type in self._noise_filters:
                        self._noise_filters[filter_type].extend(filters)
                print("[+] Loaded custom noise filters from settings")
        except Exception as e:
            print("[-] Error loading custom noise filters: {}".format(str(e)))
    
    def _compile_patterns(self):
        """Compile regex patterns for better performance."""
        self._compiled_patterns = {}
        for category, patterns in self._patterns.items():
            self._compiled_patterns[category] = []
            for pattern in patterns:
                try:
                    compiled = re.compile(pattern)
                    self._compiled_patterns[category].append(compiled)
                except Exception as e:
                    print("[-] Error compiling pattern '{}': {}".format(pattern, str(e)))
    
    def _load_settings(self):
        """Load extension settings from Burp."""
        # Default settings
        # merge_duplicates options: "match_only", "match_and_url", "none"
        self._settings = {
            "only_in_scope": False,
            "skip_media": True,
            "merge_duplicates": "match_only",
            "status_checks_enabled": False
        }
        
        try:
            settings_json = self._callbacks.loadExtensionSetting("settings")
            if settings_json:
                self._settings = json.loads(settings_json)
                print("[+] Loaded settings from Burp")
        except Exception as e:
            print("[-] Error loading settings: {}".format(str(e)))
    
    def _save_settings(self):
        """Save extension settings to Burp."""
        try:
            self._callbacks.saveExtensionSetting("settings", json.dumps(self._settings))
            print("[+] Settings saved")
        except Exception as e:
            print("[-] Error saving settings: {}".format(str(e)))
    
    def _load_exclusions(self):
        """Load false positive exclusions from Burp settings."""
        try:
            exclusions_json = self._callbacks.loadExtensionSetting("exclusions")
            if exclusions_json:
                self._exclusions = json.loads(exclusions_json)
                print("[+] Loaded {} match exclusions, {} URL exclusions".format(
                    len(self._exclusions.get('matches', [])),
                    len(self._exclusions.get('urls', []))
                ))
        except Exception as e:
            print("[-] Error loading exclusions: {}".format(str(e)))
    
    def _save_exclusions(self):
        """Save false positive exclusions to Burp settings."""
        try:
            self._callbacks.saveExtensionSetting("exclusions", json.dumps(self._exclusions))
            print("[+] Exclusions saved")
        except Exception as e:
            print("[-] Error saving exclusions: {}".format(str(e)))
    
    def _load_whiteboard(self):
        """Load whiteboard items from Burp settings."""
        try:
            wb_json = self._callbacks.loadExtensionSetting("whiteboard")
            if wb_json:
                saved = json.loads(wb_json)
                for cat in self._whiteboard:
                    if cat in saved:
                        self._whiteboard[cat] = saved[cat]
                total = sum(len(v) for v in self._whiteboard.values())
                print("[+] Loaded {} whiteboard items".format(total))
        except Exception as e:
            print("[-] Error loading whiteboard: {}".format(str(e)))
    
    def _save_whiteboard(self):
        """Save whiteboard items to Burp settings."""
        try:
            self._callbacks.saveExtensionSetting("whiteboard", json.dumps(self._whiteboard))
        except Exception as e:
            print("[-] Error saving whiteboard: {}".format(str(e)))
    
    def _classify_for_whiteboard(self, value, source_category):
        """Auto-classify a value into a whiteboard category."""
        val_lower = value.lower()
        
        if source_category.lower() == 'emails':
            return 'Emails'
        if source_category.lower() == 'configurations':
            return 'Configurations'
        
        # Check for secrets (keys, tokens, passwords)
        secret_indicators = ['key', 'token', 'secret', 'password', 'bearer', 'AKIA',
                             'sk_live', 'sk_test', 'ghp_', 'glpat-', 'xox', '-----BEGIN',
                             'eyJ', 'shpat_', 'hvs.']
        for ind in secret_indicators:
            if ind in value:
                return 'Secrets'
        
        # Check for files
        file_indicators = ['.sql', '.db', '.env', '.config', '.pem', '.key', '.crt',
                           '.bak', '.log', '.yml', '.yaml', '.json', '.xml', '.csv',
                           '.htaccess', '.htpasswd', '.ssh/', '.aws/', '.kube/']
        for ind in file_indicators:
            if ind in val_lower:
                return 'Files'
        
        # Check for emails
        if '@' in value and '.' in value.split('@')[-1]:
            return 'Emails'
        
        # Check for URLs
        if any(value.startswith(p) for p in ['http://', 'https://', 'ftp://', 'ws://', 'wss://']):
            return 'URLs'
        
        # Check for domains (has dots, no spaces, no path separators at start)
        if '.' in value and ' ' not in value and not value.startswith('/'):
            parts = value.split('.')
            if len(parts) >= 2 and all(p.replace('-', '').replace('_', '').isalnum() for p in parts if p):
                return 'Domains'
        
        # Check for paths/endpoints
        if value.startswith('/') or value.startswith('./') or value.startswith('../'):
            return 'Paths'
        
        # Connection strings
        if '://' in value:
            return 'URLs'
        
        return 'Other'
    
    def _add_to_whiteboard(self, value, source_category=''):
        """Add a value to the whiteboard with auto-classification."""
        category = self._classify_for_whiteboard(value, source_category)
        if value not in self._whiteboard[category]:
            self._whiteboard[category].append(value)
            self._save_whiteboard()
            self._refresh_whiteboard_ui()
            if category in ('Domains', 'URLs'):
                self._trigger_status_checks()
            print("[+] Added to Whiteboard [{}]: {}".format(category, value[:60]))
            return True
        return False
    
    def _remove_from_whiteboard(self, category, value):
        """Remove a value from the whiteboard."""
        if category in self._whiteboard and value in self._whiteboard[category]:
            self._whiteboard[category].remove(value)
            self._save_whiteboard()
            self._refresh_whiteboard_ui()
    
    # Known second-level TLDs that require 3 parts for root domain
    SECOND_LEVEL_TLDS = [
        'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au',
        'co.nz', 'co.za', 'co.in', 'co.jp', 'co.kr', 'com.br', 'com.mx',
        'com.ar', 'com.co', 'com.es', 'com.tr', 'com.cn', 'com.tw', 'com.sg',
        'com.hk', 'com.my', 'com.ph', 'com.pk', 'com.ng', 'com.eg', 'com.sa',
        'org.es', 'gov.es', 'edu.es', 'gob.es'
    ]
    
    @staticmethod
    def _extract_domain(value):
        """Extract the root domain from a URL or domain string.
        e.g. https://www.sub.raiz.com/path -> raiz.com
             api.test.openbank.es -> openbank.es
             mail.example.co.uk -> example.co.uk"""
        domain = value.strip()
        # Strip protocol
        for prefix in ['https://', 'http://', 'ftp://', 'wss://', 'ws://']:
            if domain.lower().startswith(prefix):
                domain = domain[len(prefix):]
                break
        # Strip path, port, auth
        domain = domain.split('/')[0].split(':')[0].split('@')[-1].lower()
        if not domain:
            return None
        
        parts = domain.split('.')
        if len(parts) <= 2:
            return domain
        
        # Check for second-level TLDs (e.g. co.uk, com.es)
        last_two = '.'.join(parts[-2:])
        for sld in BurpExtender.SECOND_LEVEL_TLDS:
            if last_two == sld:
                return '.'.join(parts[-3:]) if len(parts) >= 3 else domain
        
        return '.'.join(parts[-2:])
    
    def _search_subdomains_async(self, domain):
        """Launch subdomain search in a background thread with loading dialog."""
        loading_dialog = JOptionPane(
            "Searching subdomains for: {}\n\nQuerying crt.sh...".format(domain),
            JOptionPane.INFORMATION_MESSAGE
        )
        dialog = loading_dialog.createDialog(self._main_panel, "Subdomain Search")
        dialog.setModal(False)
        dialog.setVisible(True)
        
        def _worker():
            try:
                subdomains = self._fetch_subdomains_crtsh(domain)
                SwingUtilities.invokeLater(lambda: dialog.dispose())
                if subdomains:
                    SwingUtilities.invokeLater(lambda: self._show_subdomain_results(domain, subdomains))
                else:
                    SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(
                        self._main_panel,
                        "No subdomains found for: {}".format(domain),
                        "Subdomain Search",
                        JOptionPane.INFORMATION_MESSAGE
                    ))
            except Exception as e:
                SwingUtilities.invokeLater(lambda: dialog.dispose())
                SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(
                    self._main_panel,
                    "Error querying crt.sh: {}".format(str(e)),
                    "Subdomain Search Error",
                    JOptionPane.ERROR_MESSAGE
                ))
        
        thread = threading.Thread(target=_worker)
        thread.daemon = True
        thread.start()
    
    def _fetch_subdomains_crtsh(self, domain):
        """Query crt.sh for subdomains of the given domain."""
        url_str = "https://crt.sh/?q=%25.{}&output=json".format(domain)
        url = URL(url_str)
        conn = url.openConnection()
        conn.setRequestMethod("GET")
        conn.setRequestProperty("User-Agent", "LowHangingFruits-BurpExtension/1.0")
        conn.setConnectTimeout(15000)
        conn.setReadTimeout(30000)
        
        response_code = conn.getResponseCode()
        if response_code != 200:
            raise Exception("HTTP {} from crt.sh".format(response_code))
        
        reader = BufferedReader(InputStreamReader(conn.getInputStream(), "UTF-8"))
        sb = []
        line = reader.readLine()
        while line is not None:
            sb.append(line)
            line = reader.readLine()
        reader.close()
        conn.disconnect()
        
        raw = "".join(sb)
        entries = json.loads(raw)
        
        # Extract unique subdomains from name_value and common_name
        subdomains = set()
        for entry in entries:
            for field in ['name_value', 'common_name']:
                val = entry.get(field, '')
                if val:
                    for name in val.split('\n'):
                        name = name.strip().lower()
                        if name and '*' not in name and name.endswith(domain.lower()):
                            subdomains.add(name)
        
        return sorted(subdomains)
    
    def _show_subdomain_results(self, domain, subdomains):
        """Show a dialog with subdomain results for selective addition to whiteboard."""
        frame = JOptionPane.getRootFrame()
        result_dialog = JDialog(frame, "Subdomains for {}".format(domain), True)
        result_dialog.setSize(500, 450)
        result_dialog.setLocationRelativeTo(self._main_panel)
        
        panel = JPanel(BorderLayout())
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        # Header
        header = JLabel("{} subdomains found for {}".format(len(subdomains), domain))
        header.setFont(Font("SansSerif", Font.BOLD, 13))
        panel.add(header, BorderLayout.NORTH)
        
        # Checkboxes list
        cb_panel = JPanel()
        cb_panel.setLayout(BoxLayout(cb_panel, BoxLayout.Y_AXIS))
        checkboxes = []
        for sub in subdomains:
            already = sub in self._whiteboard.get('Domains', [])
            cb = JCheckBox(sub, not already)
            if already:
                cb.setForeground(Color.GRAY)
                cb.setToolTipText("Already on Whiteboard")
            cb.setFont(Font("Monospaced", Font.PLAIN, 12))
            checkboxes.append(cb)
            cb_panel.add(cb)
        
        scroll = JScrollPane(cb_panel)
        panel.add(scroll, BorderLayout.CENTER)
        
        # Buttons
        btn_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
        
        select_all_btn = JButton("Select All")
        deselect_all_btn = JButton("Deselect All")
        add_btn = JButton("Add Selected to Whiteboard")
        cancel_btn = JButton("Cancel")
        
        class SelectAllAction(ActionListener):
            def actionPerformed(self_inner, event):
                for cb in checkboxes:
                    cb.setSelected(True)
        
        class DeselectAllAction(ActionListener):
            def actionPerformed(self_inner, event):
                for cb in checkboxes:
                    cb.setSelected(False)
        
        extender_ref = self
        class AddSelectedAction(ActionListener):
            def actionPerformed(self_inner, event):
                count = 0
                for cb in checkboxes:
                    if cb.isSelected():
                        sub = cb.getText()
                        if sub not in extender_ref._whiteboard.get('Domains', []):
                            extender_ref._whiteboard['Domains'].append(sub)
                            count += 1
                if count > 0:
                    extender_ref._save_whiteboard()
                    extender_ref._refresh_whiteboard_ui()
                    extender_ref._trigger_status_checks()
                    print("[+] Added {} subdomains to Whiteboard".format(count))
                result_dialog.dispose()
        
        class CancelAction(ActionListener):
            def actionPerformed(self_inner, event):
                result_dialog.dispose()
        
        select_all_btn.addActionListener(SelectAllAction())
        deselect_all_btn.addActionListener(DeselectAllAction())
        add_btn.addActionListener(AddSelectedAction())
        cancel_btn.addActionListener(CancelAction())
        
        btn_panel.add(select_all_btn)
        btn_panel.add(deselect_all_btn)
        btn_panel.add(add_btn)
        btn_panel.add(cancel_btn)
        panel.add(btn_panel, BorderLayout.SOUTH)
        
        result_dialog.setContentPane(panel)
        result_dialog.setVisible(True)
    
    def _save_custom_patterns(self):
        """Save custom patterns to Burp settings."""
        try:
            # Get patterns that are not in defaults
            ext_dir = self._get_extension_dir()
            patterns_dir = os.path.join(ext_dir, "patterns")
            
            default_patterns = {}
            patterns_file = os.path.join(patterns_dir, "default_patterns.json")
            if os.path.exists(patterns_file):
                with open(patterns_file, 'r') as f:
                    default_patterns = json.load(f)
            
            custom = {}
            for category, patterns in self._patterns.items():
                default_set = set(default_patterns.get(category, []))
                custom_patterns = [p for p in patterns if p not in default_set]
                if custom_patterns:
                    custom[category] = custom_patterns
            
            self._callbacks.saveExtensionSetting("custom_patterns", json.dumps(custom))
            print("[+] Custom patterns saved")
        except Exception as e:
            print("[-] Error saving custom patterns: {}".format(str(e)))
    
    def _save_custom_noise(self):
        """Save custom noise filters to Burp settings."""
        try:
            ext_dir = self._get_extension_dir()
            patterns_dir = os.path.join(ext_dir, "patterns")
            
            default_noise = {}
            noise_file = os.path.join(patterns_dir, "noise_filters.json")
            if os.path.exists(noise_file):
                with open(noise_file, 'r') as f:
                    default_noise = json.load(f)
            
            custom = {}
            for filter_type, filters in self._noise_filters.items():
                default_set = set(default_noise.get(filter_type, []))
                custom_filters = [f for f in filters if f not in default_set]
                if custom_filters:
                    custom[filter_type] = custom_filters
            
            self._callbacks.saveExtensionSetting("custom_noise", json.dumps(custom))
            print("[+] Custom noise filters saved")
        except Exception as e:
            print("[-] Error saving custom noise filters: {}".format(str(e)))
    
    # ==================== UI Building ====================
    
    def _build_ui(self):
        """Build the main UI panel."""
        self._main_panel = JPanel(BorderLayout())
        
        # Create tabbed pane for Results, Patterns, and Settings
        self._tabbed_pane = JTabbedPane()
        
        # Build results panel
        results_panel = self._build_results_panel()
        self._tabbed_pane.addTab("Results", results_panel)
        
        # Build patterns panel
        patterns_panel = self._build_patterns_panel()
        patterns_scroll = JScrollPane(patterns_panel)
        patterns_scroll.getVerticalScrollBar().setUnitIncrement(16)
        self._tabbed_pane.addTab("Patterns", patterns_scroll)
        
        # Build whiteboard panel
        whiteboard_panel = self._build_whiteboard_panel()
        self._tabbed_pane.addTab("Whiteboard", whiteboard_panel)
        
        # Build mappings panel
        mappings_panel = self._build_mappings_panel()
        self._tabbed_pane.addTab("Mappings", mappings_panel)
        
        # Build settings panel
        settings_panel = self._build_settings_panel()
        settings_scroll = JScrollPane(settings_panel)
        settings_scroll.getVerticalScrollBar().setUnitIncrement(16)
        self._tabbed_pane.addTab("Settings", settings_scroll)
        
        self._main_panel.add(self._tabbed_pane, BorderLayout.CENTER)
    
    def _build_results_panel(self):
        """Build the results panel with table and request/response viewer."""
        panel = JPanel(BorderLayout())
        
        # Top panel with filter controls
        top_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        top_panel.add(JLabel("Filter by Category:"))
        
        categories = ["All", "Endpoints", "URLs", "Secrets", "Files", "Emails", "Configurations"]
        self._category_filter = JComboBox(categories)
        self._category_filter.addActionListener(CategoryFilterListener(self))
        top_panel.add(self._category_filter)
        
        # Add clear button
        clear_btn = JButton("Clear Results")
        clear_btn.addActionListener(ClearResultsListener(self))
        top_panel.add(clear_btn)
        
        # Add export button
        export_btn = JButton("Export Results")
        export_btn.addActionListener(ExportResultsListener(self))
        top_panel.add(export_btn)
        
        # Search field
        top_panel.add(Box.createHorizontalStrut(10))
        top_panel.add(JLabel("Search:"))
        self._search_field = JTextField(20)
        self._search_field.addActionListener(SearchFilterListener(self))
        top_panel.add(self._search_field)
        
        search_btn = JButton("Filter")
        search_btn.addActionListener(SearchFilterListener(self))
        top_panel.add(search_btn)
        
        # Results count label
        self._results_count_label = JLabel("Results: 0")
        top_panel.add(Box.createHorizontalStrut(20))
        top_panel.add(self._results_count_label)
        
        panel.add(top_panel, BorderLayout.NORTH)
        
        # Create results table
        self._table_model = ResultsTableModel(self)
        self._results_table = JTable(self._table_model)
        self._results_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._results_table.getSelectionModel().addListSelectionListener(ResultSelectionListener(self))
        
        # Add mouse listener for context menu
        self._results_table.addMouseListener(ResultsTableMouseListener(self))
        
        # Set column widths
        self._results_table.getColumnModel().getColumn(0).setPreferredWidth(80)
        self._results_table.getColumnModel().getColumn(1).setPreferredWidth(70)
        self._results_table.getColumnModel().getColumn(2).setPreferredWidth(380)
        self._results_table.getColumnModel().getColumn(3).setPreferredWidth(270)
        
        # Color-code severity column with editable dropdown
        self._results_table.getColumnModel().getColumn(1).setCellRenderer(SeverityCellRenderer())
        severity_combo = JComboBox(["High", "Medium", "Low", "Info"])
        self._results_table.getColumnModel().getColumn(1).setCellEditor(DefaultCellEditor(severity_combo))
        
        # Set row height
        self._results_table.setRowHeight(25)
        
        # Create scroll pane for table
        table_scroll = JScrollPane(self._results_table)
        table_scroll.setPreferredSize(Dimension(800, 300))
        
        # Create request/response viewers
        self._request_viewer = self._callbacks.createMessageEditor(self, False)
        self._response_viewer = self._callbacks.createMessageEditor(self, False)
        
        # Create split pane for request/response
        req_resp_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        
        request_panel = JPanel(BorderLayout())
        request_panel.add(JLabel(" Request", SwingConstants.LEFT), BorderLayout.NORTH)
        request_panel.add(self._request_viewer.getComponent(), BorderLayout.CENTER)
        
        response_panel = JPanel(BorderLayout())
        response_panel.add(JLabel(" Response", SwingConstants.LEFT), BorderLayout.NORTH)
        response_panel.add(self._response_viewer.getComponent(), BorderLayout.CENTER)
        
        req_resp_split.setLeftComponent(request_panel)
        req_resp_split.setRightComponent(response_panel)
        req_resp_split.setResizeWeight(0.5)
        
        # Create main split pane
        main_split = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        main_split.setTopComponent(table_scroll)
        main_split.setBottomComponent(req_resp_split)
        main_split.setResizeWeight(0.4)
        
        panel.add(main_split, BorderLayout.CENTER)
        
        return panel
    
    def _build_patterns_panel(self):
        """Build the patterns panel with custom patterns and pattern tester."""
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        # Custom patterns section
        patterns_panel = JPanel(BorderLayout())
        patterns_panel.setBorder(BorderFactory.createTitledBorder("Custom Patterns"))
        patterns_panel.setAlignmentX(0.0)
        
        patterns_top = JPanel(FlowLayout(FlowLayout.LEFT))
        patterns_top.add(JLabel("Category:"))
        self._pattern_category = JComboBox(["endpoints", "urls", "secrets", "files", "emails", "configurations"])
        self._pattern_category.addActionListener(PatternCategoryListener(self))
        patterns_top.add(self._pattern_category)
        patterns_panel.add(patterns_top, BorderLayout.NORTH)
        
        self._patterns_text = JTextArea(8, 50)
        self._patterns_text.setFont(Font("Monospaced", Font.PLAIN, 12))
        patterns_scroll = JScrollPane(self._patterns_text)
        patterns_panel.add(patterns_scroll, BorderLayout.CENTER)
        
        patterns_buttons = JPanel(FlowLayout(FlowLayout.LEFT))
        add_pattern_btn = JButton("Add Pattern")
        add_pattern_btn.addActionListener(AddPatternListener(self))
        patterns_buttons.add(add_pattern_btn)
        
        import_patterns_btn = JButton("Import from File")
        import_patterns_btn.addActionListener(ImportPatternsListener(self))
        patterns_buttons.add(import_patterns_btn)
        
        save_patterns_btn = JButton("Save Patterns")
        save_patterns_btn.addActionListener(SavePatternsListener(self))
        patterns_buttons.add(save_patterns_btn)
        
        patterns_panel.add(patterns_buttons, BorderLayout.SOUTH)
        
        panel.add(patterns_panel)
        panel.add(Box.createVerticalStrut(10))
        
        # Pattern Tester section
        tester_panel = JPanel(BorderLayout())
        tester_panel.setBorder(BorderFactory.createTitledBorder("Pattern Tester"))
        tester_panel.setAlignmentX(0.0)
        
        tester_top = JPanel(FlowLayout(FlowLayout.LEFT))
        tester_top.add(JLabel("Regex:"))
        self._tester_regex_field = JTextField(40)
        self._tester_regex_field.setFont(Font("Monospaced", Font.PLAIN, 12))
        tester_top.add(self._tester_regex_field)
        test_btn = JButton("Test")
        test_btn.addActionListener(PatternTesterListener(self))
        tester_top.add(test_btn)
        tester_panel.add(tester_top, BorderLayout.NORTH)
        
        tester_center = JPanel()
        tester_center.setLayout(BoxLayout(tester_center, BoxLayout.Y_AXIS))
        
        sample_label = JPanel(FlowLayout(FlowLayout.LEFT))
        sample_label.add(JLabel("Sample text (paste response body or any text to test against):"))
        tester_center.add(sample_label)
        
        self._tester_sample_text = JTextArea(6, 50)
        self._tester_sample_text.setFont(Font("Monospaced", Font.PLAIN, 12))
        tester_center.add(JScrollPane(self._tester_sample_text))
        
        results_label = JPanel(FlowLayout(FlowLayout.LEFT))
        results_label.add(JLabel("Matches found:"))
        tester_center.add(results_label)
        
        self._tester_results_text = JTextArea(4, 50)
        self._tester_results_text.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._tester_results_text.setEditable(False)
        self._tester_results_text.setBackground(Color(245, 245, 245))
        tester_center.add(JScrollPane(self._tester_results_text))
        
        tester_panel.add(tester_center, BorderLayout.CENTER)
        
        panel.add(tester_panel)
        
        # Load initial pattern values
        self._update_patterns_display()
        
        return panel
    
    def _build_whiteboard_panel(self):
        """Build the Whiteboard panel with categorized investigation items."""
        self._wb_main_panel = JPanel(BorderLayout())
        
        # Toolbar
        toolbar = JPanel(FlowLayout(FlowLayout.LEFT))
        toolbar.add(JLabel("Investigation Whiteboard"))
        toolbar.add(Box.createHorizontalStrut(20))
        
        add_manual_btn = JButton("Add Item")
        add_manual_btn.addActionListener(WhiteboardAddManualListener(self))
        toolbar.add(add_manual_btn)
        
        export_wb_btn = JButton("Export Whiteboard")
        export_wb_btn.addActionListener(WhiteboardExportListener(self))
        toolbar.add(export_wb_btn)
        
        clear_wb_btn = JButton("Clear All")
        clear_wb_btn.addActionListener(WhiteboardClearListener(self))
        toolbar.add(clear_wb_btn)
        
        self._wb_count_label = JLabel("Items: 0")
        toolbar.add(Box.createHorizontalStrut(20))
        toolbar.add(self._wb_count_label)
        
        self._wb_main_panel.add(toolbar, BorderLayout.NORTH)
        
        # Scrollable content with category sections
        self._wb_content = JPanel()
        self._wb_content.setLayout(BoxLayout(self._wb_content, BoxLayout.Y_AXIS))
        self._wb_content.setBorder(BorderFactory.createEmptyBorder(5, 10, 10, 10))
        
        # Category colors for visual distinction
        self._wb_category_colors = {
            'Domains': Color(52, 152, 219),
            'Secrets': Color(231, 76, 60),
            'Files': Color(230, 126, 34),
            'Paths': Color(155, 89, 182),
            'Emails': Color(26, 188, 156),
            'URLs': Color(41, 128, 185),
            'Configurations': Color(243, 156, 18),
            'Other': Color(149, 165, 166)
        }
        
        self._wb_text_areas = {}
        for category in self._whiteboard:
            cat_panel = JPanel(BorderLayout())
            cat_panel.setAlignmentX(0.0)
            
            # Color-coded header
            header = JPanel(FlowLayout(FlowLayout.LEFT))
            color = self._wb_category_colors.get(category, Color.GRAY)
            header.setBackground(color)
            cat_label = JLabel("  {}  ".format(category))
            cat_label.setForeground(Color.WHITE)
            cat_label.setFont(Font("SansSerif", Font.BOLD, 13))
            header.add(cat_label)
            
            count_label = JLabel("(0)")
            count_label.setForeground(Color(255, 255, 255, 200))
            count_label.setFont(Font("SansSerif", Font.PLAIN, 11))
            header.add(count_label)
            
            cat_panel.add(header, BorderLayout.NORTH)
            
            # Text area for items
            text_area = JTextArea(3, 50)
            text_area.setFont(Font("Monospaced", Font.PLAIN, 12))
            text_area.setEditable(False)
            text_area.setLineWrap(True)
            text_area.setWrapStyleWord(True)
            
            # Context menu for text area items
            text_area.addMouseListener(WhiteboardItemMouseListener(self, category, text_area))
            
            cat_panel.add(JScrollPane(text_area), BorderLayout.CENTER)
            
            self._wb_text_areas[category] = (text_area, count_label)
            self._wb_content.add(cat_panel)
            self._wb_content.add(Box.createVerticalStrut(5))
        
        wb_scroll = JScrollPane(self._wb_content)
        wb_scroll.getVerticalScrollBar().setUnitIncrement(16)
        self._wb_main_panel.add(wb_scroll, BorderLayout.CENTER)
        
        # Populate initial data
        self._refresh_whiteboard_ui()
        
        return self._wb_main_panel
    
    def _refresh_whiteboard_ui(self):
        """Refresh all whiteboard text areas with current data."""
        try:
            total = 0
            status_enabled = self._settings.get("status_checks_enabled", False)
            for category, (text_area, count_label) in self._wb_text_areas.items():
                items = self._whiteboard.get(category, [])
                if category in ('Domains', 'URLs') and items:
                    display_lines = []
                    for item in items:
                        if status_enabled:
                            status = self._wb_status_cache.get(item, "checking...")
                            display_lines.append("{}  [{}]".format(item, status))
                        else:
                            display_lines.append("{}  [status checks off]".format(item))
                    text_area.setText("\n".join(display_lines))
                else:
                    text_area.setText("\n".join(items))
                count_label.setText("({})".format(len(items)))
                total += len(items)
            self._wb_count_label.setText("Items: {}".format(total))
        except Exception:
            pass
    
    def _trigger_status_checks(self):
        """Start background HTTP status checks if enabled."""
        if not self._settings.get("status_checks_enabled", False):
            return
        
        # Increment generation to invalidate any stale threads
        self._wb_check_generation = getattr(self, '_wb_check_generation', 0) + 1
        gen = self._wb_check_generation
        
        print("[*] Starting status check thread (gen={})...".format(gen))
        extender_ref = self
        
        class StatusCheckRunnable(Runnable):
            def run(self_inner):
                extender_ref._run_status_checks(gen)
        
        t = JThread(StatusCheckRunnable())
        t.setDaemon(True)
        t.start()
    
    def _run_status_checks(self, generation):
        """Background worker: check HTTP status for all Domains and URLs items."""
        print("[*] Status check thread started (gen={})".format(generation))
        try:
            items_to_check = []
            for category in ('Domains', 'URLs'):
                for item in self._whiteboard.get(category, []):
                    if item not in self._wb_status_cache:
                        items_to_check.append(item)
            
            print("[*] Status checks: {} items to check".format(len(items_to_check)))
            
            for item in items_to_check:
                # Stop if disabled or a newer generation started
                if not self._settings.get("status_checks_enabled", False):
                    print("[*] Status checks disabled, stopping")
                    break
                if getattr(self, '_wb_check_generation', 0) != generation:
                    print("[*] Newer check generation detected, stopping gen={}".format(generation))
                    break
                
                print("[*] Checking: {}".format(item[:80]))
                status = self._check_http_status_with_timeout(item)
                print("[*] Result: {} -> {}".format(item[:60], status))
                
                self._wb_status_cache[item] = status
                
                extender_ref = self
                class RefreshRunnable(Runnable):
                    def run(self_inner):
                        extender_ref._refresh_whiteboard_ui()
                SwingUtilities.invokeLater(RefreshRunnable())
                
                # Throttle: 2 seconds between requests
                try:
                    JThread.sleep(2000)
                except Exception:
                    pass
        except Exception as e:
            print("[-] Status check error: {}".format(str(e)))
        finally:
            print("[*] Status checks finished (gen={})".format(generation))
    
    def _check_http_status_with_timeout(self, item, timeout_ms=6000):
        """Check HTTP status with a hard timeout using a sub-thread."""
        result_holder = [None]
        
        class CheckRunnable(Runnable):
            def run(self_inner):
                result_holder[0] = BurpExtender._check_http_status(item)
        
        checker = JThread(CheckRunnable())
        checker.setDaemon(True)
        checker.start()
        
        try:
            checker.join(timeout_ms)
        except Exception:
            pass
        
        if result_holder[0] is not None:
            return result_holder[0]
        
        # Thread didn't finish in time — it's stuck
        print("[*] Timeout checking: {}".format(item[:60]))
        try:
            checker.interrupt()
        except Exception:
            pass
        return "TIMEOUT"
    
    @staticmethod
    def _check_http_status(item):
        """Check HTTP status of a domain or URL via HEAD request."""
        # Build target URL
        if item.startswith('http://') or item.startswith('https://'):
            target = item
        else:
            target = "https://{}".format(item)
        
        # Try HTTPS first
        result = BurpExtender._do_head_request(target)
        if result:
            return result
        
        # Fallback to HTTP
        plain = item.replace('https://', '').replace('http://', '')
        result = BurpExtender._do_head_request("http://{}".format(plain))
        if result:
            return result
        
        return "NO RESPONSE"
    
    @staticmethod
    def _do_head_request(target):
        """Perform a single HEAD request. Returns status code string or None."""
        conn = None
        try:
            url = URL(target)
            conn = url.openConnection()
            conn.setRequestMethod("HEAD")
            conn.setConnectTimeout(3000)
            conn.setReadTimeout(3000)
            conn.setInstanceFollowRedirects(True)
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (compatible)")
            conn.setUseCaches(False)
            code = conn.getResponseCode()
            return str(code)
        except Exception:
            return None
        finally:
            if conn:
                try:
                    conn.disconnect()
                except Exception:
                    pass
    
    def _export_whiteboard(self):
        """Export whiteboard to a file."""
        chooser = JFileChooser()
        chooser.setDialogTitle("Export Whiteboard")
        chooser.setFileFilter(FileNameExtensionFilter("Text Files", ["txt"]))
        chooser.setFileFilter(FileNameExtensionFilter("JSON Files", ["json"]))
        
        if chooser.showSaveDialog(self._main_panel) == JFileChooser.APPROVE_OPTION:
            file_path = str(chooser.getSelectedFile().getAbsolutePath())
            try:
                if file_path.endswith('.json'):
                    with open(file_path, 'w') as f:
                        json.dump(self._whiteboard, f, indent=2)
                else:
                    if not file_path.endswith('.txt'):
                        file_path += '.txt'
                    with open(file_path, 'w') as f:
                        for category, items in self._whiteboard.items():
                            if items:
                                f.write("=" * 50 + "\n")
                                f.write("  {}\n".format(category.upper()))
                                f.write("=" * 50 + "\n")
                                for item in items:
                                    f.write("  {}\n".format(item))
                                f.write("\n")
                
                JOptionPane.showMessageDialog(
                    self._main_panel,
                    "Whiteboard exported to: {}".format(file_path),
                    "Export Complete",
                    JOptionPane.INFORMATION_MESSAGE
                )
            except Exception as e:
                JOptionPane.showMessageDialog(
                    self._main_panel,
                    "Error exporting: {}".format(str(e)),
                    "Export Error",
                    JOptionPane.ERROR_MESSAGE
                )
    
    # ==================== Source Maps / Mappings ====================
    
    def _collect_source_map(self, match, js_url):
        """Collect a sourceMappingURL finding for the Mappings tab."""
        # Extract the .map filename from the match (e.g., "//# sourceMappingURL=app.js.map")
        import re as _re
        m = _re.search(r'sourceMappingURL\s*=\s*(\S+)', match)
        if not m:
            return
        map_ref = m.group(1).strip()
        map_url = self._resolve_map_url(js_url, map_ref)
        
        if map_url in self._source_maps_seen:
            return
        self._source_maps_seen.add(map_url)
        
        entry = {
            'js_url': js_url,
            'map_url': map_url,
            'status': 'Pending',
            'sources': [],
            'sourcesContent': [],
            'names': []
        }
        self._source_maps.append(entry)
        
        try:
            self._refresh_mappings_ui()
        except Exception:
            pass
        print("[+] Source map discovered: {}".format(map_url[:80]))
    
    @staticmethod
    def _resolve_map_url(js_url, map_ref):
        """Resolve a .map reference relative to the JS file URL."""
        if map_ref.startswith('http://') or map_ref.startswith('https://'):
            return map_ref
        if map_ref.startswith('//'):
            protocol = 'https:' if js_url.startswith('https') else 'http:'
            return protocol + map_ref
        # Relative path — resolve against JS URL
        base = js_url.rsplit('/', 1)[0] if '/' in js_url else js_url
        return base + '/' + map_ref
    
    def _build_mappings_panel(self):
        """Build the Mappings panel for source map extraction and analysis."""
        self._map_panel = JPanel(BorderLayout())
        self._map_findings = []
        
        # Toolbar
        toolbar = JPanel(FlowLayout(FlowLayout.LEFT))
        toolbar.add(JLabel("Source Map Extractor"))
        toolbar.add(Box.createHorizontalStrut(20))
        
        fetch_all_btn = JButton("Fetch All")
        fetch_all_btn.addActionListener(MappingsFetchAllListener(self))
        toolbar.add(fetch_all_btn)
        
        scan_btn = JButton("Scan Sources for Secrets")
        scan_btn.addActionListener(MappingsScanListener(self))
        toolbar.add(scan_btn)
        
        export_btn = JButton("Export Sources")
        export_btn.addActionListener(MappingsExportListener(self))
        toolbar.add(export_btn)
        
        self._map_count_label = JLabel("Maps: 0")
        toolbar.add(Box.createHorizontalStrut(20))
        toolbar.add(self._map_count_label)
        
        self._map_panel.add(toolbar, BorderLayout.NORTH)
        
        # Main split: left (maps + files + findings) | right (source viewer)
        main_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        
        # Left panel: 3 sections stacked
        left_panel = JPanel()
        left_panel.setLayout(BoxLayout(left_panel, BoxLayout.Y_AXIS))
        
        # Map list
        map_list_panel = JPanel(BorderLayout())
        map_list_panel.add(JLabel(" Discovered Source Maps"), BorderLayout.NORTH)
        self._map_list_model = DefaultListModel()
        self._map_list = JList(self._map_list_model)
        self._map_list.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._map_list.addListSelectionListener(MappingsMapSelectionListener(self))
        self._map_list.addMouseListener(MappingsMapMouseListener(self))
        map_scroll = JScrollPane(self._map_list)
        map_scroll.setPreferredSize(Dimension(400, 120))
        map_list_panel.add(map_scroll, BorderLayout.CENTER)
        left_panel.add(map_list_panel)
        
        # Source files list
        files_panel = JPanel(BorderLayout())
        files_panel.add(JLabel(" Source Files"), BorderLayout.NORTH)
        self._map_files_model = DefaultListModel()
        self._map_files_list = JList(self._map_files_model)
        self._map_files_list.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._map_files_list.addListSelectionListener(MappingsFileSelectionListener(self))
        files_scroll = JScrollPane(self._map_files_list)
        files_scroll.setPreferredSize(Dimension(400, 150))
        files_panel.add(files_scroll, BorderLayout.CENTER)
        left_panel.add(files_panel)
        
        # Findings list
        findings_panel = JPanel(BorderLayout())
        self._map_findings_label = JLabel(" Findings (0)")
        findings_panel.add(self._map_findings_label, BorderLayout.NORTH)
        self._map_findings_model = DefaultListModel()
        self._map_findings_list = JList(self._map_findings_model)
        self._map_findings_list.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._map_findings_list.addListSelectionListener(MappingsFindingsSelectionListener(self))
        findings_scroll = JScrollPane(self._map_findings_list)
        findings_scroll.setPreferredSize(Dimension(400, 150))
        findings_panel.add(findings_scroll, BorderLayout.CENTER)
        left_panel.add(findings_panel)
        
        left_scroll = JScrollPane(left_panel)
        main_split.setLeftComponent(left_scroll)
        
        # Right panel: search bar + source code viewer
        viewer_panel = JPanel(BorderLayout())
        
        # Search bar
        search_bar = JPanel(FlowLayout(FlowLayout.LEFT))
        self._map_source_label = JLabel(" Source Code")
        search_bar.add(self._map_source_label)
        search_bar.add(Box.createHorizontalStrut(10))
        search_bar.add(JLabel("Search:"))
        self._map_search_field = JTextField(20)
        self._map_search_field.addActionListener(MappingsSearchListener(self))
        search_bar.add(self._map_search_field)
        find_btn = JButton("Find")
        find_btn.addActionListener(MappingsSearchListener(self))
        search_bar.add(find_btn)
        next_btn = JButton("Next")
        next_btn.addActionListener(MappingsSearchNextListener(self))
        search_bar.add(next_btn)
        viewer_panel.add(search_bar, BorderLayout.NORTH)
        
        self._map_source_viewer = JTextArea()
        self._map_source_viewer.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._map_source_viewer.setEditable(False)
        self._map_source_viewer.setTabSize(4)
        viewer_panel.add(JScrollPane(self._map_source_viewer), BorderLayout.CENTER)
        
        main_split.setRightComponent(viewer_panel)
        main_split.setResizeWeight(0.3)
        
        self._map_panel.add(main_split, BorderLayout.CENTER)
        
        # Search state
        self._map_search_pos = 0
        
        return self._map_panel
    
    def _refresh_mappings_ui(self):
        """Refresh the mappings list UI."""
        try:
            self._map_list_model.clear()
            for entry in self._source_maps:
                self._map_list_model.addElement("[{}] {}".format(entry['status'], entry['map_url'][:100]))
            self._map_count_label.setText("Maps: {}".format(len(self._source_maps)))
        except Exception:
            pass
    
    def _fetch_source_map(self, entry):
        """Fetch and parse a single .map file."""
        entry['status'] = 'Fetching...'
        self._refresh_mappings_ui()
        
        conn = None
        try:
            url = URL(entry['map_url'])
            conn = url.openConnection()
            conn.setRequestMethod("GET")
            conn.setConnectTimeout(10000)
            conn.setReadTimeout(15000)
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (compatible)")
            
            code = conn.getResponseCode()
            if code != 200:
                entry['status'] = 'HTTP {}'.format(code)
                return
            
            reader = BufferedReader(InputStreamReader(conn.getInputStream(), "UTF-8"))
            sb = []
            line = reader.readLine()
            while line is not None:
                sb.append(line)
                line = reader.readLine()
            reader.close()
            
            raw = "".join(sb)
            parsed = json.loads(raw)
            
            entry['sources'] = parsed.get('sources', [])
            entry['sourcesContent'] = parsed.get('sourcesContent', [])
            entry['names'] = parsed.get('names', [])
            entry['status'] = 'Fetched ({} files)'.format(len(entry['sources']))
            print("[+] Fetched source map: {} ({} sources)".format(
                entry['map_url'][:60], len(entry['sources'])))
            
        except Exception as e:
            entry['status'] = 'Error: {}'.format(str(e)[:50])
            print("[-] Error fetching {}: {}".format(entry['map_url'][:60], str(e)))
        finally:
            if conn:
                try:
                    conn.disconnect()
                except Exception:
                    pass
    
    def _fetch_all_maps_async(self):
        """Fetch all pending source maps in background."""
        pending = [e for e in self._source_maps if e['status'] == 'Pending']
        if not pending:
            JOptionPane.showMessageDialog(self._main_panel,
                "No pending source maps to fetch.", "Mappings", JOptionPane.INFORMATION_MESSAGE)
            return
        
        extender_ref = self
        class FetchRunnable(Runnable):
            def run(self_inner):
                for entry in pending:
                    extender_ref._fetch_source_map(entry)
                    class Refresh(Runnable):
                        def run(self_r):
                            extender_ref._refresh_mappings_ui()
                    SwingUtilities.invokeLater(Refresh())
                    try:
                        JThread.sleep(500)
                    except Exception:
                        pass
                print("[+] All source maps fetched")
        
        t = JThread(FetchRunnable())
        t.setDaemon(True)
        t.start()
    
    def _scan_source_maps_async(self):
        """Launch source map scan in background thread."""
        self._map_findings = []
        self._map_findings_model.clear()
        self._map_findings_label.setText(" Findings (scanning...)")
        
        extender_ref = self
        class ScanRunnable(Runnable):
            def run(self_inner):
                extender_ref._scan_source_maps_worker()
        
        t = JThread(ScanRunnable())
        t.setDaemon(True)
        t.start()
    
    def _scan_source_maps_worker(self):
        """Background worker: scan source map contents for patterns."""
        findings = []
        seen = set()
        
        for map_idx, entry in enumerate(self._source_maps):
            sources = entry.get('sources', [])
            contents = entry.get('sourcesContent', [])
            map_url = entry.get('map_url', '')
            
            if not contents:
                continue
            
            for source_idx, content in enumerate(contents):
                if not content:
                    continue
                source_name = sources[source_idx] if source_idx < len(sources) else 'unknown'
                source_url = "[MAP] {} from {}".format(source_name, map_url.split('/')[-1])
                
                for category, compiled_patterns in self._compiled_patterns.items():
                    for pattern in compiled_patterns:
                        try:
                            matches = pattern.findall(content)
                            for match in matches:
                                if isinstance(match, tuple):
                                    match = match[0] if match[0] else ''.join(match)
                                match_str = str(match).strip()
                                if not match_str or len(match_str) < 3:
                                    continue
                                if self._is_noise(match_str, category):
                                    continue
                                if category == 'secrets' and self._is_low_entropy_generic(match_str):
                                    continue
                                dedup_key = (category, match_str)
                                if dedup_key in seen:
                                    continue
                                seen.add(dedup_key)
                                finding = {
                                    'category': category.capitalize(),
                                    'match': match_str[:200],
                                    'source': source_name,
                                    'map': map_url.split('/')[-1],
                                    'map_idx': map_idx,
                                    'source_idx': source_idx
                                }
                                findings.append(finding)
                                self._add_result(category, match_str, source_url, None)
                        except Exception:
                            pass
                
                # Batch UI update every 50 findings
                if len(findings) % 50 < 5 and findings:
                    batch = findings[:]
                    extender_ref = self
                    class BatchUpdate(Runnable):
                        def __init__(self_inner, b):
                            self_inner._b = b
                        def run(self_inner):
                            extender_ref._map_findings_label.setText(
                                " Findings ({}, scanning...)".format(len(self_inner._b)))
                    SwingUtilities.invokeLater(BatchUpdate(batch))
        
        self._map_findings = findings
        extender_ref = self
        class FinalUpdate(Runnable):
            def run(self_inner):
                extender_ref._map_findings_model.clear()
                for f in extender_ref._map_findings:
                    extender_ref._map_findings_model.addElement("[{}] {} | {}".format(
                        f['category'], f['match'][:80], f['source']))
                extender_ref._map_findings_label.setText(
                    " Findings ({})".format(len(extender_ref._map_findings)))
        SwingUtilities.invokeLater(FinalUpdate())
        print("[+] Source map scan: {} findings".format(len(findings)))
    
    def _export_sources(self):
        """Export extracted source files to a directory."""
        chooser = JFileChooser()
        chooser.setDialogTitle("Select Directory to Export Sources")
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        
        if chooser.showSaveDialog(self._main_panel) != JFileChooser.APPROVE_OPTION:
            return
        
        base_dir = str(chooser.getSelectedFile().getAbsolutePath())
        count = 0
        
        for entry in self._source_maps:
            sources = entry.get('sources', [])
            contents = entry.get('sourcesContent', [])
            map_name = entry['map_url'].split('/')[-1].replace('.map', '')
            
            for i, content in enumerate(contents):
                if not content:
                    continue
                source_path = sources[i] if i < len(sources) else 'file_{}'.format(i)
                # Clean path for filesystem
                clean_path = source_path.replace('webpack://', '').replace('../', '').lstrip('/')
                full_path = os.path.join(base_dir, map_name, clean_path)
                
                try:
                    dir_path = os.path.dirname(full_path)
                    if not os.path.exists(dir_path):
                        os.makedirs(dir_path)
                    with open(full_path, 'w') as f:
                        f.write(content)
                    count += 1
                except Exception as e:
                    print("[-] Error writing {}: {}".format(full_path, str(e)))
        
        JOptionPane.showMessageDialog(self._main_panel,
            "Exported {} source files to:\n{}".format(count, base_dir),
            "Export Complete", JOptionPane.INFORMATION_MESSAGE)
        print("[+] Exported {} source files to {}".format(count, base_dir))
    
    def _build_settings_panel(self):
        """Build the settings panel."""
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        # General settings section
        general_panel = JPanel()
        general_panel.setLayout(BoxLayout(general_panel, BoxLayout.Y_AXIS))
        general_panel.setBorder(BorderFactory.createTitledBorder("General Settings"))
        general_panel.setAlignmentX(0.0)
        
        self._scope_checkbox = JCheckBox("Only analyze in-scope items")
        self._scope_checkbox.setSelected(self._settings.get("only_in_scope", False))
        self._scope_checkbox.addActionListener(SettingsChangeListener(self))
        general_panel.add(self._scope_checkbox)
        
        self._skip_media_checkbox = JCheckBox("Skip media-type responses (images, videos, fonts)")
        self._skip_media_checkbox.setSelected(self._settings.get("skip_media", True))
        self._skip_media_checkbox.addActionListener(SettingsChangeListener(self))
        general_panel.add(self._skip_media_checkbox)
        
        # Whiteboard HTTP status checks
        self._status_checks_checkbox = JCheckBox("Enable HTTP status checks on Whiteboard domains/URLs (background, non-aggressive)")
        self._status_checks_checkbox.setSelected(self._settings.get("status_checks_enabled", False))
        self._status_checks_checkbox.addActionListener(StatusChecksToggleListener(self))
        general_panel.add(self._status_checks_checkbox)
        
        # Merge duplicates setting
        merge_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        merge_panel.add(JLabel("Merge Duplicates:"))
        merge_options = ["By Match Only", "By Match + URL", "No Merging (Show All)"]
        self._merge_combo = JComboBox(merge_options)
        current_merge = self._settings.get("merge_duplicates", "match_only")
        if current_merge == "match_only":
            self._merge_combo.setSelectedIndex(0)
        elif current_merge == "match_and_url":
            self._merge_combo.setSelectedIndex(1)
        else:
            self._merge_combo.setSelectedIndex(2)
        self._merge_combo.addActionListener(MergeDuplicatesListener(self))
        merge_panel.add(self._merge_combo)
        general_panel.add(merge_panel)
        
        panel.add(general_panel)
        panel.add(Box.createVerticalStrut(10))
        
        # Noise filters section
        noise_panel = JPanel(BorderLayout())
        noise_panel.setBorder(BorderFactory.createTitledBorder("Noise Filters"))
        noise_panel.setAlignmentX(0.0)
        
        noise_top = JPanel(FlowLayout(FlowLayout.LEFT))
        noise_top.add(JLabel("Filter Type:"))
        self._noise_category = JComboBox(["domains", "strings", "paths"])
        self._noise_category.addActionListener(NoiseCategoryListener(self))
        noise_top.add(self._noise_category)
        noise_panel.add(noise_top, BorderLayout.NORTH)
        
        self._noise_text = JTextArea(6, 50)
        self._noise_text.setFont(Font("Monospaced", Font.PLAIN, 12))
        noise_scroll = JScrollPane(self._noise_text)
        noise_panel.add(noise_scroll, BorderLayout.CENTER)
        
        noise_buttons = JPanel(FlowLayout(FlowLayout.LEFT))
        add_noise_btn = JButton("Add Filter")
        add_noise_btn.addActionListener(AddNoiseListener(self))
        noise_buttons.add(add_noise_btn)
        
        import_noise_btn = JButton("Import from File")
        import_noise_btn.addActionListener(ImportNoiseListener(self))
        noise_buttons.add(import_noise_btn)
        
        save_noise_btn = JButton("Save Filters")
        save_noise_btn.addActionListener(SaveNoiseListener(self))
        noise_buttons.add(save_noise_btn)
        
        noise_panel.add(noise_buttons, BorderLayout.SOUTH)
        
        panel.add(noise_panel)
        panel.add(Box.createVerticalStrut(10))
        
        # Exclusions (False Positives) section
        excl_panel = JPanel()
        excl_panel.setLayout(BoxLayout(excl_panel, BoxLayout.Y_AXIS))
        excl_panel.setBorder(BorderFactory.createTitledBorder("Exclusions (False Positives)"))
        excl_panel.setAlignmentX(0.0)
        
        # Excluded matches
        excl_matches_label = JPanel(FlowLayout(FlowLayout.LEFT))
        excl_matches_label.add(JLabel("Excluded Matches (one per line):"))
        excl_panel.add(excl_matches_label)
        
        self._excl_matches_text = JTextArea(4, 50)
        self._excl_matches_text.setFont(Font("Monospaced", Font.PLAIN, 12))
        excl_panel.add(JScrollPane(self._excl_matches_text))
        
        # Excluded URLs
        excl_urls_label = JPanel(FlowLayout(FlowLayout.LEFT))
        excl_urls_label.add(JLabel("Excluded URLs (one per line):"))
        excl_panel.add(excl_urls_label)
        
        self._excl_urls_text = JTextArea(4, 50)
        self._excl_urls_text.setFont(Font("Monospaced", Font.PLAIN, 12))
        excl_panel.add(JScrollPane(self._excl_urls_text))
        
        excl_buttons = JPanel(FlowLayout(FlowLayout.LEFT))
        save_excl_btn = JButton("Save Exclusions")
        save_excl_btn.addActionListener(SaveExclusionsListener(self))
        excl_buttons.add(save_excl_btn)
        
        clear_excl_btn = JButton("Clear All Exclusions")
        clear_excl_btn.addActionListener(ClearExclusionsListener(self))
        excl_buttons.add(clear_excl_btn)
        
        excl_panel.add(excl_buttons)
        
        panel.add(excl_panel)
        
        # Load initial noise/exclusion values
        self._update_noise_display()
        self._update_exclusions_display()
        
        return panel
    
    def _update_patterns_display(self):
        """Update the patterns text area based on selected category."""
        category = str(self._pattern_category.getSelectedItem())
        patterns = self._patterns.get(category, [])
        self._patterns_text.setText("\n".join(patterns))
    
    def _update_noise_display(self):
        """Update the noise text area based on selected type."""
        filter_type = str(self._noise_category.getSelectedItem())
        filters = self._noise_filters.get(filter_type, [])
        self._noise_text.setText("\n".join(filters))
    
    # ==================== ITab Implementation ====================
    
    def getTabCaption(self):
        """Return the tab caption."""
        return self.EXTENSION_NAME
    
    def getUiComponent(self):
        """Return the UI component."""
        return self._main_panel
    
    # ==================== IHttpListener Implementation ====================
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """Process HTTP messages."""
        if messageIsRequest:
            return
        
        try:
            # Get request/response info
            request_info = self._helpers.analyzeRequest(messageInfo)
            response_info = self._helpers.analyzeResponse(messageInfo.getResponse())
            
            url = request_info.getUrl()
            url_str = str(url)
            
            # Check if in scope
            if self._settings.get("only_in_scope", False):
                if not self._callbacks.isInScope(url):
                    return
            
            # Check content type for media
            if self._settings.get("skip_media", True):
                content_type = self._get_content_type(response_info)
                if self._is_media_type(content_type):
                    return
            
            # Check if should analyze
            if not self._should_analyze(url_str, response_info, messageInfo):
                return
            
            # Get response body
            response = messageInfo.getResponse()
            body_offset = response_info.getBodyOffset()
            body = self._helpers.bytesToString(response[body_offset:])
            
            # Analyze content
            self._analyze_content(body, url_str, messageInfo)
            
        except Exception as e:
            print("[-] Error processing message: {}".format(str(e)))
    
    def _get_content_type(self, response_info):
        """Extract content type from response headers."""
        headers = response_info.getHeaders()
        for header in headers:
            if header.lower().startswith("content-type:"):
                return header.split(":", 1)[1].strip().lower()
        return ""
    
    def _is_media_type(self, content_type):
        """Check if content type is a media type."""
        for media in self.MEDIA_TYPES:
            if media in content_type:
                return True
        return False
    
    def _should_analyze(self, url, response_info, messageInfo):
        """Determine if response should be analyzed."""
        # Check file extension
        url_lower = url.lower()
        for ext in self.ANALYZE_EXTENSIONS:
            if ext in url_lower:
                return True
        
        # Check content type
        content_type = self._get_content_type(response_info)
        for ct in self.ANALYZE_CONTENT_TYPES:
            if ct in content_type:
                return True
        
        # Check for script tags in HTML
        if 'text/html' in content_type or not content_type:
            response = messageInfo.getResponse()
            body_offset = response_info.getBodyOffset()
            body_preview = self._helpers.bytesToString(response[body_offset:body_offset + 50000])
            if '<script' in body_preview.lower():
                return True
        
        return False
    
    def _analyze_content(self, content, url, messageInfo):
        """Analyze content for patterns."""
        for category, compiled_patterns in self._compiled_patterns.items():
            for pattern in compiled_patterns:
                try:
                    matches = pattern.findall(content)
                    for match in matches:
                        # Handle tuple matches from groups
                        if isinstance(match, tuple):
                            match = match[0] if match[0] else ''.join(match)
                        
                        match_str = str(match).strip()
                        
                        # Skip empty matches
                        if not match_str or len(match_str) < 3:
                            continue
                        
                        # Apply noise filters
                        if self._is_noise(match_str, category):
                            continue
                        
                        # Phase D: Entropy filter for generic secret patterns
                        if category == 'secrets' and self._is_low_entropy_generic(match_str):
                            continue
                        
                        # Add result
                        self._add_result(category, match_str, url, messageInfo)
                        
                except Exception as e:
                    print("[-] Error matching pattern: {}".format(str(e)))
    
    def _compile_noise_filters(self):
        """Pre-compute lowercased noise filter lists for fast matching."""
        self._noise_domains_lower = [d.lower() for d in self._noise_filters.get("domains", [])]
        self._noise_strings_lower = [s.lower() for s in self._noise_filters.get("strings", [])]
        self._noise_paths_lower = [p.lower() for p in self._noise_filters.get("paths", [])]
    
    def _is_noise(self, match, category):
        """Check if match is noise."""
        match_lower = match.lower()
        
        # Check domain filters
        for domain in self._noise_domains_lower:
            if domain in match_lower:
                return True
        
        # Check string filters
        for string in self._noise_strings_lower:
            if string in match_lower:
                return True
        
        # Check path filters
        for path in self._noise_paths_lower:
            if path in match_lower:
                return True
        
        return False
    
    @staticmethod
    def _calculate_entropy(value):
        """Calculate Shannon entropy of a string (bits per character)."""
        if not value:
            return 0.0
        freq = {}
        for ch in value:
            freq[ch] = freq.get(ch, 0) + 1
        length = float(len(value))
        return -sum((count / length) * math.log(count / length, 2) for count in freq.values())
    
    def _is_low_entropy_generic(self, match_str):
        """Check if a secret match is a low-entropy generic pattern (likely FP).
        Only applies to generic patterns (password=, token=, etc.), not prefixed tokens."""
        # Skip entropy check for prefixed tokens — they are high confidence
        for prefix in self.HIGH_SECRET_PATTERNS:
            if prefix in match_str:
                return False
        # Extract the value portion after = or : delimiter
        for delim in ['=', ':']:
            if delim in match_str:
                value = match_str.split(delim, 1)[1].strip().strip('"').strip("'")
                if value and self._calculate_entropy(value) < self.ENTROPY_THRESHOLD:
                    return True
                return False
        return False
    
    def _get_severity(self, category, match):
        """Classify finding severity based on category and match content."""
        cat_lower = category.lower()
        base_severity = self.SEVERITY_RULES.get(cat_lower, 'Info')
        
        # Promote secrets with known high-value patterns
        if cat_lower == 'secrets':
            match_lower = match.lower()
            # Phase E: Demote test/dev/sandbox secrets to Medium
            for indicator in self.TEST_SECRET_INDICATORS:
                if indicator in match_lower:
                    return 'Medium'
            # Demote DB connection strings to localhost
            if ('://localhost' in match_lower or '://127.0.0.1' in match_lower) and '://' in match:
                return 'Low'
            for pattern in self.HIGH_SECRET_PATTERNS:
                if pattern in match:
                    return 'High'
            return 'Medium'
        
        # Promote URLs with sensitive indicators
        if cat_lower == 'urls':
            match_lower = match.lower()
            for pattern in self.MEDIUM_URL_PATTERNS:
                if pattern in match_lower:
                    return 'Medium'
        
        # Configurations: promote cloud metadata to High
        if cat_lower == 'configurations':
            if '169.254.169.254' in match:
                return 'High'
        
        return base_severity
    
    def _add_result(self, category, match, url, messageInfo):
        """Add a result to the table."""
        with self._lock:
            # Check for duplicates based on merge setting using set-based O(1) lookup
            merge_mode = self._settings.get("merge_duplicates", "match_only")
            cat_lower = category.lower()
            
            if merge_mode == "match_only":
                dedup_key = (cat_lower, match)
                if dedup_key in self._seen_match_only:
                    return
                self._seen_match_only.add(dedup_key)
            elif merge_mode == "match_and_url":
                dedup_key = (cat_lower, match, url)
                if dedup_key in self._seen_match_and_url:
                    return
                self._seen_match_and_url.add(dedup_key)
            
            result = {
                'category': category.capitalize(),
                'match': match[:200],  # Truncate long matches
                'url': url,
                'severity': self._get_severity(category, match),
                'messageInfo': messageInfo
            }
            self._results.append(result)
            
            # Report High/Medium findings as Burp Scanner issues
            severity = result['severity']
            if severity in ('High', 'Medium') and messageInfo:
                self._report_issue(result, messageInfo)
            
            # Auto-collect sourceMappingURL findings for Mappings tab
            if cat_lower == 'configurations' and 'sourcemappingurl' in match.lower():
                self._collect_source_map(match, url)
            
            # Update table on EDT
            from javax.swing import SwingUtilities
            SwingUtilities.invokeLater(UpdateTableRunnable(self))
    
    def _report_issue(self, result, messageInfo):
        """Report a finding as a Burp Scanner issue."""
        try:
            http_service = messageInfo.getHttpService()
            severity_map = {'High': 'High', 'Medium': 'Medium', 'Low': 'Low', 'Info': 'Information'}
            issue = LHFScanIssue(
                http_service,
                self._helpers.analyzeRequest(messageInfo).getUrl(),
                [messageInfo],
                "LowHangingFruits: {} {}".format(result['category'], result.get('severity', 'Info')),
                "The following {} was found in the response:<br><br><b>{}</b>".format(
                    result['category'].lower(), result['match']),
                severity_map.get(result.get('severity', 'Info'), 'Information'),
                "Certain"
            )
            self._callbacks.addScanIssue(issue)
        except Exception as e:
            print("[-] Error reporting issue: {}".format(str(e)))
    
    def _update_table(self):
        """Update the results table."""
        self._table_model.fireTableDataChanged()
        self._update_results_count()
    
    def _update_results_count(self):
        """Update the results count label."""
        filtered = self._get_filtered_results()
        total = len(self._results)
        if len(filtered) == total:
            self._results_count_label.setText("Results: {}".format(total))
        else:
            self._results_count_label.setText("Results: {} / {} (filtered)".format(len(filtered), total))
    
    def _get_filtered_results(self):
        """Get results filtered by category, search text, and exclusions."""
        filter_category = str(self._category_filter.getSelectedItem())
        search_text = str(self._search_field.getText()).strip().lower()
        excluded_matches = set(self._exclusions.get('matches', []))
        excluded_urls = set(self._exclusions.get('urls', []))
        
        results = self._results
        
        if filter_category != "All":
            results = [r for r in results if r['category'] == filter_category]
        
        if search_text:
            results = [r for r in results if search_text in r['match'].lower() or search_text in r['url'].lower()]
        
        if excluded_matches or excluded_urls:
            results = [r for r in results if r['match'] not in excluded_matches and r['url'] not in excluded_urls]
        
        return results
    
    def _update_exclusions_display(self):
        """Update the exclusions text areas in settings."""
        try:
            self._excl_matches_text.setText("\n".join(self._exclusions.get('matches', [])))
            self._excl_urls_text.setText("\n".join(self._exclusions.get('urls', [])))
        except Exception:
            pass
    
    # ==================== IContextMenuFactory Implementation ====================
    
    def createMenuItems(self, invocation):
        """Create context menu items."""
        menu_items = []
        
        # Only show for our table
        context = invocation.getInvocationContext()
        
        if self._results_table.getSelectedRow() >= 0:
            send_to_repeater = JMenuItem("Send to Repeater")
            send_to_repeater.addActionListener(SendToRepeaterListener(self))
            menu_items.append(send_to_repeater)
            
            send_to_intruder = JMenuItem("Send to Intruder")
            send_to_intruder.addActionListener(SendToIntruderListener(self))
            menu_items.append(send_to_intruder)
            
            send_resp_comparer = JMenuItem("Send Response to Comparer")
            send_resp_comparer.addActionListener(SendToComparerListener(self, False))
            menu_items.append(send_resp_comparer)
            
            send_req_comparer = JMenuItem("Send Request to Comparer")
            send_req_comparer.addActionListener(SendToComparerListener(self, True))
            menu_items.append(send_req_comparer)
        
        return menu_items if menu_items else None
    
    # ==================== IMessageEditorController Implementation ====================
    
    def getHttpService(self):
        """Return HTTP service for selected item."""
        if self._current_request:
            return self._current_request.getHttpService()
        return None
    
    def getRequest(self):
        """Return request for selected item."""
        if self._current_request:
            return self._current_request.getRequest()
        return None
    
    def getResponse(self):
        """Return response for selected item."""
        if self._current_request:
            return self._current_request.getResponse()
        return None
    
    def _send_to_repeater(self):
        """Send selected item to Repeater."""
        row = self._results_table.getSelectedRow()
        if row < 0:
            return
        
        filtered = self._get_filtered_results()
        if row >= len(filtered):
            return
        
        result = filtered[row]
        messageInfo = result.get('messageInfo')
        
        if messageInfo:
            http_service = messageInfo.getHttpService()
            request = messageInfo.getRequest()
            self._callbacks.sendToRepeater(
                http_service.getHost(),
                http_service.getPort(),
                http_service.getProtocol() == "https",
                request,
                "LHF: " + result['match'][:30]
            )
            print("[+] Sent to Repeater: {}".format(result['url']))
    
    def _send_to_intruder(self):
        """Send selected item to Intruder."""
        row = self._results_table.getSelectedRow()
        if row < 0:
            return
        
        filtered = self._get_filtered_results()
        if row >= len(filtered):
            return
        
        result = filtered[row]
        messageInfo = result.get('messageInfo')
        
        if messageInfo:
            http_service = messageInfo.getHttpService()
            request = messageInfo.getRequest()
            self._callbacks.sendToIntruder(
                http_service.getHost(),
                http_service.getPort(),
                http_service.getProtocol() == "https",
                request
            )
            print("[+] Sent to Intruder: {}".format(result['url']))
    
    def _send_to_comparer(self, is_request=False):
        """Send selected item to Comparer."""
        row = self._results_table.getSelectedRow()
        if row < 0:
            return
        
        filtered = self._get_filtered_results()
        if row >= len(filtered):
            return
        
        result = filtered[row]
        messageInfo = result.get('messageInfo')
        
        if messageInfo:
            if is_request:
                self._callbacks.sendToComparer(messageInfo.getRequest())
                print("[+] Sent request to Comparer: {}".format(result['url']))
            else:
                self._callbacks.sendToComparer(messageInfo.getResponse())
                print("[+] Sent response to Comparer: {}".format(result['url']))
    
    def _export_results(self):
        """Export results to file."""
        chooser = JFileChooser()
        chooser.setDialogTitle("Export Results")
        chooser.setFileFilter(FileNameExtensionFilter("JSON Files", ["json"]))
        chooser.setFileFilter(FileNameExtensionFilter("CSV Files", ["csv"]))
        
        if chooser.showSaveDialog(self._main_panel) == JFileChooser.APPROVE_OPTION:
            file_path = str(chooser.getSelectedFile().getAbsolutePath())
            
            try:
                if file_path.endswith('.csv'):
                    self._export_csv(file_path)
                else:
                    if not file_path.endswith('.json'):
                        file_path += '.json'
                    self._export_json(file_path)
                
                JOptionPane.showMessageDialog(
                    self._main_panel,
                    "Results exported to: {}".format(file_path),
                    "Export Complete",
                    JOptionPane.INFORMATION_MESSAGE
                )
            except Exception as e:
                JOptionPane.showMessageDialog(
                    self._main_panel,
                    "Error exporting: {}".format(str(e)),
                    "Export Error",
                    JOptionPane.ERROR_MESSAGE
                )
    
    def _export_json(self, file_path):
        """Export currently filtered results to JSON file."""
        filtered = self._get_filtered_results()
        export_data = []
        for result in filtered:
            export_data.append({
                'category': result['category'],
                'severity': result.get('severity', 'Info'),
                'match': result['match'],
                'url': result['url']
            })
        
        with open(file_path, 'w') as f:
            json.dump(export_data, f, indent=2)
    
    def _export_csv(self, file_path):
        """Export currently filtered results to CSV file."""
        filtered = self._get_filtered_results()
        with open(file_path, 'w') as f:
            f.write("Category,Severity,Match,URL\n")
            for result in filtered:
                # Escape CSV fields
                match = result['match'].replace('"', '""')
                url = result['url'].replace('"', '""')
                f.write('"{}","{}","{}","{}"\n'.format(
                    result['category'],
                    result.get('severity', 'Info'),
                    match,
                    url
                ))
    
    def _clear_results(self):
        """Clear all results."""
        with self._lock:
            self._results = []
            self._seen_match_only.clear()
            self._seen_match_and_url.clear()
        self._table_model.fireTableDataChanged()
        self._update_results_count()
        self._request_viewer.setMessage([], True)
        self._response_viewer.setMessage([], False)
        print("[+] Results cleared")


# ==================== Table Model ====================

class ResultsTableModel(AbstractTableModel):
    """Table model for results."""
    
    COLUMNS = ["Category", "Severity", "Match", "URL"]
    
    def __init__(self, extender):
        self._extender = extender
    
    def getRowCount(self):
        return len(self._extender._get_filtered_results())
    
    def getColumnCount(self):
        return len(self.COLUMNS)
    
    def getColumnName(self, column):
        return self.COLUMNS[column]
    
    def isCellEditable(self, row, column):
        return column == 1
    
    def setValueAt(self, value, row, column):
        if column == 1:
            filtered = self._extender._get_filtered_results()
            if row < len(filtered):
                filtered[row]['severity'] = str(value)
                self.fireTableCellUpdated(row, column)
    
    def getValueAt(self, row, column):
        filtered = self._extender._get_filtered_results()
        if row < len(filtered):
            result = filtered[row]
            if column == 0:
                return result['category']
            elif column == 1:
                return result.get('severity', 'Info')
            elif column == 2:
                return result['match']
            elif column == 3:
                return result['url']
        return ""


class SeverityCellRenderer(DefaultTableCellRenderer):
    """Color-coded cell renderer for the Severity column."""
    
    SEVERITY_COLORS = {
        'High': Color(255, 70, 70),
        'Medium': Color(255, 165, 0),
        'Low': Color(100, 149, 237),
        'Info': Color(144, 238, 144)
    }
    
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        component = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, column
        )
        if not isSelected:
            color = self.SEVERITY_COLORS.get(str(value), Color.WHITE)
            component.setBackground(color)
            component.setForeground(Color.BLACK)
        component.setHorizontalAlignment(SwingConstants.CENTER)
        return component


# ==================== Event Listeners ====================

class CategoryFilterListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, event):
        self._extender._table_model.fireTableDataChanged()
        self._extender._update_results_count()


class SearchFilterListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, event):
        self._extender._table_model.fireTableDataChanged()
        self._extender._update_results_count()


class ClearResultsListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, event):
        self._extender._clear_results()


class ExportResultsListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, event):
        self._extender._export_results()


class ResultSelectionListener(ListSelectionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def valueChanged(self, event):
        if event.getValueIsAdjusting():
            return
        
        row = self._extender._results_table.getSelectedRow()
        if row < 0:
            return
        
        filtered = self._extender._get_filtered_results()
        if row >= len(filtered):
            return
        
        result = filtered[row]
        messageInfo = result.get('messageInfo')
        
        if messageInfo:
            self._extender._current_request = messageInfo
            self._extender._request_viewer.setMessage(messageInfo.getRequest(), True)
            self._extender._response_viewer.setMessage(messageInfo.getResponse(), False)
            
            # Highlight all occurrences of the match in the response viewer
            match_str = result.get('match', '')
            if match_str:
                viewer_component = self._extender._response_viewer.getComponent()
                SwingUtilities.invokeLater(HighlightMatchRunnable(viewer_component, match_str))


class ResultsTableMouseListener(MouseAdapter):
    def __init__(self, extender):
        self._extender = extender
    
    def mousePressed(self, event):
        self._show_popup(event)
    
    def mouseReleased(self, event):
        self._show_popup(event)
    
    def _show_popup(self, event):
        if event.isPopupTrigger():
            row = self._extender._results_table.rowAtPoint(event.getPoint())
            if row >= 0:
                self._extender._results_table.setRowSelectionInterval(row, row)
                
                popup = JPopupMenu()
                send_item = JMenuItem("Send to Repeater")
                send_item.addActionListener(SendToRepeaterListener(self._extender))
                popup.add(send_item)
                
                intruder_item = JMenuItem("Send to Intruder")
                intruder_item.addActionListener(SendToIntruderListener(self._extender))
                popup.add(intruder_item)
                
                comparer_resp_item = JMenuItem("Send Response to Comparer")
                comparer_resp_item.addActionListener(SendToComparerListener(self._extender, False))
                popup.add(comparer_resp_item)
                
                comparer_req_item = JMenuItem("Send Request to Comparer")
                comparer_req_item.addActionListener(SendToComparerListener(self._extender, True))
                popup.add(comparer_req_item)
                
                popup.addSeparator()
                
                copy_match_item = JMenuItem("Copy Match Value")
                copy_match_item.addActionListener(CopyValueListener(self._extender, 'match'))
                popup.add(copy_match_item)
                
                copy_url_item = JMenuItem("Copy URL")
                copy_url_item.addActionListener(CopyValueListener(self._extender, 'url'))
                popup.add(copy_url_item)
                
                open_url_item = JMenuItem("Open URL in Browser")
                open_url_item.addActionListener(OpenUrlListener(self._extender))
                popup.add(open_url_item)
                
                popup.addSeparator()
                
                wb_match_item = JMenuItem("Send Match to Whiteboard")
                wb_match_item.addActionListener(SendToWhiteboardListener(self._extender, 'match'))
                popup.add(wb_match_item)
                
                wb_url_item = JMenuItem("Send URL to Whiteboard")
                wb_url_item.addActionListener(SendToWhiteboardListener(self._extender, 'url'))
                popup.add(wb_url_item)
                
                popup.addSeparator()
                
                fp_item = JMenuItem("Mark as False Positive...")
                fp_item.addActionListener(MarkFalsePositiveListener(self._extender))
                popup.add(fp_item)
                
                popup.show(event.getComponent(), event.getX(), event.getY())


class SendToRepeaterListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, event):
        self._extender._send_to_repeater()


class SendToIntruderListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, event):
        self._extender._send_to_intruder()


class SendToComparerListener(ActionListener):
    def __init__(self, extender, is_request):
        self._extender = extender
        self._is_request = is_request
    
    def actionPerformed(self, event):
        self._extender._send_to_comparer(self._is_request)


class CopyValueListener(ActionListener):
    def __init__(self, extender, field):
        self._extender = extender
        self._field = field
    
    def actionPerformed(self, event):
        row = self._extender._results_table.getSelectedRow()
        if row < 0:
            return
        filtered = self._extender._get_filtered_results()
        if row < len(filtered):
            value = filtered[row].get(self._field, '')
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(StringSelection(value), None)
            print("[+] Copied to clipboard: {}".format(value[:50]))


class OpenUrlListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, event):
        row = self._extender._results_table.getSelectedRow()
        if row < 0:
            return
        filtered = self._extender._get_filtered_results()
        if row < len(filtered):
            url = filtered[row].get('url', '')
            if url:
                try:
                    Desktop.getDesktop().browse(URI(url))
                    print("[+] Opened URL in browser: {}".format(url))
                except Exception as e:
                    print("[-] Error opening URL: {}".format(str(e)))


class MarkFalsePositiveListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, event):
        row = self._extender._results_table.getSelectedRow()
        if row < 0:
            return
        filtered = self._extender._get_filtered_results()
        if row >= len(filtered):
            return
        result = filtered[row]
        
        options = ["Exclude by Match", "Exclude by URL", "Cancel"]
        choice = JOptionPane.showOptionDialog(
            self._extender._main_panel,
            "Exclude future results matching:\n\nMatch: {}\nURL: {}".format(
                result['match'][:80], result['url'][:80]),
            "Mark as False Positive",
            JOptionPane.DEFAULT_OPTION,
            JOptionPane.QUESTION_MESSAGE,
            None,
            options,
            options[0]
        )
        
        if choice == 0:
            self._extender._exclusions['matches'].append(result['match'])
            self._extender._save_exclusions()
            self._extender._table_model.fireTableDataChanged()
            self._extender._update_results_count()
            self._extender._update_exclusions_display()
            print("[+] Excluded match: {}".format(result['match'][:50]))
        elif choice == 1:
            self._extender._exclusions['urls'].append(result['url'])
            self._extender._save_exclusions()
            self._extender._table_model.fireTableDataChanged()
            self._extender._update_results_count()
            self._extender._update_exclusions_display()
            print("[+] Excluded URL: {}".format(result['url'][:50]))


class StatusChecksToggleListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, event):
        enabled = self._extender._status_checks_checkbox.isSelected()
        self._extender._settings["status_checks_enabled"] = enabled
        self._extender._save_settings()
        # Reset state when toggling
        self._extender._wb_status_running = False
        if not enabled:
            self._extender._wb_status_cache.clear()
        self._extender._refresh_whiteboard_ui()
        if enabled:
            self._extender._wb_status_cache.clear()
            self._extender._trigger_status_checks()
        print("[+] HTTP status checks: {}".format("enabled" if enabled else "disabled"))


class SettingsChangeListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, event):
        self._extender._settings["only_in_scope"] = self._extender._scope_checkbox.isSelected()
        self._extender._settings["skip_media"] = self._extender._skip_media_checkbox.isSelected()
        self._extender._save_settings()


class MergeDuplicatesListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, event):
        selected_index = self._extender._merge_combo.getSelectedIndex()
        if selected_index == 0:
            self._extender._settings["merge_duplicates"] = "match_only"
        elif selected_index == 1:
            self._extender._settings["merge_duplicates"] = "match_and_url"
        else:
            self._extender._settings["merge_duplicates"] = "none"
        self._extender._save_settings()
        print("[+] Merge duplicates mode: {}".format(self._extender._settings["merge_duplicates"]))


class PatternCategoryListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, event):
        self._extender._update_patterns_display()


class NoiseCategoryListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, event):
        self._extender._update_noise_display()


class AddPatternListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, event):
        pattern = JOptionPane.showInputDialog(
            self._extender._main_panel,
            "Enter regex pattern:",
            "Add Pattern",
            JOptionPane.PLAIN_MESSAGE
        )
        if pattern:
            category = str(self._extender._pattern_category.getSelectedItem())
            self._extender._patterns[category].append(pattern)
            self._extender._update_patterns_display()
            self._extender._compile_patterns()
            self._extender._save_custom_patterns()


class ImportPatternsListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, event):
        chooser = JFileChooser()
        chooser.setDialogTitle("Import Patterns")
        chooser.setFileFilter(FileNameExtensionFilter("Text/JSON Files", ["txt", "json"]))
        
        if chooser.showOpenDialog(self._extender._main_panel) == JFileChooser.APPROVE_OPTION:
            file_path = str(chooser.getSelectedFile().getAbsolutePath())
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                
                category = str(self._extender._pattern_category.getSelectedItem())
                
                if file_path.endswith('.json'):
                    data = json.loads(content)
                    if isinstance(data, list):
                        self._extender._patterns[category].extend(data)
                    elif isinstance(data, dict) and category in data:
                        self._extender._patterns[category].extend(data[category])
                else:
                    # Text file - one pattern per line
                    for line in content.split('\n'):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            self._extender._patterns[category].append(line)
                
                self._extender._update_patterns_display()
                self._extender._compile_patterns()
                self._extender._save_custom_patterns()
                
                JOptionPane.showMessageDialog(
                    self._extender._main_panel,
                    "Patterns imported successfully",
                    "Import Complete",
                    JOptionPane.INFORMATION_MESSAGE
                )
            except Exception as e:
                JOptionPane.showMessageDialog(
                    self._extender._main_panel,
                    "Error importing: {}".format(str(e)),
                    "Import Error",
                    JOptionPane.ERROR_MESSAGE
                )


class SavePatternsListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, event):
        # Update patterns from text area
        category = str(self._extender._pattern_category.getSelectedItem())
        text = self._extender._patterns_text.getText()
        patterns = [p.strip() for p in text.split('\n') if p.strip()]
        self._extender._patterns[category] = patterns
        self._extender._compile_patterns()
        self._extender._save_custom_patterns()
        
        JOptionPane.showMessageDialog(
            self._extender._main_panel,
            "Patterns saved",
            "Save Complete",
            JOptionPane.INFORMATION_MESSAGE
        )


class PatternTesterListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, event):
        regex_str = self._extender._tester_regex_field.getText().strip()
        sample = self._extender._tester_sample_text.getText()
        
        if not regex_str:
            self._extender._tester_results_text.setText("[!] Enter a regex pattern to test.")
            return
        if not sample:
            self._extender._tester_results_text.setText("[!] Enter sample text to test against.")
            return
        
        try:
            compiled = re.compile(regex_str)
            matches = compiled.findall(sample)
            
            if not matches:
                self._extender._tester_results_text.setText("No matches found.")
                return
            
            # Format results
            lines = ["[+] {} match(es) found:\n".format(len(matches))]
            for i, match in enumerate(matches, 1):
                if isinstance(match, tuple):
                    match = match[0] if match[0] else ''.join(match)
                lines.append("  {}. {}".format(i, str(match).strip()[:200]))
            
            self._extender._tester_results_text.setText("\n".join(lines))
            self._extender._tester_results_text.setCaretPosition(0)
            
        except Exception as e:
            self._extender._tester_results_text.setText("[ERROR] Invalid regex: {}".format(str(e)))


class AddNoiseListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, event):
        filter_val = JOptionPane.showInputDialog(
            self._extender._main_panel,
            "Enter noise filter:",
            "Add Filter",
            JOptionPane.PLAIN_MESSAGE
        )
        if filter_val:
            filter_type = str(self._extender._noise_category.getSelectedItem())
            self._extender._noise_filters[filter_type].append(filter_val)
            self._extender._compile_noise_filters()
            self._extender._update_noise_display()
            self._extender._save_custom_noise()


class ImportNoiseListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, event):
        chooser = JFileChooser()
        chooser.setDialogTitle("Import Noise Filters")
        chooser.setFileFilter(FileNameExtensionFilter("Text/JSON Files", ["txt", "json"]))
        
        if chooser.showOpenDialog(self._extender._main_panel) == JFileChooser.APPROVE_OPTION:
            file_path = str(chooser.getSelectedFile().getAbsolutePath())
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                
                filter_type = str(self._extender._noise_category.getSelectedItem())
                
                if file_path.endswith('.json'):
                    data = json.loads(content)
                    if isinstance(data, list):
                        self._extender._noise_filters[filter_type].extend(data)
                    elif isinstance(data, dict) and filter_type in data:
                        self._extender._noise_filters[filter_type].extend(data[filter_type])
                else:
                    for line in content.split('\n'):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            self._extender._noise_filters[filter_type].append(line)
                
                self._extender._compile_noise_filters()
                self._extender._update_noise_display()
                self._extender._save_custom_noise()
                
                JOptionPane.showMessageDialog(
                    self._extender._main_panel,
                    "Noise filters imported successfully",
                    "Import Complete",
                    JOptionPane.INFORMATION_MESSAGE
                )
            except Exception as e:
                JOptionPane.showMessageDialog(
                    self._extender._main_panel,
                    "Error importing: {}".format(str(e)),
                    "Import Error",
                    JOptionPane.ERROR_MESSAGE
                )


class SaveNoiseListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, event):
        filter_type = str(self._extender._noise_category.getSelectedItem())
        text = self._extender._noise_text.getText()
        filters = [f.strip() for f in text.split('\n') if f.strip()]
        self._extender._noise_filters[filter_type] = filters
        self._extender._compile_noise_filters()
        self._extender._save_custom_noise()
        
        JOptionPane.showMessageDialog(
            self._extender._main_panel,
            "Noise filters saved",
            "Save Complete",
            JOptionPane.INFORMATION_MESSAGE
        )


class SaveExclusionsListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, event):
        matches_text = self._extender._excl_matches_text.getText()
        urls_text = self._extender._excl_urls_text.getText()
        self._extender._exclusions['matches'] = [m.strip() for m in matches_text.split('\n') if m.strip()]
        self._extender._exclusions['urls'] = [u.strip() for u in urls_text.split('\n') if u.strip()]
        self._extender._save_exclusions()
        self._extender._table_model.fireTableDataChanged()
        self._extender._update_results_count()
        
        JOptionPane.showMessageDialog(
            self._extender._main_panel,
            "Exclusions saved ({} matches, {} URLs)".format(
                len(self._extender._exclusions['matches']),
                len(self._extender._exclusions['urls'])),
            "Save Complete",
            JOptionPane.INFORMATION_MESSAGE
        )


class ClearExclusionsListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, event):
        confirm = JOptionPane.showConfirmDialog(
            self._extender._main_panel,
            "Clear all exclusions? This will show previously excluded results.",
            "Clear Exclusions",
            JOptionPane.YES_NO_OPTION
        )
        if confirm == JOptionPane.YES_OPTION:
            self._extender._exclusions = {'matches': [], 'urls': []}
            self._extender._save_exclusions()
            self._extender._update_exclusions_display()
            self._extender._table_model.fireTableDataChanged()
            self._extender._update_results_count()
            print("[+] All exclusions cleared")


class SendToWhiteboardListener(ActionListener):
    def __init__(self, extender, field):
        self._extender = extender
        self._field = field
    
    def actionPerformed(self, event):
        row = self._extender._results_table.getSelectedRow()
        if row < 0:
            return
        filtered = self._extender._get_filtered_results()
        if row < len(filtered):
            result = filtered[row]
            value = result.get(self._field, '')
            source_cat = result.get('category', '')
            if value:
                added = self._extender._add_to_whiteboard(value, source_cat)
                if not added:
                    print("[*] Already on Whiteboard: {}".format(value[:50]))


class WhiteboardAddManualListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, event):
        value = JOptionPane.showInputDialog(
            self._extender._main_panel,
            "Enter value to add to Whiteboard:",
            "Add to Whiteboard",
            JOptionPane.PLAIN_MESSAGE
        )
        if value and value.strip():
            self._extender._add_to_whiteboard(value.strip())


class WhiteboardExportListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, event):
        self._extender._export_whiteboard()


class WhiteboardClearListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, event):
        confirm = JOptionPane.showConfirmDialog(
            self._extender._main_panel,
            "Clear all Whiteboard items?",
            "Confirm Clear",
            JOptionPane.YES_NO_OPTION
        )
        if confirm == JOptionPane.YES_OPTION:
            for cat in self._extender._whiteboard:
                self._extender._whiteboard[cat] = []
            self._extender._save_whiteboard()
            self._extender._refresh_whiteboard_ui()
            print("[+] Whiteboard cleared")


class WhiteboardItemMouseListener(MouseAdapter):
    def __init__(self, extender, category, text_area):
        self._extender = extender
        self._category = category
        self._text_area = text_area
    
    def mousePressed(self, event):
        self._show_popup(event)
    
    def mouseReleased(self, event):
        self._show_popup(event)
    
    def _show_popup(self, event):
        if not event.isPopupTrigger():
            return
        
        # Get the line under the cursor
        pos = self._text_area.viewToModel(event.getPoint())
        text = self._text_area.getText()
        if not text:
            return
        
        lines = text.split('\n')
        current = 0
        selected_line = None
        for line in lines:
            if current <= pos <= current + len(line):
                selected_line = line.strip()
                break
            current += len(line) + 1
        
        if not selected_line:
            return
        
        # Strip status suffix for Domains/URLs (e.g. "domain.com  [200]" -> "domain.com")
        clean_value = selected_line
        if self._category in ('Domains', 'URLs') and '  [' in selected_line:
            clean_value = selected_line.rsplit('  [', 1)[0].strip()
        
        popup = JPopupMenu()
        
        copy_item = JMenuItem("Copy: {}".format(clean_value[:50]))
        copy_item.addActionListener(WhiteboardCopyListener(clean_value))
        popup.add(copy_item)
        
        remove_item = JMenuItem("Remove from Whiteboard")
        remove_item.addActionListener(WhiteboardRemoveListener(self._extender, self._category, clean_value))
        popup.add(remove_item)
        
        if clean_value.startswith('http://') or clean_value.startswith('https://'):
            open_item = JMenuItem("Open in Browser")
            open_item.addActionListener(WhiteboardOpenUrlListener(clean_value))
            popup.add(open_item)
        
        # Show subdomain search for Domains and URLs
        if self._category in ('Domains', 'URLs'):
            popup.addSeparator()
            domain = BurpExtender._extract_domain(clean_value)
            if domain:
                subdomain_item = JMenuItem("Find Subdomains (crt.sh): {}".format(domain))
                subdomain_item.addActionListener(WhiteboardSubdomainListener(self._extender, domain))
                popup.add(subdomain_item)
        
        popup.show(event.getComponent(), event.getX(), event.getY())


class WhiteboardCopyListener(ActionListener):
    def __init__(self, value):
        self._value = value
    
    def actionPerformed(self, event):
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(StringSelection(self._value), None)


class WhiteboardRemoveListener(ActionListener):
    def __init__(self, extender, category, value):
        self._extender = extender
        self._category = category
        self._value = value
    
    def actionPerformed(self, event):
        self._extender._remove_from_whiteboard(self._category, self._value)


class WhiteboardOpenUrlListener(ActionListener):
    def __init__(self, url):
        self._url = url
    
    def actionPerformed(self, event):
        try:
            Desktop.getDesktop().browse(URI(self._url))
        except Exception as e:
            print("[-] Error opening URL: {}".format(str(e)))


class MappingsSearchListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, event):
        query = self._extender._map_search_field.getText()
        if not query:
            return
        text = self._extender._map_source_viewer.getText()
        if not text:
            return
        self._extender._map_search_pos = 0
        idx = text.find(query, 0)
        if idx >= 0:
            self._extender._map_source_viewer.setCaretPosition(idx)
            self._extender._map_source_viewer.select(idx, idx + len(query))
            self._extender._map_search_pos = idx + len(query)
        else:
            JOptionPane.showMessageDialog(self._extender._map_panel,
                "Not found: {}".format(query), "Search", JOptionPane.INFORMATION_MESSAGE)


class MappingsSearchNextListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, event):
        query = self._extender._map_search_field.getText()
        if not query:
            return
        text = self._extender._map_source_viewer.getText()
        if not text:
            return
        idx = text.find(query, self._extender._map_search_pos)
        if idx >= 0:
            self._extender._map_source_viewer.setCaretPosition(idx)
            self._extender._map_source_viewer.select(idx, idx + len(query))
            self._extender._map_search_pos = idx + len(query)
        else:
            # Wrap around
            idx = text.find(query, 0)
            if idx >= 0:
                self._extender._map_source_viewer.setCaretPosition(idx)
                self._extender._map_source_viewer.select(idx, idx + len(query))
                self._extender._map_search_pos = idx + len(query)
            else:
                JOptionPane.showMessageDialog(self._extender._map_panel,
                    "Not found: {}".format(query), "Search", JOptionPane.INFORMATION_MESSAGE)


class MappingsFetchAllListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, event):
        self._extender._fetch_all_maps_async()


class MappingsScanListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, event):
        self._extender._scan_source_maps_async()


class MappingsExportListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, event):
        self._extender._export_sources()


class MappingsMapSelectionListener(ListSelectionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def valueChanged(self, event):
        if event.getValueIsAdjusting():
            return
        idx = self._extender._map_list.getSelectedIndex()
        if idx < 0 or idx >= len(self._extender._source_maps):
            return
        entry = self._extender._source_maps[idx]
        self._extender._map_files_model.clear()
        for source in entry.get('sources', []):
            self._extender._map_files_model.addElement(source)
        self._extender._map_source_viewer.setText("")
        self._extender._map_source_label.setText(" Source Code ({} files)".format(len(entry.get('sources', []))))


class MappingsFileSelectionListener(ListSelectionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def valueChanged(self, event):
        if event.getValueIsAdjusting():
            return
        map_idx = self._extender._map_list.getSelectedIndex()
        file_idx = self._extender._map_files_list.getSelectedIndex()
        if map_idx < 0 or file_idx < 0:
            return
        entry = self._extender._source_maps[map_idx]
        contents = entry.get('sourcesContent', [])
        sources = entry.get('sources', [])
        if file_idx < len(contents) and contents[file_idx]:
            self._extender._map_source_viewer.setText(contents[file_idx])
            self._extender._map_source_viewer.setCaretPosition(0)
            name = sources[file_idx] if file_idx < len(sources) else 'unknown'
            self._extender._map_source_label.setText(" Source: {}".format(name))
        else:
            self._extender._map_source_viewer.setText("(no source content available)")


class MappingsFindingsSelectionListener(ListSelectionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def valueChanged(self, event):
        if event.getValueIsAdjusting():
            return
        idx = self._extender._map_findings_list.getSelectedIndex()
        if idx < 0 or idx >= len(self._extender._map_findings):
            return
        finding = self._extender._map_findings[idx]
        map_idx = finding.get('map_idx', -1)
        source_idx = finding.get('source_idx', -1)
        match_str = finding.get('match', '')
        
        if map_idx < 0 or source_idx < 0:
            return
        if map_idx >= len(self._extender._source_maps):
            return
        
        entry = self._extender._source_maps[map_idx]
        contents = entry.get('sourcesContent', [])
        sources = entry.get('sources', [])
        
        if source_idx >= len(contents) or not contents[source_idx]:
            return
        
        # Show source code
        source_text = contents[source_idx]
        source_name = sources[source_idx] if source_idx < len(sources) else 'unknown'
        self._extender._map_source_viewer.setText(source_text)
        self._extender._map_source_label.setText(" Source: {} | Match: {}".format(source_name, match_str[:40]))
        
        # Highlight all occurrences of the match and scroll to first
        try:
            viewer = self._extender._map_source_viewer
            highlighter = viewer.getHighlighter()
            highlighter.removeAllHighlights()
            painter = DefaultHighlighter.DefaultHighlightPainter(Color(255, 165, 0, 120))
            
            first_pos = -1
            start = 0
            match_len = len(match_str)
            while True:
                pos = source_text.find(match_str, start)
                if pos < 0:
                    break
                highlighter.addHighlight(pos, pos + match_len, painter)
                if first_pos < 0:
                    first_pos = pos
                start = pos + match_len
            
            if first_pos >= 0:
                viewer.setCaretPosition(first_pos)
                try:
                    rect = viewer.modelToView(first_pos)
                    if rect:
                        viewer.scrollRectToVisible(rect)
                except Exception:
                    pass
        except Exception:
            pass


class MappingsMapMouseListener(MouseAdapter):
    def __init__(self, extender):
        self._extender = extender
    
    def mousePressed(self, event):
        self._show_popup(event)
    
    def mouseReleased(self, event):
        self._show_popup(event)
    
    def _show_popup(self, event):
        if not event.isPopupTrigger():
            return
        idx = self._extender._map_list.locationToIndex(event.getPoint())
        if idx < 0 or idx >= len(self._extender._source_maps):
            return
        self._extender._map_list.setSelectedIndex(idx)
        entry = self._extender._source_maps[idx]
        
        popup = JPopupMenu()
        
        if entry['status'] == 'Pending':
            fetch_item = JMenuItem("Fetch this Source Map")
            fetch_item.addActionListener(MappingsFetchSingleListener(self._extender, entry))
            popup.add(fetch_item)
        
        copy_item = JMenuItem("Copy Map URL")
        copy_item.addActionListener(WhiteboardCopyListener(entry['map_url']))
        popup.add(copy_item)
        
        open_item = JMenuItem("Open Map URL in Browser")
        open_item.addActionListener(WhiteboardOpenUrlListener(entry['map_url']))
        popup.add(open_item)
        
        popup.show(event.getComponent(), event.getX(), event.getY())


class MappingsFetchSingleListener(ActionListener):
    def __init__(self, extender, entry):
        self._extender = extender
        self._entry = entry
    
    def actionPerformed(self, event):
        extender_ref = self._extender
        entry_ref = self._entry
        
        class FetchRunnable(Runnable):
            def run(self_inner):
                extender_ref._fetch_source_map(entry_ref)
                class Refresh(Runnable):
                    def run(self_r):
                        extender_ref._refresh_mappings_ui()
                SwingUtilities.invokeLater(Refresh())
        
        t = JThread(FetchRunnable())
        t.setDaemon(True)
        t.start()


class WhiteboardSubdomainListener(ActionListener):
    def __init__(self, extender, domain):
        self._extender = extender
        self._domain = domain
    
    def actionPerformed(self, event):
        self._extender._search_subdomains_async(self._domain)


class HighlightMatchRunnable(Runnable):
    """Highlights all occurrences of a match string in a Swing component tree and scrolls to the first."""
    
    HIGHLIGHT_COLOR = Color(255, 165, 0, 120)
    
    def __init__(self, component, match_str):
        self._component = component
        self._match_str = match_str
    
    def run(self):
        try:
            text_components = self._find_text_components(self._component)
            painter = DefaultHighlighter.DefaultHighlightPainter(self.HIGHLIGHT_COLOR)
            
            for tc in text_components:
                text = tc.getText()
                if not text or self._match_str not in text:
                    continue
                
                highlighter = tc.getHighlighter()
                highlighter.removeAllHighlights()
                
                match_len = len(self._match_str)
                first_pos = -1
                start = 0
                while True:
                    idx = text.find(self._match_str, start)
                    if idx < 0:
                        break
                    highlighter.addHighlight(idx, idx + match_len, painter)
                    if first_pos < 0:
                        first_pos = idx
                    start = idx + match_len
                
                # Scroll to first occurrence
                if first_pos >= 0:
                    tc.setCaretPosition(first_pos)
                    try:
                        rect = tc.modelToView(first_pos)
                        if rect:
                            tc.scrollRectToVisible(rect)
                    except Exception:
                        pass
        except Exception:
            pass
    
    def _find_text_components(self, component):
        """Recursively find all JTextComponent instances."""
        results = []
        if isinstance(component, JTextComponent):
            results.append(component)
        try:
            for i in range(component.getComponentCount()):
                results.extend(self._find_text_components(component.getComponent(i)))
        except Exception:
            pass
        return results


class UpdateTableRunnable(Runnable):
    def __init__(self, extender):
        self._extender = extender
    
    def run(self):
        self._extender._update_table()


# ==================== Scan Issue ====================

class LHFScanIssue(IScanIssue):
    """Custom scan issue for reporting findings to Burp Scanner."""
    
    def __init__(self, http_service, url, http_messages, name, detail, severity, confidence):
        self._http_service = http_service
        self._url = url
        self._http_messages = http_messages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence
    
    def getUrl(self):
        return self._url
    
    def getIssueName(self):
        return self._name
    
    def getIssueType(self):
        return 0
    
    def getSeverity(self):
        return self._severity
    
    def getConfidence(self):
        return self._confidence
    
    def getIssueBackground(self):
        return "LowHangingFruits detected a potentially sensitive item in the HTTP response."
    
    def getRemediationBackground(self):
        return None
    
    def getIssueDetail(self):
        return self._detail
    
    def getRemediationDetail(self):
        return "Review the finding and remove sensitive data from the response if it should not be exposed."
    
    def getHttpMessages(self):
        return self._http_messages
    
    def getHttpService(self):
        return self._http_service
