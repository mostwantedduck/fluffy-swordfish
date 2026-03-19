# -*- coding: utf-8 -*-
"""
LowHangingFruits Burp Grabber
A Burp Suite extension for detecting secrets, endpoints, URLs, files, and emails in HTTP responses.

Author: Daniel
Version: 1.0.0
"""

from burp import IBurpExtender, IHttpListener, ITab, IContextMenuFactory, IMessageEditorController
from javax.swing import (
    JPanel, JTable, JScrollPane, JSplitPane, JLabel, JComboBox, JCheckBox,
    JButton, JTextField, JTextArea, JTabbedPane, JFileChooser, JOptionPane,
    SwingConstants, BorderFactory, BoxLayout, Box, ListSelectionModel,
    JPopupMenu, JMenuItem
)
from javax.swing.table import AbstractTableModel, DefaultTableCellRenderer
from javax.swing.event import ListSelectionListener
from javax.swing.filechooser import FileNameExtensionFilter
from java.awt import BorderLayout, FlowLayout, GridBagLayout, GridBagConstraints, Insets, Dimension, Color, Font
from java.awt.event import ActionListener, MouseAdapter
from java.io import File
from java.lang import Runnable
import re
import json
import os
import threading


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
        
        # Load patterns and settings
        self._load_patterns()
        self._load_settings()
        
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
            "emails": []
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
            "merge_duplicates": "match_only"
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
        
        # Create tabbed pane for Results and Settings
        self._tabbed_pane = JTabbedPane()
        
        # Build results panel
        results_panel = self._build_results_panel()
        self._tabbed_pane.addTab("Results", results_panel)
        
        # Build settings panel
        settings_panel = self._build_settings_panel()
        self._tabbed_pane.addTab("Settings", settings_panel)
        
        self._main_panel.add(self._tabbed_pane, BorderLayout.CENTER)
    
    def _build_results_panel(self):
        """Build the results panel with table and request/response viewer."""
        panel = JPanel(BorderLayout())
        
        # Top panel with filter controls
        top_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        top_panel.add(JLabel("Filter by Category:"))
        
        categories = ["All", "Endpoints", "URLs", "Secrets", "Files", "Emails"]
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
        self._results_table.getColumnModel().getColumn(0).setPreferredWidth(100)
        self._results_table.getColumnModel().getColumn(1).setPreferredWidth(400)
        self._results_table.getColumnModel().getColumn(2).setPreferredWidth(300)
        
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
        
        # Custom patterns section
        patterns_panel = JPanel(BorderLayout())
        patterns_panel.setBorder(BorderFactory.createTitledBorder("Custom Patterns"))
        patterns_panel.setAlignmentX(0.0)
        
        patterns_top = JPanel(FlowLayout(FlowLayout.LEFT))
        patterns_top.add(JLabel("Category:"))
        self._pattern_category = JComboBox(["endpoints", "urls", "secrets", "files", "emails"])
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
        
        # Load initial pattern/noise values
        self._update_patterns_display()
        self._update_noise_display()
        
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
                'messageInfo': messageInfo
            }
            self._results.append(result)
            
            # Update table on EDT
            from javax.swing import SwingUtilities
            SwingUtilities.invokeLater(UpdateTableRunnable(self))
    
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
        """Get results filtered by category."""
        filter_category = str(self._category_filter.getSelectedItem())
        if filter_category == "All":
            return self._results
        return [r for r in self._results if r['category'] == filter_category]
    
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
        """Export results to JSON file."""
        export_data = []
        for result in self._results:
            export_data.append({
                'category': result['category'],
                'match': result['match'],
                'url': result['url']
            })
        
        with open(file_path, 'w') as f:
            json.dump(export_data, f, indent=2)
    
    def _export_csv(self, file_path):
        """Export results to CSV file."""
        with open(file_path, 'w') as f:
            f.write("Category,Match,URL\n")
            for result in self._results:
                # Escape CSV fields
                match = result['match'].replace('"', '""')
                url = result['url'].replace('"', '""')
                f.write('"{}","{}","{}"\n'.format(
                    result['category'],
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
    
    COLUMNS = ["Category", "Match", "URL"]
    
    def __init__(self, extender):
        self._extender = extender
    
    def getRowCount(self):
        return len(self._extender._get_filtered_results())
    
    def getColumnCount(self):
        return len(self.COLUMNS)
    
    def getColumnName(self, column):
        return self.COLUMNS[column]
    
    def getValueAt(self, row, column):
        filtered = self._extender._get_filtered_results()
        if row < len(filtered):
            result = filtered[row]
            if column == 0:
                return result['category']
            elif column == 1:
                return result['match']
            elif column == 2:
                return result['url']
        return ""


# ==================== Event Listeners ====================

class CategoryFilterListener(ActionListener):
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
            
            # TODO: Highlight the match in response


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
                popup.show(event.getComponent(), event.getX(), event.getY())


class SendToRepeaterListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, event):
        self._extender._send_to_repeater()


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


class UpdateTableRunnable(Runnable):
    def __init__(self, extender):
        self._extender = extender
    
    def run(self):
        self._extender._update_table()
