#!/usr/bin/env ruby
#
# Copyright (c) 2025 Cisco Systems, Inc. and/or its affiliates
# Copyright (c) 2026 Chainguard
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# STIG HTML Report Generator with Interactive Features
# Includes filtering, multiple views, expandable details, and full test results

require 'json'
require 'erb'
require 'time'
require 'cgi'

class StigHtmlGenerator
  attr_reader :data, :output_file, :container_name, :container_label, :container_sha256, :stig_mappings

  def initialize(json_file, output_file, container_name: nil, container_label: nil, container_sha256: nil)
    @json_file = json_file
    @output_file = output_file
    @container_name = container_name
    @container_label = container_label
    @container_sha256 = container_sha256
    @data = JSON.parse(File.read(json_file), symbolize_names: true)

    # Load STIG mappings for descriptions
    script_dir = File.dirname(File.expand_path(__FILE__))
    require File.join(script_dir, '../libraries/stig_mappings')
    @stig_mappings = StigMappings.new
  end

  def get_stig_rule_details(rule_id)
    # Try both full and short ID formats
    @stig_mappings.all_rules[rule_id] ||
    @stig_mappings.all_rules["xccdf_mil.disa.stig_rule_#{rule_id}"] ||
    {}
  end

  def profile
    @data[:profiles]&.first || {}
  end

  def controls
    profile[:controls] || []
  end

  def platform
    @data.dig(:platform, :name) || 'Unknown'
  end

  def statistics
    stats = {
      total_controls: controls.length,
      total_tests: 0,
      passed_tests: 0,
      failed_tests: 0,
      skipped_tests: 0,
      passed: 0,
      failed: 0,
      skipped: 0,
      total_stig_rules: 0,
      passed_stig_rules: 0,
      failed_stig_rules: 0,
      skipped_stig_rules: 0,
      not_applicable_rules: 0,
      additional_checks: 0,
      passed_additional: 0,
      failed_additional: 0,
      severity_stats: { high: {total: 0, passed: 0, failed: 0}, medium: {total: 0, passed: 0, failed: 0}, low: {total: 0, passed: 0, failed: 0} }
    }

    controls.each do |control|
      status = control_status(control)
      stats[:passed] += 1 if status == 'passed'
      stats[:failed] += 1 if status == 'failed'
      stats[:skipped] += 1 if status == 'skipped'

      # Count individual test assertions
      results = control[:results] || []
      stats[:total_tests] += results.length
      results.each do |result|
        case result[:status].to_s
        when 'passed'
          stats[:passed_tests] += 1
        when 'failed'
          stats[:failed_tests] += 1
        when 'skipped'
          stats[:skipped_tests] += 1
        end
      end

      # Count STIG rules
      stig_rules = control.dig(:tags, :stig_rules) || []
      severities = control.dig(:tags, :stig_severities) || []

      if stig_rules.empty?
        # Additional check (no STIG mapping)
        stats[:additional_checks] += 1
        stats[:passed_additional] += 1 if status == 'passed'
        stats[:failed_additional] += 1 if status == 'failed'
      else
        # STIG-mapped control
        stats[:total_stig_rules] += stig_rules.length
        stats[:passed_stig_rules] += stig_rules.length if status == 'passed'
        stats[:failed_stig_rules] += stig_rules.length if status == 'failed'
        stats[:skipped_stig_rules] += stig_rules.length if status == 'skipped'
      end

      # Severity stats - count individual STIG rules
      stig_rules.each_with_index do |rule_id, idx|
        sev = severities[idx] || severities.first || 'medium'
        sev_key = sev.to_s.downcase.to_sym

        next unless [:high, :medium, :low].include?(sev_key)

        stats[:severity_stats][sev_key][:total] += 1
        stats[:severity_stats][sev_key][:passed] += 1 if status == 'passed'
        stats[:severity_stats][sev_key][:failed] += 1 if status == 'failed'
      end
    end

    # Count not applicable rules from STIG mappings
    stats[:not_applicable_rules] = stig_mappings.all_rules.values.count { |r| r[:not_applicable] }

    # Compliance based on STIG rules (not controls)
    stats[:compliance_pct] = stats[:total_stig_rules] > 0 ?
      ((stats[:passed_stig_rules].to_f / stats[:total_stig_rules]) * 100).round(1) : 0

    stats
  end

  def control_status(control)
    results = control[:results] || []
    return 'skipped' if results.empty? || results.all? { |r| r[:status] == 'skipped' }
    return 'failed' if results.any? { |r| r[:status] == 'failed' }
    'passed'
  end

  def severity_class(severity)
    case severity.to_s.downcase
    when 'critical', 'high'
      'high'
    when 'medium'
      'medium'
    when 'low'
      'low'
    else
      'unknown'
    end
  end

  def escape_html(text)
    CGI.escapeHTML(text.to_s)
  end

  def generate
    template = ERB.new(html_template, trim_mode: '-')
    html = template.result(binding)
    File.write(@output_file, html)
    puts 'STIG HTML report generated successfully!'
    puts "Output: #{@output_file}"
    puts "Open in browser: file://#{File.absolute_path(@output_file)}"
  end

  def html_template
    # Template is too large, splitting into parts
    [
      html_head,
      html_styles,
      html_javascript,
      html_body
    ].join("\n")
  end

  def html_head
    <<~HTML
      <!DOCTYPE html>
      <html lang="en">
      <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>DISA STIG Compliance Report - Interactive</title>
    HTML
  end

  def html_styles
    File.read(File.join(File.dirname(__FILE__), 'stig_report_styles.css')) rescue default_styles
  rescue
    default_styles
  end

  def default_styles
    <<~CSS
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            line-height: 1.6;
            color: #1f2937;
            background: #f9fafb;
        }
        .container { max-width: 1600px; margin: 0 auto; padding: 20px; }

        /* Header */
        .header {
            background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%);
            color: white;
            padding: 30px 40px;
            border-radius: 12px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .header h1 { font-size: 28px; margin-bottom: 8px; font-weight: 700; }

        /* Toolbar */
        .toolbar {
            background: white;
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.08);
        }
        .toolbar-section { margin-bottom: 15px; }
        .toolbar-section:last-child { margin-bottom: 0; }
        .toolbar-label {
            font-size: 12px;
            font-weight: 600;
            color: #6b7280;
            text-transform: uppercase;
            margin-bottom: 8px;
            display: block;
        }
        .button-group { display: flex; flex-wrap: wrap; gap: 8px; }
        .filter-btn, .view-btn {
            padding: 8px 16px;
            border: 2px solid #e5e7eb;
            background: white;
            border-radius: 8px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
            transition: all 0.2s;
        }
        .filter-btn:hover, .view-btn:hover {
            border-color: #3b82f6;
            background: #eff6ff;
        }
        .filter-btn.active, .view-btn.active {
            background: #3b82f6;
            color: white;
            border-color: #3b82f6;
        }
        .search-box {
            width: 100%;
            padding: 10px 15px;
            border: 2px solid #e5e7eb;
            border-radius: 8px;
            font-size: 14px;
        }
        .search-box:focus {
            outline: none;
            border-color: #3b82f6;
        }

        /* Stats */
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 12px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.08);
            text-align: center;
        }
        .stat-card.passed { border-top: 4px solid #10b981; }
        .stat-card.failed { border-top: 4px solid #ef4444; }
        .stat-card .label { font-size: 11px; color: #6b7280; text-transform: uppercase; margin-bottom: 8px; font-weight: 600; }
        .stat-card .count { font-size: 36px; font-weight: 700; }

        /* Controls */
        .controls-section {
            background: white;
            border-radius: 12px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.08);
            padding: 30px;
        }
        .control-card {
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
        }
        .control-card.hidden { display: none; }
        .control-header {
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 12px;
        }
        .control-id {
            font-weight: 600;
            color: #1e3a8a;
            font-size: 13px;
            font-family: monospace;
        }
        .status-badge {
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
        }
        .status-badge.passed { background: #d1fae5; color: #065f46; }
        .status-badge.failed { background: #fee2e2; color: #991b1b; }
        .status-badge.skipped { background: #fef3c7; color: #92400e; }

        /* Expandable sections */
        .expandable-header {
            cursor: pointer;
            display: flex;
            align-items: center;
            padding: 8px 0;
            user-select: none;
            font-size: 13px;
            color: #374151;
        }
        .expandable-header:hover { color: #1e3a8a; }
        .expandable-icon {
            margin-right: 8px;
            transition: transform 0.2s;
        }

        /* Collapsible section headers */
        .section-header-collapsible {
            cursor: pointer;
            display: flex;
            align-items: center;
            padding: 12px 15px;
            background: #f3f4f6;
            border-radius: 8px;
            margin-bottom: 15px;
            user-select: none;
        }
        .section-header-collapsible:hover { background: #e5e7eb; }
        .section-collapse-icon {
            margin-right: 10px;
            font-size: 14px;
            transition: transform 0.2s;
        }
        .section-content-collapsible {
            max-height: 100000px;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
        }
        .section-content-collapsible.collapsed {
            max-height: 0;
        }
        .expandable-content {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease;
        }
        .expandable-content.expanded {
            max-height: 5000px;
        }

        /* STIG tags */
        .stig-tags { display: flex; flex-wrap: wrap; gap: 6px; margin: 10px 0; }
        .stig-tag {
            background: #ede9fe;
            color: #5b21b6;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 600;
            font-family: monospace;
        }
        .stig-tag.high { background: #fee2e2; color: #991b1b; }
        .stig-tag.medium { background: #fed7aa; color: #9a3412; }
        .stig-tag.low { background: #dbeafe; color: #1e40af; }
        .cci-badge {
            background: #f3f4f6;
            color: #374151;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 600;
            font-family: monospace;
            margin-right: 6px;
        }

        /* Test results */
        .test-result {
            padding: 10px;
            margin: 8px 0;
            background: #f9fafb;
            border-left: 3px solid #d1d5db;
            border-radius: 4px;
            font-size: 13px;
        }
        .test-result.passed { border-left-color: #10b981; background: #f0fdf4; }
        .test-result.failed { border-left-color: #ef4444; background: #fef2f2; }
        .test-result code {
            background: #1f2937;
            color: #f9fafb;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 12px;
        }

        .view-section { display: none; }
        .view-section.active { display: block; }
    </style>
    CSS
  end

  def html_javascript
    <<~JAVASCRIPT
    <script>
        // Global state
        let filters = {
            status: new Set(['passed', 'failed', 'skipped']),
            severity: new Set(['high', 'medium', 'low']),
            search: ''
        };
        let currentView = 'controls';

        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            initializeFilters();
            initializeViewSwitcher();
            initializeExpandables();
            applyFilters();
        });

        function initializeFilters() {
            // Status filters
            document.querySelectorAll('.status-filter').forEach(btn => {
                btn.addEventListener('click', function() {
                    const status = this.dataset.status;
                    if (status === 'all') {
                        filters.status = new Set(['passed', 'failed', 'skipped']);
                        document.querySelectorAll('.status-filter').forEach(b => b.classList.remove('active'));
                        this.classList.add('active');
                    } else {
                        document.querySelector('[data-status="all"]').classList.remove('active');
                        if (filters.status.has(status)) {
                            filters.status.delete(status);
                            this.classList.remove('active');
                        } else {
                            filters.status.add(status);
                            this.classList.add('active');
                        }
                    }
                    applyFilters();
                });
            });

            // Severity filters
            document.querySelectorAll('.severity-filter').forEach(btn => {
                btn.addEventListener('click', function() {
                    const severity = this.dataset.severity;
                    if (severity === 'all') {
                        filters.severity = new Set(['high', 'medium', 'low']);
                        document.querySelectorAll('.severity-filter').forEach(b => b.classList.remove('active'));
                        this.classList.add('active');
                    } else {
                        document.querySelector('[data-severity="all"]').classList.remove('active');
                        if (filters.severity.has(severity)) {
                            filters.severity.delete(severity);
                            this.classList.remove('active');
                        } else {
                            filters.severity.add(severity);
                            this.classList.add('active');
                        }
                    }
                    applyFilters();
                });
            });

            // Search
            document.getElementById('searchBox').addEventListener('input', function(e) {
                filters.search = e.target.value.toLowerCase();
                applyFilters();
            });
        }

        function initializeViewSwitcher() {
            document.querySelectorAll('.view-btn').forEach(btn => {
                btn.addEventListener('click', function() {
                    document.querySelectorAll('.view-btn').forEach(b => b.classList.remove('active'));
                    this.classList.add('active');
                    currentView = this.dataset.view;
                    switchView(currentView);
                });
            });
        }

        function initializeExpandables() {
            document.querySelectorAll('.expandable-header').forEach(header => {
                header.addEventListener('click', function() {
                    const content = this.nextElementSibling;
                    const icon = this.querySelector('.expandable-icon');
                    content.classList.toggle('expanded');
                    icon.textContent = content.classList.contains('expanded') ? '▼' : '▶';
                });
            });

            // Handle section-level collapsible headers
            document.querySelectorAll('.section-header-collapsible').forEach(header => {
                header.addEventListener('click', function() {
                    const content = this.nextElementSibling;
                    const icon = this.querySelector('.section-collapse-icon');
                    content.classList.toggle('collapsed');
                    icon.textContent = content.classList.contains('collapsed') ? '▶' : '▼';
                });
            });
        }

        function applyFilters() {
            document.querySelectorAll('.control-card').forEach(card => {
                const status = card.dataset.status;
                const severities = (card.dataset.severities || '').split(',').filter(s => s);
                const searchText = card.textContent.toLowerCase();

                const statusMatch = filters.status.has(status);
                // If no severities (additional checks), always match
                const severityMatch = severities.length === 0 || severities.some(s => filters.severity.has(s));
                const searchMatch = !filters.search || searchText.includes(filters.search);

                if (statusMatch && severityMatch && searchMatch) {
                    card.classList.remove('hidden');
                } else {
                    card.classList.add('hidden');
                }
            });

            updateVisibleCount();
        }

        function switchView(view) {
            document.querySelectorAll('.view-section').forEach(section => {
                section.classList.remove('active');
            });
            document.getElementById(view + '-view').classList.add('active');
        }

        function updateVisibleCount() {
            const currentView = document.querySelector('.view-section.active');
            const viewId = currentView.id;

            // Count only cards in the active view
            const visible = currentView.querySelectorAll('.control-card:not(.hidden)').length;
            const total = currentView.querySelectorAll('.control-card').length;

            let label = 'items';
            if (viewId === 'controls-view') {
                label = 'controls';
            } else if (viewId === 'stig-rules-view') {
                label = 'STIG rules';
            } else if (viewId === 'groups-view') {
                label = 'rules';
            } else if (viewId === 'severity-view') {
                label = 'controls';
            } else if (viewId === 'failures-view') {
                label = 'failed controls';
            }

            document.getElementById('visibleCount').textContent = `Showing ${visible} of ${total} ${label}`;
        }
    </script>
    JAVASCRIPT
  end

  def html_body
    # This would be the full body HTML - simplified version here
    # In practice, this would render all controls with full details
    <<~HTML
    </head>
    <body>
      <div class="container">
        <div class="header">
            <h1>DISA STIG Compliance Report</h1>
            <div class="subtitle"><%= profile[:title] || 'Chainguard GPOS STIG' %></div>
        </div>

        <!-- Summary Section -->
        <div style="background: white; padding: 25px; border-radius: 12px; box-shadow: 0 2px 4px rgba(0,0,0,0.08); margin-bottom: 20px;">
            <h2 style="margin: 0 0 15px 0; color: #1e3a8a; font-size: 20px;">Scan Summary</h2>

            <!-- Coverage Overview Statement -->
            <div style="padding: 12px 15px; background: #eff6ff; border-left: 4px solid #3b82f6; border-radius: 6px; font-size: 14px; color: #1e3a8a; margin-bottom: 20px;">
                <strong><%= statistics[:total_controls] %> InSpec Controls</strong> covering
                <strong><%= statistics[:total_stig_rules] %> STIG Rules</strong> validated by
                <strong><%= statistics[:total_tests] %> Test Assertions</strong>
            </div>

            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 20px;">
                <!-- STIG Compliance (Primary Metric) -->
                <div style="text-align: center; padding: 20px; background: linear-gradient(135deg, #3b82f6 0%, #1e40af 100%); border-radius: 10px; color: white;">
                    <div style="font-size: 14px; opacity: 0.9; margin-bottom: 8px;">STIG COMPLIANCE</div>
                    <div style="font-size: 48px; font-weight: 700;"><%= statistics[:compliance_pct] %>%</div>
                    <div style="font-size: 13px; opacity: 0.9; margin-top: 8px;">
                        <%= statistics[:passed_stig_rules] %>/<%= statistics[:total_stig_rules] %> STIG Rules Pass
                    </div>
                </div>

                <!-- InSpec Controls -->
                <div style="padding: 20px; background: #f9fafb; border-radius: 10px; border-left: 4px solid #6366f1;">
                    <div style="font-size: 12px; color: #6b7280; text-transform: uppercase; margin-bottom: 8px;">InSpec Control Tests</div>
                    <div style="font-size: 32px; font-weight: 700; color: #1e3a8a; margin-bottom: 8px;"><%= statistics[:total_controls] %></div>
                    <div style="font-size: 13px; color: #6b7280;">
                        <span style="color: #10b981;"><%= statistics[:passed] %> passed</span>,
                        <span style="color: #ef4444;">✗ <%= statistics[:failed] %> failed</span>
                    </div>
                    <div style="font-size: 11px; color: #9ca3af; margin-top: 6px;">
                        Covering <%= statistics[:total_stig_rules] %> STIG rules
                    </div>
                </div>

                <!-- STIG Rule IDs -->
                <div style="padding: 20px; background: #f9fafb; border-radius: 10px; border-left: 4px solid #8b5cf6;">
                    <div style="font-size: 12px; color: #6b7280; text-transform: uppercase; margin-bottom: 8px;">STIG Rule IDs</div>
                    <div style="font-size: 32px; font-weight: 700; color: #1e3a8a; margin-bottom: 8px;"><%= statistics[:total_stig_rules] %></div>
                    <div style="font-size: 13px; color: #6b7280;">
                        <span style="color: #10b981;"><%= statistics[:passed_stig_rules] %></span>,
                        <span style="color: #ef4444;">✗ <%= statistics[:failed_stig_rules] %></span>,
                        <span style="color: #f59e0b;">⊘ <%= statistics[:skipped_stig_rules] %></span>
                    </div>
                    <div style="font-size: 11px; color: #9ca3af; margin-top: 6px;">
                        From <%= statistics[:total_controls] %> controls
                    </div>
                </div>

                <!-- Individual Tests -->
                <div style="padding: 20px; background: #f9fafb; border-radius: 10px; border-left: 4px solid #10b981;">
                    <div style="font-size: 12px; color: #6b7280; text-transform: uppercase; margin-bottom: 8px;">Individual Test Assertions</div>
                    <div style="font-size: 32px; font-weight: 700; color: #1e3a8a; margin-bottom: 8px;"><%= statistics[:total_tests] %></div>
                    <div style="font-size: 13px; color: #6b7280;">
                        <span style="color: #10b981;"><%= statistics[:passed_tests] %></span>,
                        <span style="color: #ef4444;">✗ <%= statistics[:failed_tests] %></span>,
                        <span style="color: #f59e0b;">⊘ <%= statistics[:skipped_tests] %></span>
                    </div>
                    <div style="font-size: 11px; color: #9ca3af; margin-top: 6px;">
                        Executed across <%= statistics[:total_controls] %> controls
                    </div>
                </div>
            </div>

            <!-- Control Coverage Breakdown (Collapsible) -->
            <div style="margin-top: 20px;">
                <div class="section-header-collapsible">
                    <span class="section-collapse-icon">▶</span>
                    <span style="font-size: 16px; font-weight: 600; color: #1e3a8a;">
                        Control Coverage Breakdown
                        <span style="font-size: 13px; color: #6b7280; font-weight: normal; margin-left: 8px;">
                            (Click to expand <%= statistics[:total_controls] %> controls)
                        </span>
                    </span>
                </div>

                <div class="section-content-collapsible collapsed">
                    <div style="background: #f9fafb; border-radius: 8px; padding: 15px; max-height: 400px; overflow-y: auto;">
                        <table style="width: 100%; font-size: 13px; border-collapse: collapse;">
                            <thead>
                                <tr style="border-bottom: 2px solid #e5e7eb;">
                                    <th style="text-align: left; padding: 8px; color: #6b7280; font-weight: 600;">Control ID</th>
                                    <th style="text-align: center; padding: 8px; color: #6b7280; font-weight: 600;">STIG Rules</th>
                                    <th style="text-align: center; padding: 8px; color: #6b7280; font-weight: 600;">Tests</th>
                                    <th style="text-align: center; padding: 8px; color: #6b7280; font-weight: 600;">Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                <% controls.each do |control| %>
                                <% status = control_status(control) %>
                                <% stig_count = (control.dig(:tags, :stig_rules) || []).length %>
                                <% test_count = control[:results].length %>
                                <tr style="border-bottom: 1px solid #e5e7eb;">
                                    <td style="padding: 8px; font-family: monospace; font-size: 12px;"><%= control[:id] %></td>
                                    <td style="padding: 8px; text-align: center; color: #6b7280;">
                                        <%= stig_count > 0 ? stig_count : '—' %>
                                    </td>
                                    <td style="padding: 8px; text-align: center; color: #6b7280;"><%= test_count %></td>
                                    <td style="padding: 8px; text-align: center;">
                                        <% if status == 'passed' %>
                                        <span style="color: #10b981; font-weight: 600;">PASS</span>
                                        <% elsif status == 'failed' %>
                                        <span style="color: #ef4444; font-weight: 600;">✗ FAIL</span>
                                        <% else %>
                                        <span style="color: #f59e0b; font-weight: 600;">⊘ SKIP</span>
                                        <% end %>
                                    </td>
                                </tr>
                                <% end %>
                            </tbody>
                            <tfoot>
                                <tr style="border-top: 2px solid #e5e7eb; font-weight: 600;">
                                    <td style="padding: 8px; color: #1e3a8a;">TOTAL</td>
                                    <td style="padding: 8px; text-align: center; color: #1e3a8a;"><%= statistics[:total_stig_rules] %></td>
                                    <td style="padding: 8px; text-align: center; color: #1e3a8a;"><%= statistics[:total_tests] %></td>
                                    <td style="padding: 8px; text-align: center; color: #1e3a8a;">
                                        <%= statistics[:passed] %>/<%= statistics[:total_controls] %>
                                    </td>
                                </tr>
                            </tfoot>
                        </table>
                    </div>
                </div>
            </div>

            <%
            additional_controls = controls.select { |c| (c.dig(:tags, :stig_rules) || []).empty? }
            if additional_controls.length > 0
            %>
            <div style="padding: 12px 15px; background: #fef3c7; border-left: 4px solid #f59e0b; border-radius: 6px; font-size: 13px; color: #92400e; margin-top: 10px;">
                <strong>⊕ <%= additional_controls.length %> Additional Security Check<%= additional_controls.length == 1 ? '' : 's' %></strong>
                (<%= statistics[:passed_additional] %> passed, <%= statistics[:failed_additional] %> failed) -
                These validate security posture but have no direct STIG rule mapping:
                <div style="margin-top: 6px; font-family: monospace; font-size: 12px;">
                    <%= additional_controls.map { |c| c[:id] }.join(', ') %>
                </div>
            </div>
            <% end %>

            <% if statistics[:not_applicable_rules] > 0 %>
            <div style="padding: 12px 15px; background: #f3f4f6; border-left: 4px solid #9ca3af; border-radius: 6px; font-size: 13px; color: #6b7280; margin-top: 10px;">
                <strong>⊘ <%= statistics[:not_applicable_rules] %> STIG Rules Marked Not Applicable</strong> -
                These rules do not apply to distroless Chainguard images (see "By Group" → "Not Applicable").
            </div>
            <% end %>
        </div>

        <!-- Toolbar with Filters -->
        <div class="toolbar">
            <div class="toolbar-section">
                <span class="toolbar-label">View Mode</span>
                <div class="view-tabs">
                    <button class="view-btn active" data-view="controls">Controls</button>
                    <button class="view-btn" data-view="stig-rules">STIG Rules</button>
                    <button class="view-btn" data-view="groups">By Group</button>
                    <button class="view-btn" data-view="severity">By Severity</button>
                    <button class="view-btn" data-view="failures">Failures Only</button>
                </div>
            </div>

            <div class="toolbar-section">
                <span class="toolbar-label">Status Filter</span>
                <div class="button-group">
                    <button class="filter-btn status-filter active" data-status="all">All</button>
                    <button class="filter-btn status-filter active" data-status="passed">Passed</button>
                    <button class="filter-btn status-filter active" data-status="failed">Failed</button>
                    <button class="filter-btn status-filter active" data-status="skipped">Skipped</button>
                </div>
            </div>

            <div class="toolbar-section">
                <span class="toolbar-label">Severity Filter</span>
                <div class="button-group">
                    <button class="filter-btn severity-filter active" data-severity="all">All</button>
                    <button class="filter-btn severity-filter active" data-severity="high">High</button>
                    <button class="filter-btn severity-filter active" data-severity="medium">Medium</button>
                    <button class="filter-btn severity-filter active" data-severity="low">Low</button>
                </div>
            </div>

            <div class="toolbar-section">
                <span class="toolbar-label">Search</span>
                <input type="text" id="searchBox" class="search-box" placeholder="Search STIG rules, CCIs, or descriptions...">
            </div>

            <div id="visibleCount" style="margin-top: 10px; font-size: 13px; color: #6b7280;"></div>
        </div>

        <!-- Controls View -->
        <div id="controls-view" class="view-section active">
            <div class="controls-section">
                <!-- Scan Information -->
                <div style="background: #f9fafb; padding: 15px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #e5e7eb;">
                    <h3 style="font-size: 12px; color: #6b7280; text-transform: uppercase; margin-bottom: 10px; font-weight: 600;">Scan Information</h3>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; font-size: 13px;">
                        <% if container_name %>
                        <div>
                            <strong style="color: #6b7280;">Container:</strong>
                            <div style="font-family: monospace; font-size: 11px; color: #111827; margin-top: 2px;"><%= container_name %></div>
                        </div>
                        <% end %>
                        <div>
                            <strong style="color: #6b7280;">Profile:</strong>
                            <div style="color: #111827; margin-top: 2px;"><%= profile[:name] %></div>
                        </div>
                        <div>
                            <strong style="color: #6b7280;">Scan Date:</strong>
                            <div style="color: #111827; margin-top: 2px;"><%= Time.now.strftime('%Y-%m-%d %H:%M') %></div>
                        </div>
                        <% if container_label %>
                        <div>
                            <strong style="color: #6b7280;">Environment:</strong>
                            <div style="color: #111827; margin-top: 2px;"><%= container_label %></div>
                        </div>
                        <% end %>
                    </div>
                </div>

                <h2 style="margin-bottom: 20px;">Control Results</h2>
                <% controls.each do |control| %>
                <% status = control_status(control) %>
                <% stig_rules = control.dig(:tags, :stig_rules) || [] %>
                <% severities = control.dig(:tags, :stig_severities) || [] %>
                <div class="control-card"
                     data-status="<%= status %>"
                     data-severities="<%= severities.join(',') %>">

                    <div class="control-header">
                        <div>
                            <div class="control-id"><%= control[:id] %></div>
                            <h3 style="margin: 4px 0; font-size: 16px;"><%= control[:title] %></h3>
                            <% if stig_rules.empty? %>
                            <div style="margin-top: 6px;">
                                <span style="background: #dbeafe; color: #1e40af; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;">⊕ ADDITIONAL CHECK (No STIG Mapping)</span>
                            </div>
                            <% end %>
                        </div>
                        <span class="status-badge <%= status %>"><%= status.upcase %></span>
                    </div>

                    <!-- STIG Rules (collapsed by default) -->
                    <% if !stig_rules.empty? %>
                    <div class="expandable-header">
                        <span class="expandable-icon">▶</span>
                        STIG Rules (<%= stig_rules.length %>)
                    </div>
                    <div class="expandable-content">
                        <div class="stig-tags">
                            <% stig_rules.each_with_index do |rule_id, idx| %>
                            <% rule_details = get_stig_rule_details(rule_id) %>
                            <% severity = severities[idx] || 'medium' %>
                            <span class="stig-tag <%= severity_class(severity) %>"
                                  title="<%= escape_html(rule_details[:title] || '') %>">
                                <%= stig_mappings.short_id(rule_id) %>
                            </span>
                            <% end %>
                        </div>

                        <!-- STIG Rule Descriptions -->
                        <% stig_rules.each do |rule_id| %>
                        <% rule_details = get_stig_rule_details(rule_id) %>
                        <% if rule_details[:description] && !rule_details[:description].empty? %>
                        <div style="margin: 10px 0; padding: 10px; background: #f9fafb; border-radius: 4px; font-size: 12px;">
                            <strong><%= stig_mappings.short_id(rule_id) %>:</strong>
                            <%= escape_html(rule_details[:description]) %>
                        </div>
                        <% end %>
                        <% end %>
                    </div>
                    <% end %>

                    <!-- Test Results (collapsed by default) -->
                    <div class="expandable-header">
                        <span class="expandable-icon">▶</span>
                        Test Results (<%= control[:results].length %> tests)
                    </div>
                    <div class="expandable-content">
                        <%
                        passed_count = control[:results].count { |r| r[:status] == 'passed' }
                        failed_count = control[:results].count { |r| r[:status] == 'failed' }
                        skipped_count = control[:results].count { |r| r[:status] == 'skipped' }
                        %>
                        <div style="margin-bottom: 10px; padding: 8px; background: #f3f4f6; border-radius: 4px; font-size: 12px;">
                            <strong>Summary:</strong>
                            <span style="color: #10b981;"><%= passed_count %> passed</span>,
                            <span style="color: #ef4444;">✗ <%= failed_count %> failed</span>,
                            <span style="color: #f59e0b;">⊘ <%= skipped_count %> skipped</span>
                        </div>
                        <% control[:results].each_with_index do |result, idx| %>
                        <div class="test-result <%= result[:status] %>">
                            <div><strong>[<%= idx + 1 %>] <%= result[:code_desc] %></strong></div>
                            <div style="margin-top: 4px;">Status: <strong><%= result[:status].upcase %></strong></div>
                            <% if result[:message] %>
                            <div style="margin-top: 4px;">Message: <%= escape_html(result[:message]) %></div>
                            <% end %>
                            <% if result[:status] == 'failed' && result[:exception] %>
                            <div style="margin-top: 4px; color: #ef4444;">Error: <%= escape_html(result[:exception]) %></div>
                            <% end %>
                            <% if result[:run_time] %>
                            <div style="margin-top: 4px; font-size: 11px; color: #6b7280;">Runtime: <%= (result[:run_time] * 1000).round(2) %> ms</div>
                            <% end %>
                        </div>
                        <% end %>
                    </div>

                </div>
                <% end %>
            </div>
        </div>

        <!-- STIG Rules View: One card per STIG rule -->
        <div id="stig-rules-view" class="view-section">
            <div class="controls-section">
                <!-- Scan Information -->
                <div style="background: #f9fafb; padding: 15px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #e5e7eb;">
                    <h3 style="font-size: 12px; color: #6b7280; text-transform: uppercase; margin-bottom: 10px; font-weight: 600;">Scan Information</h3>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; font-size: 13px;">
                        <% if container_name %>
                        <div>
                            <strong style="color: #6b7280;">Container:</strong>
                            <div style="font-family: monospace; font-size: 11px; color: #111827; margin-top: 2px;"><%= container_name %></div>
                        </div>
                        <% end %>
                        <div>
                            <strong style="color: #6b7280;">Profile:</strong>
                            <div style="color: #111827; margin-top: 2px;"><%= profile[:name] %></div>
                        </div>
                        <div>
                            <strong style="color: #6b7280;">Scan Date:</strong>
                            <div style="color: #111827; margin-top: 2px;"><%= Time.now.strftime('%Y-%m-%d %H:%M') %></div>
                        </div>
                        <% if container_label %>
                        <div>
                            <strong style="color: #6b7280;">Environment:</strong>
                            <div style="color: #111827; margin-top: 2px;"><%= container_label %></div>
                        </div>
                        <% end %>
                    </div>
                </div>

                <h2 style="margin-bottom: 20px;">STIG Rules (<%= statistics[:total_stig_rules] %> Total)</h2>
                <%
                # Build map of STIG rule -> controls
                stig_to_controls = {}
                controls.each do |control|
                    status = control_status(control)
                    stig_rules = control.dig(:tags, :stig_rules) || []
                    stig_rules.each do |rule_id|
                        stig_to_controls[rule_id] ||= []
                        stig_to_controls[rule_id] << {control: control, status: status}
                    end
                end

                stig_to_controls.keys.sort.each do |rule_id|
                    rule_details = get_stig_rule_details(rule_id)
                    controls_list = stig_to_controls[rule_id]
                    overall_status = controls_list.any? { |c| c[:status] == 'failed' } ? 'failed' :
                                    controls_list.all? { |c| c[:status] == 'passed' } ? 'passed' : 'skipped'
                    severities = controls_list.flat_map { |c| c[:control].dig(:tags, :stig_severities) || [] }.uniq
                %>
                <div class="control-card"
                     data-status="<%= overall_status %>"
                     data-severities="<%= severities.join(',') %>">

                    <div class="control-header">
                        <div>
                            <div class="control-id"><%= stig_mappings.short_id(rule_id) %></div>
                            <h3 style="margin: 4px 0; font-size: 16px;"><%= escape_html(rule_details[:title] || 'No title') %></h3>
                            <div style="margin-top: 8px;">
                                <% if rule_details[:cci] && !rule_details[:cci].empty? %>
                                <span class="cci-badge"><%= rule_details[:cci] %></span>
                                <% end %>
                                <% severities.each do |sev| %>
                                <span class="stig-tag <%= severity_class(sev) %>"><%= sev.upcase %></span>
                                <% end %>
                            </div>
                        </div>
                        <span class="status-badge <%= overall_status %>"><%= overall_status.upcase %></span>
                    </div>

                    <% if rule_details[:description] && !rule_details[:description].empty? %>
                    <div class="expandable-header">
                        <span class="expandable-icon">▶</span>
                        Description
                    </div>
                    <div class="expandable-content">
                        <div style="padding: 10px; background: #f9fafb; border-radius: 4px; font-size: 13px;">
                            <%= escape_html(rule_details[:description]) %>
                        </div>
                    </div>
                    <% end %>

                    <div class="expandable-header">
                        <span class="expandable-icon">▶</span>
                        Validated by <%= controls_list.length %> Control<%= controls_list.length == 1 ? '' : 's' %>
                    </div>
                    <div class="expandable-content">
                        <% controls_list.each do |item| %>
                        <div style="margin: 8px 0; padding: 10px; background: white; border: 1px solid #e5e7eb; border-radius: 4px;">
                            <strong><%= item[:control][:id] %></strong>: <%= item[:control][:title] %>
                            <span class="status-badge <%= item[:status] %>" style="margin-left: 10px;"><%= item[:status].upcase %></span>
                        </div>
                        <% end %>
                    </div>
                </div>
                <% end %>
            </div>
        </div>

        <!-- Groups View: Group by XCCDF Group -->
        <div id="groups-view" class="view-section">
            <div class="controls-section">
                <!-- Scan Information -->
                <div style="background: #f9fafb; padding: 15px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #e5e7eb;">
                    <h3 style="font-size: 12px; color: #6b7280; text-transform: uppercase; margin-bottom: 10px; font-weight: 600;">Scan Information</h3>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; font-size: 13px;">
                        <% if container_name %>
                        <div>
                            <strong style="color: #6b7280;">Container:</strong>
                            <div style="font-family: monospace; font-size: 11px; color: #111827; margin-top: 2px;"><%= container_name %></div>
                        </div>
                        <% end %>
                        <div>
                            <strong style="color: #6b7280;">Profile:</strong>
                            <div style="color: #111827; margin-top: 2px;"><%= profile[:name] %></div>
                        </div>
                        <div>
                            <strong style="color: #6b7280;">Scan Date:</strong>
                            <div style="color: #111827; margin-top: 2px;"><%= Time.now.strftime('%Y-%m-%d %H:%M') %></div>
                        </div>
                        <% if container_label %>
                        <div>
                            <strong style="color: #6b7280;">Environment:</strong>
                            <div style="color: #111827; margin-top: 2px;"><%= container_label %></div>
                        </div>
                        <% end %>
                    </div>
                </div>

                <h2 style="margin-bottom: 20px;">STIG Rules by Group</h2>
                <%
                # Build map of group -> STIG rules
                groups_map = {}
                stig_mappings.all_rules.each do |rule_id, rule_data|
                    next if rule_data[:check_href].empty?
                    group_name = rule_data[:group_name]
                    group_name = 'Ungrouped' if group_name.nil? || group_name.empty?
                    groups_map[group_name] ||= []
                    groups_map[group_name] << rule_data
                end

                groups_map.keys.sort.each do |group_name|
                    group_rules = groups_map[group_name]
                %>
                <div style="margin-bottom: 30px;">
                    <div class="section-header-collapsible" style="background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%); color: white;">
                        <span class="section-collapse-icon">▼</span>
                        <span style="font-size: 18px; font-weight: 600;">
                            <%= group_name %>
                            <span style="margin-left: 10px; font-size: 14px; opacity: 0.9;">
                                (<%= group_rules.length %> STIG Rules)
                            </span>
                        </span>
                    </div>

                    <div class="section-content-collapsible">

                    <% group_rules.each do |rule_data| %>
                    <%
                    # Find control status for this rule
                    rule_status = 'skipped'
                    related_control = nil
                    short_rule_id = stig_mappings.short_id(rule_data[:rule_id])
                    controls.each do |c|
                        if (c.dig(:tags, :stig_rules) || []).include?(short_rule_id)
                            related_control = c
                            rule_status = control_status(c)
                            break
                        end
                    end
                    %>
                    <div class="control-card"
                         data-status="<%= rule_status %>"
                         data-severities="<%= rule_data[:severity] %>">

                        <div class="control-header">
                            <div>
                                <div class="control-id"><%= stig_mappings.short_id(rule_data[:rule_id]) %></div>
                                <h4 style="margin: 4px 0; font-size: 15px;"><%= escape_html(rule_data[:title]) %></h4>
                                <div style="margin-top: 8px;">
                                    <% if rule_data[:cci] && !rule_data[:cci].empty? %>
                                    <span class="cci-badge"><%= rule_data[:cci] %></span>
                                    <% end %>
                                    <span class="stig-tag <%= severity_class(rule_data[:severity]) %>"><%= rule_data[:severity].upcase %></span>
                                </div>
                            </div>
                            <span class="status-badge <%= rule_status %>"><%= rule_status.upcase %></span>
                        </div>

                        <% if rule_data[:description] && !rule_data[:description].empty? %>
                        <div class="expandable-header">
                            <span class="expandable-icon">▶</span>
                            Description
                        </div>
                        <div class="expandable-content">
                            <div style="padding: 10px; background: #f9fafb; border-radius: 4px; font-size: 13px;">
                                <%= escape_html(rule_data[:description]) %>
                            </div>
                        </div>
                        <% end %>

                        <% if related_control %>
                        <div style="margin-top: 10px; font-size: 13px; color: #6b7280;">
                            <strong>Validated by:</strong> <%= related_control[:id] %> - <%= related_control[:title] %>
                        </div>
                        <% end %>
                    </div>
                    <% end %>
                    </div><!-- end section-content-collapsible -->
                </div>
                <% end %>

                <%
                # Add Not Applicable group
                not_applicable_rules = stig_mappings.all_rules.values.select { |r| r[:not_applicable] }
                unless not_applicable_rules.empty?
                %>
                <div style="margin-bottom: 30px;">
                    <div class="section-header-collapsible" style="background: #9ca3af; color: white;">
                        <span class="section-collapse-icon">▼</span>
                        <span style="font-size: 18px; font-weight: 600;">
                            Not Applicable
                            <span style="margin-left: 10px; font-size: 14px; opacity: 0.9;">
                                (<%= not_applicable_rules.length %> STIG Rules)
                            </span>
                        </span>
                    </div>

                    <div class="section-content-collapsible">
                    <div style="padding: 15px; background: #f9fafb; border-radius: 8px; margin-bottom: 15px; font-size: 13px; color: #6b7280;">
                        These STIG rules are not applicable to distroless Chainguard images due to missing components or architectural differences.
                    </div>

                    <% not_applicable_rules.each do |rule_data| %>
                    <div class="control-card" data-status="skipped" data-severities="<%= rule_data[:severity] %>">
                        <div class="control-header">
                            <div>
                                <div class="control-id"><%= stig_mappings.short_id(rule_data[:rule_id]) %></div>
                                <h4 style="margin: 4px 0; font-size: 15px;"><%= escape_html(rule_data[:title]) %></h4>
                                <div class="stig-tags">
                                    <span class="stig-tag <%= severity_class(rule_data[:severity]) %>">
                                        <%= rule_data[:severity].upcase %>
                                    </span>
                                    <% if rule_data[:cci] && !rule_data[:cci].empty? %>
                                    <span class="stig-tag cci"><%= rule_data[:cci] %></span>
                                    <% end %>
                                </div>
                            </div>
                            <span class="status-badge skipped">NOT APPLICABLE</span>
                        </div>

                        <% if rule_data[:description] && !rule_data[:description].empty? %>
                        <div class="expandable-header">
                            <span class="expandable-icon">▶</span>
                            Description
                        </div>
                        <div class="expandable-content">
                            <div style="padding: 10px; background: #f9fafb; border-radius: 4px; font-size: 13px;">
                                <%= escape_html(rule_data[:description]) %>
                            </div>
                        </div>
                        <% end %>
                    </div>
                    <% end %>
                    </div><!-- end section-content-collapsible -->
                </div>
                <% end %>
            </div>
        </div>

        <!-- Severity View: Group by High/Medium/Low -->
        <div id="severity-view" class="view-section">
            <div class="controls-section">
                <!-- Scan Information -->
                <div style="background: #f9fafb; padding: 15px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #e5e7eb;">
                    <h3 style="font-size: 12px; color: #6b7280; text-transform: uppercase; margin-bottom: 10px; font-weight: 600;">Scan Information</h3>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; font-size: 13px;">
                        <% if container_name %>
                        <div>
                            <strong style="color: #6b7280;">Container:</strong>
                            <div style="font-family: monospace; font-size: 11px; color: #111827; margin-top: 2px;"><%= container_name %></div>
                        </div>
                        <% end %>
                        <div>
                            <strong style="color: #6b7280;">Profile:</strong>
                            <div style="color: #111827; margin-top: 2px;"><%= profile[:name] %></div>
                        </div>
                        <div>
                            <strong style="color: #6b7280;">Scan Date:</strong>
                            <div style="color: #111827; margin-top: 2px;"><%= Time.now.strftime('%Y-%m-%d %H:%M') %></div>
                        </div>
                        <% if container_label %>
                        <div>
                            <strong style="color: #6b7280;">Environment:</strong>
                            <div style="color: #111827; margin-top: 2px;"><%= container_label %></div>
                        </div>
                        <% end %>
                    </div>
                </div>

                <h2 style="margin-bottom: 20px;">Controls by Severity</h2>

                <% ['high', 'medium', 'low'].each do |severity_level| %>
                <% severity_controls = controls.select { |c| (c.dig(:tags, :stig_severities) || []).include?(severity_level) } %>
                <% next if severity_controls.empty? %>

                <div style="margin-bottom: 30px;">
                    <div class="section-header-collapsible">
                        <span class="section-collapse-icon">▼</span>
                        <span style="font-size: 18px; font-weight: 600;">
                            <span class="stig-tag <%= severity_class(severity_level) %>" style="padding: 6px 12px; font-size: 14px;">
                                <%= severity_level.upcase %>
                            </span>
                            <span style="margin-left: 10px; font-size: 16px; color: #374151;">
                                <%= severity_controls.length %> Controls
                            </span>
                        </span>
                    </div>

                    <div class="section-content-collapsible">

                    <% severity_controls.each do |control| %>
                    <% status = control_status(control) %>
                    <% stig_rules = control.dig(:tags, :stig_rules) || [] %>
                    <div class="control-card"
                         data-status="<%= status %>"
                         data-severities="<%= severity_level %>">

                        <div class="control-header">
                            <div>
                                <div class="control-id"><%= control[:id] %></div>
                                <h4 style="margin: 4px 0; font-size: 15px;"><%= control[:title] %></h4>
                                <div class="stig-tags">
                                    <% stig_rules.first(5).each do |rule_id| %>
                                    <span class="stig-tag <%= severity_class(severity_level) %>">
                                        <%= stig_mappings.short_id(rule_id) %>
                                    </span>
                                    <% end %>
                                </div>
                            </div>
                            <span class="status-badge <%= status %>"><%= status.upcase %></span>
                        </div>
                    </div>
                    <% end %>
                    </div><!-- end section-content-collapsible -->
                </div>
                <% end %>
            </div>
        </div>

        <!-- Failures Only View -->
        <div id="failures-view" class="view-section">
            <div class="controls-section">
                <!-- Scan Information -->
                <div style="background: #f9fafb; padding: 15px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #e5e7eb;">
                    <h3 style="font-size: 12px; color: #6b7280; text-transform: uppercase; margin-bottom: 10px; font-weight: 600;">Scan Information</h3>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; font-size: 13px;">
                        <% if container_name %>
                        <div>
                            <strong style="color: #6b7280;">Container:</strong>
                            <div style="font-family: monospace; font-size: 11px; color: #111827; margin-top: 2px;"><%= container_name %></div>
                        </div>
                        <% end %>
                        <div>
                            <strong style="color: #6b7280;">Profile:</strong>
                            <div style="color: #111827; margin-top: 2px;"><%= profile[:name] %></div>
                        </div>
                        <div>
                            <strong style="color: #6b7280;">Scan Date:</strong>
                            <div style="color: #111827; margin-top: 2px;"><%= Time.now.strftime('%Y-%m-%d %H:%M') %></div>
                        </div>
                        <% if container_label %>
                        <div>
                            <strong style="color: #6b7280;">Environment:</strong>
                            <div style="color: #111827; margin-top: 2px;"><%= container_label %></div>
                        </div>
                        <% end %>
                    </div>
                </div>

                <h2 style="margin-bottom: 20px; color: #ef4444;">Failed Controls</h2>
                <%
                failed_controls = controls.select { |c| control_status(c) == 'failed' }
                if failed_controls.empty?
                %>
                <div style="text-align: center; padding: 60px 20px; background: #f0fdf4; border-radius: 12px;">
                    <div style="font-size: 48px; margin-bottom: 20px;"></div>
                    <h3 style="color: #10b981; font-size: 24px; margin-bottom: 10px;">All Controls Passed!</h3>
                    <p style="color: #6b7280;">No failed controls to display.</p>
                </div>
                <% else %>
                <div style="background: #fef2f2; padding: 15px; border-left: 4px solid #ef4444; border-radius: 4px; margin-bottom: 20px;">
                    <strong style="color: #991b1b;"><%= failed_controls.length %> Control<%= failed_controls.length == 1 ? '' : 's' %> Failed</strong>
                    <div style="margin-top: 5px; font-size: 14px; color: #6b7280;">
                        Review and remediate the issues below to improve compliance.
                    </div>
                </div>

                <% failed_controls.each do |control| %>
                <% stig_rules = control.dig(:tags, :stig_rules) || [] %>
                <% severities = control.dig(:tags, :stig_severities) || [] %>
                <% failed_results = control[:results].select { |r| r[:status] == 'failed' } %>

                <div class="control-card"
                     data-status="failed"
                     data-severities="<%= severities.join(',') %>"
                     style="border-left: 4px solid #ef4444;">
                    <div class="control-header">
                        <div>
                            <div class="control-id"><%= control[:id] %></div>
                            <h3 style="margin: 4px 0; font-size: 16px;"><%= control[:title] %></h3>
                        </div>
                        <span class="status-badge failed">FAILED</span>
                    </div>

                    <% if !stig_rules.empty? %>
                    <div style="margin: 10px 0;">
                        <strong style="font-size: 12px; color: #6b7280;">IMPACTED STIG RULES:</strong>
                        <div class="stig-tags" style="margin-top: 5px;">
                            <% stig_rules.first(10).each_with_index do |rule_id, idx| %>
                            <span class="stig-tag <%= severity_class(severities[idx] || 'medium') %>">
                                <%= stig_mappings.short_id(rule_id) %>
                            </span>
                            <% end %>
                        </div>
                    </div>
                    <% end %>

                    <div class="expandable-header">
                        <span class="expandable-icon">▶</span>
                        Failed Tests (<%= failed_results.length %>)
                    </div>
                    <div class="expandable-content">
                        <% failed_results.each do |result| %>
                        <div class="test-result failed">
                            <div><strong><%= result[:code_desc] %></strong></div>
                            <% if result[:message] %>
                            <div style="margin-top: 6px; color: #991b1b;"><%= escape_html(result[:message]) %></div>
                            <% end %>
                            <% if result[:exception] %>
                            <div style="margin-top: 6px; font-size: 12px; color: #7f1d1d;">
                                <%= escape_html(result[:exception]) %>
                            </div>
                            <% end %>
                        </div>
                        <% end %>
                    </div>
                </div>
                <% end %>
                <% end %>
            </div>
        </div>

      </div>
    </body>
    </html>
    HTML
  end
end

# CLI execution
if __FILE__ == $0
  if ARGV.length < 2
    puts "Usage: #{$0} <input.json> <output.html> [--container-name NAME] [--container-label LABEL] [--container-sha256 SHA]"
    exit 1
  end

  json_file = ARGV[0]
  output_file = ARGV[1]

  options = {}
  i = 2
  while i < ARGV.length
    case ARGV[i]
    when '--container-name'
      options[:container_name] = ARGV[i + 1]
      i += 2
    when '--container-label'
      options[:container_label] = ARGV[i + 1]
      i += 2
    when '--container-sha256'
      options[:container_sha256] = ARGV[i + 1]
      i += 2
    else
      i += 1
    end
  end

  generator = StigHtmlGenerator.new(json_file, output_file, **options)
  generator.generate
end
