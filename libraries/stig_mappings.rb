# Copyright (c) 2025 Cisco Systems, Inc. and/or its affiliates
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

# STIG Mapping Library
# Parses XCCDF XML directly to extract STIG metadata and OVAL check mappings

require 'rexml/document'

class StigMappings
  attr_reader :mappings_by_check, :all_rules, :unmapped_rules

  def initialize(xccdf_path = nil)
    xccdf_path ||= File.join(File.dirname(__FILE__), '../../benchmarks/ssg-chainguard-gpos-ds.xml')
    @mappings_by_check = {}
    @all_rules = {}
    @unmapped_rules = []

    load_xccdf(xccdf_path) if File.exist?(xccdf_path)
  end

  def load_xccdf(xccdf_path)
    doc = REXML::Document.new(File.read(xccdf_path))

    # Parse all Rule elements
    REXML::XPath.each(doc, '//ns0:Rule', { 'ns0' => 'http://checklists.nist.gov/xccdf/1.2' }) do |rule|
      parse_rule(rule)
    end
  end

  def parse_rule(rule_element)
    # Extract rule ID and severity
    rule_id = rule_element.attributes['id']
    return if rule_id.nil? || rule_id.empty?

    severity = rule_element.attributes['severity'] || 'medium'

    # Extract title - get all text content
    title_elem = REXML::XPath.first(rule_element, 'ns0:title', { 'ns0' => 'http://checklists.nist.gov/xccdf/1.2' })
    title = title_elem ? title_elem.get_text.to_s.strip.gsub(/\s+/, ' ') : ''

    # Extract description - get all text content
    desc_elem = REXML::XPath.first(rule_element, 'ns0:description', { 'ns0' => 'http://checklists.nist.gov/xccdf/1.2' })
    description = desc_elem ? desc_elem.get_text.to_s.strip.gsub(/\s+/, ' ') : ''

    # Extract CCI identifiers
    ccis = []
    REXML::XPath.each(rule_element, 'ns0:ident[@system="http://cyber.mil/cci"]', { 'ns0' => 'http://checklists.nist.gov/xccdf/1.2' }) do |cci|
      ccis << cci.text.to_s.strip
    end

    # Extract OVAL check reference
    check_ref = REXML::XPath.first(rule_element, 'ns0:check/ns0:check-content-ref', { 'ns0' => 'http://checklists.nist.gov/xccdf/1.2' })
    check_href = check_ref ? check_ref.attributes['href'] : nil

    # Extract group (parent element)
    group_elem = rule_element.parent
    group_id = ''
    group_name = ''
    not_applicable = false
    if group_elem && group_elem.name == 'Group'
      group_id = group_elem.attributes['id'] || ''
      # Check if this is the not_applicable group
      not_applicable = group_id.include?('not_applicable_tests')
      # Extract group name from ID (e.g., "xccdf_._group_Open_Ssl" -> "Open_Ssl")
      if group_id =~ /group_(.+)$/
        group_name = $1.gsub('_', ' ')
      end
    end

    # Store rule metadata
    rule_data = {
      rule_id: rule_id,
      severity: severity,
      cci: ccis.join(', '),
      title: title,
      description: description,
      check_href: check_href || '',
      group_id: group_id,
      group_name: group_name,
      not_applicable: not_applicable
    }

    @all_rules[rule_id] = rule_data

    if check_href && !check_href.empty?
      # Extract check name from href (e.g., "DetectOpenSslTest.xml" -> "DetectOpenSslTest")
      check_name = File.basename(check_href, '.xml')
      @mappings_by_check[check_name] ||= []
      @mappings_by_check[check_name] << rule_data
    else
      @unmapped_rules << rule_data
    end
  end

  def rules_for_check(check_name)
    @mappings_by_check[check_name] || []
  end

  def check_names
    @mappings_by_check.keys.sort
  end

  def rule_count_for_check(check_name)
    rules_for_check(check_name).length
  end

  def total_mapped_rules
    @mappings_by_check.values.flatten.length
  end

  def total_unmapped_rules
    @unmapped_rules.length
  end

  # Format STIG rule for reporting
  def format_rule_list(rules, max_display = 3)
    return '' if rules.empty?

    lines = []
    rules.first(max_display).each do |rule|
      # Clean up rule_id (remove xccdf prefix)
      short_id = rule[:rule_id].sub('xccdf_mil.disa.stig_rule_', '')
      lines << "  • #{short_id} [#{rule[:severity]}]: #{rule[:title][0..80]}"
    end

    if rules.length > max_display
      lines << "  • ... and #{rules.length - max_display} more STIG rules"
    end

    lines.join("\n")
  end

  # Get short STIG ID (e.g., "SV-203739r987791_rule")
  def short_id(rule_id)
    rule_id.sub('xccdf_mil.disa.stig_rule_', '')
  end
end
