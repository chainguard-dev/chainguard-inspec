# Copyright (c) 2025 Cisco Systems, Inc. and/or its affiliates
# Copyright (c) 2025 Chainguard
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

control 'oval:org.OpenSsl:def:1' do
  impact 0.5
  title 'Check for OpenSSL FIPS Packages'
  desc 'Ensure that the necessary OpenSSL FIPS packages and configuration files are present.'

  # STIG Rule Mappings

  tag stig_rules: [

    'SV-203739r987791_rule',

    'SV-203776r959006_rule',

    'SV-203750r958912_rule',

    'SV-203751r958914_rule',

    'SV-203649r971535_rule'

  ]

  tag stig_severities: ['high', 'medium']

  tag ccis: ['CCI-002450', 'CCI-002420', 'CCI-002422', 'CCI-000803']

  rootfs = ENV['ROOTFS_DIR'] || input('rootfs')
  ssl_dir = File.join(rootfs, 'etc/ssl')
  installed_db_path = File.join(rootfs, 'lib/apk/db/installed')

  ssl_dir_resource = directory(ssl_dir)
  describe ssl_dir_resource do
    it { should exist }
  end

  # Find FIPS module files
  fips_module_files =
    if ssl_dir_resource.exist?
      command("find #{ssl_dir} -type f -a -name '*fipsmodule*' -print0").stdout.split("\0").sort
    else
      []
    end

  # Find OpenSSL config files
  openssl_conf_files =
    if ssl_dir_resource.exist?
      command("find #{ssl_dir} -type f -a -name '*openssl*' -print0").stdout.split("\0").sort
    else
      []
    end

  # Check and display FIPS module files with contents
  describe 'FIPS module configuration files in /etc/ssl' do
    it 'should have FIPS module configuration' do
      if fips_module_files.empty?
        expect(fips_module_files).not_to be_empty, "No FIPS module files found in #{ssl_dir}"
      else
        files = fips_module_files.map { |f| File.basename(f) }.join(', ')
        expect(fips_module_files).not_to be_empty, "Found #{fips_module_files.length} FIPS module file(s): #{files}"
      end
    end
  end

  # Read and display each FIPS module file content
  fips_module_files.each do |fips_file|
    file_resource = file(fips_file)

    describe file_resource do
      it { should exist }
      it { should be_readable }
      its('content') { should_not be_empty }
    end

    next unless file_resource.exist? && !file_resource.content.empty?

    # Display full content of FIPS module file
    content = file_resource.content.strip
    describe "FIPS module file: #{File.basename(fips_file)} (#{content.lines.count} lines)" do
      it "Full contents:\n#{content}" do
        expect(content.length).to be > 0
      end
    end
  end

  # Check OpenSSL config files
  describe 'OpenSSL configuration files in /etc/ssl' do
    it 'should have OpenSSL configuration' do
      if openssl_conf_files.empty?
        expect(openssl_conf_files).not_to be_empty, "No OpenSSL configuration files found in #{ssl_dir}"
      else
        files = openssl_conf_files.map { |f| File.basename(f) }.join(', ')
        expect(openssl_conf_files).not_to be_empty, "Found #{openssl_conf_files.length} OpenSSL config file(s): #{files}"
      end
    end
  end

  # Read and display each OpenSSL config file content
  openssl_conf_files.each do |conf_file|
    file_resource = file(conf_file)

    describe file_resource do
      it { should exist }
      it { should be_readable }
      its('content') { should_not be_empty }
      its('content') { should match(/^\s*\.include\s+fipsmodule\.cnf\s*$/) }
    end

    # Check provider_sect and its fips setting
    describe "OpenSSL config #{File.basename(conf_file)}: [provider_sect] configuration" do
      subject { ini(conf_file) }

      it 'has [provider_sect] section with fips = fips_sect' do
        expect(subject['provider_sect']).not_to be_nil,
          "[provider_sect] section is missing from #{conf_file}"
        expect(subject['provider_sect']['fips']).not_to be_nil,
          "[provider_sect] section exists but 'fips' key is missing in #{conf_file}"
        expect(subject['provider_sect']['fips']).to eq('fips_sect'),
          "[provider_sect] fips should be 'fips_sect' but got '#{subject['provider_sect']&.[]('fips')}' in #{conf_file}"
      end
    end

    # Check algorithm_sect and its default_properties setting
    describe "OpenSSL config #{File.basename(conf_file)}: [algorithm_sect] configuration" do
      subject { ini(conf_file) }

      it 'has [algorithm_sect] section with default_properties = fips=yes' do
        expect(subject['algorithm_sect']).not_to be_nil,
          "[algorithm_sect] section is missing from #{conf_file}"
        expect(subject['algorithm_sect']['default_properties']).not_to be_nil,
          "[algorithm_sect] section exists but 'default_properties' key is missing in #{conf_file}"
        expect(subject['algorithm_sect']['default_properties']).to eq('fips=yes'),
          "[algorithm_sect] default_properties should be 'fips=yes' but got '#{subject['algorithm_sect']&.[]('default_properties')}' in #{conf_file}"
      end
    end

    next unless file_resource.exist? && !file_resource.content.empty?

    # Display full content of OpenSSL config file
    content = file_resource.content.strip
    describe "OpenSSL config file: #{File.basename(conf_file)} (#{content.lines.count} lines)" do
      it "Full contents:\n#{content}" do
        expect(content.length).to be > 0
      end
    end
  end

  # Verify that the expected openssl fips packages are installed
  installed_db_resource = file(installed_db_path)

  describe installed_db_resource do
    it { should exist }
    it { should be_readable }
    its('content') { should_not be_empty }
  end

  # Read installed DB using command
  installed_db_read = installed_db_resource.content

  required_packages = %w[openssl-config-fipshardened openssl-provider-fips]
  present_packages = []
  package_details = {}

  unless installed_db_read.empty?
    lines = installed_db_read.split("\n")

    # Find and extract package details
    required_packages.each do |pkg|
      pattern = /^P:#{Regexp.escape(pkg)}(?:-[\w\.+~:]+)?$/
      matching_line = lines.find { |line| line.match?(pattern) }

      next unless matching_line

      present_packages << pkg
      # Extract full package name with version
      package_details[pkg] = matching_line.sub(/^P:/, '')
    end
  end

  # Display each required package with its installation details
  required_packages.each do |pkg|
    describe "Package: #{pkg}" do
      if present_packages.include?(pkg)
        it "INSTALLED: #{package_details[pkg]}" do
          expect(present_packages).to include(pkg)
        end
      else
        it 'NOT FOUND' do
          expect(present_packages).to include(pkg), "Package #{pkg} not found in installed DB"
        end
      end
    end
  end

  # Summary check
  describe 'Required OpenSSL FIPS packages summary' do
    it 'should have all required packages installed' do
      missing = required_packages - present_packages
      if missing.empty?
        details = present_packages.map { |p| package_details[p] }.join(', ')
        expect(present_packages.length).to eq(required_packages.length), "All #{required_packages.length} required packages installed: #{details}"
      else
        found_details = present_packages.any? ? present_packages.map { |p| package_details[p] }.join(', ') : 'none'
        expect(missing).to be_empty, "Missing #{missing.length} required package(s): #{missing.join(', ')}. Found: #{found_details}"
      end
    end
  end
end
