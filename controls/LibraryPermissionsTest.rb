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

require 'shellwords'

control 'oval:org.LibraryPermissions:def:2' do
  impact 0.5
  title 'Check Library Permissions'
  desc 'Ensure all libraries in /usr/lib have root:root permissions.'

  # STIG Rule Mappings

  tag stig_rules: [

    'SV-203675r991560_rule',

    'SV-203716r982210_rule'

  ]

  tag stig_severities: ['medium']

  tag ccis: ['CCI-001499', 'CCI-003980']

  rootfs = ENV['ROOTFS_DIR'] || input('rootfs')
  lib_path = File.join(rootfs, 'usr/lib')
  lib_dir = directory(lib_path)

  describe lib_dir do
    it { should exist }
  end

  find_cmd = ::FindHelper.find_command(self)

  describe 'find utility availability' do
    it 'must be resolvable (real find or busybox with find applet)' do
      expect(find_cmd).not_to be_nil
    end
  end

  entries =
    if lib_dir.exist? && find_cmd
      command("#{find_cmd} #{Shellwords.escape(lib_path)} -type f -print0").stdout.split("\0").sort
    else
      []
    end

  # Provide evidence summary
  describe 'Library permissions scan of /usr/lib' do
    it "scanned #{entries.length} file(s) and director(ies)" do
      expect(entries.length).to be >= 0
    end
  end

  entries.each do |path|
    describe file(path) do
      it { should be_owned_by 'root' }
      it { should be_grouped_into 'root' }
    end
  end
end
