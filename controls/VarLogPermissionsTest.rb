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

control 'oval:org.varlog:def:2' do
  impact 0.5
  title 'Check Var/Log Permissions'
  desc 'Ensure /var/log has root:root permissions.'

  # STIG Rule Mappings

  tag stig_rules: [
    'SV-203664r958566_rule',
    'SV-203617r958436_rule',
    'SV-203616r958434_rule'
  ]

  tag stig_severities: ['medium']

  tag ccis: ['CCI-001314', 'CCI-000163', 'CCI-000162']

  rootfs = ENV['ROOTFS_DIR'] || input('rootfs')
  var_log_path = File.join(rootfs, 'var/log')
  var_log = directory(var_log_path)

  describe var_log do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    its('mode') { should cmp '0755' }
  end
end
