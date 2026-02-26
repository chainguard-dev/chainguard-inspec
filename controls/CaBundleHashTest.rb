# Copyright (c) 2025 Cisco Systems, Inc. and/or its affiliates
# Copyright (c) 2026 Chainguard
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

control 'oval:org.CABundleHash:def:1' do
  impact 0.5
  title 'Validate SHA-256 hash of CA bundle'
  desc 'Ensure the CA bundle exists and matches the expected SHA-256 hash.'

  # STIG rule mappings

  tag stig_rules: [
    'SV-263659r982563_rule'
  ]

  tag stig_priorities: ['medium']

  tag ccis: ['CCI-004909']

  expected_hash = input('expected_cacert_hash')
  rootfs = ENV['ROOTFS_DIR'] || input('rootfs')
  bundle_path = File.join(rootfs, 'etc/ssl/certs/ca-certificates.crt')

  bundle_file = file(bundle_path)

  describe bundle_file do
    it { should exist }
    it { should be_file }
    its('sha256sum') { should eq expected_hash }
  end
end
