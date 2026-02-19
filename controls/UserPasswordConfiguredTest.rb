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

control 'oval:org.example:def:3' do
  impact 0.5
  title 'Check for Hashed Passwords in /etc/shadow'
  desc 'Ensure there are hashed passwords in the /etc/shadow file.'

  # STIG Rule Mappings (13 rules)

  tag stig_rules: [

    'SV-203629r982199_rule',

    'SV-203630r987796_rule',

    'SV-203733r958828_rule',

    'SV-203628r982198_rule',

    'SV-203625r982195_rule',

    'SV-203626r982196_rule',

    'SV-203627r982197_rule',

    'SV-203635r958470_rule',

    'SV-203634r982202_rule',

    'SV-203632r1038967_rule',

    'SV-203631r982188_rule',

    'SV-203676r991561_rule',

    'SV-203778r991587_rule'

  ]

  tag stig_severities: ['high', 'medium']

  tag ccis: ['CCI-004062', 'CCI-000197', 'CCI-002007', 'CCI-004066', 'CCI-000206', 'CCI-000366']

  rootfs = ENV['ROOTFS_DIR'] || input('rootfs')
  shadow_path = File.join(rootfs, 'etc/shadow')
  shadow_resource = shadow(shadow_path)

  describe shadow_resource do
    it { should exist }
  end

# distroless baseline is that no accounts should have valid passwords
  describe shadow_resource.where { password !~ /^[!*]+$/ } do
    its('count') { should eq 0 }
    # if the count test fails, this test outputs the users that are causing the failure.
    its('users') { should be_empty }
  end
end
