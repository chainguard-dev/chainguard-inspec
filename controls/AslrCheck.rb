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

control 'aslr-runtime-check' do
  impact 0.5
  title 'ASLR must be enabled'
  desc 'Verify that kernel.randomize_va_space equals 2 to ensure full Address Space Layout Randomization is enabled.'

  # STIG Rule Mappings (2 rules)
  tag stig_rules: [
    'SV-203754r958928_rule',
    'SV-203753r958928_rule'
  ]
  tag stig_severities: ['medium']
  tag ccis: ['CCI-002824']

  rootfs = ENV['ROOTFS_DIR'] || input('rootfs')
  sysctl_path = File.join(rootfs, 'proc/sys/kernel/randomize_va_space')
  runtime_capture_path = File.join(rootfs, '.runtime_capture', 'aslr_setting')

  only_if('Runtime ASLR setting must have been captured during scan') do
    file(sysctl_path).exist? or file(runtime_capture_path).exist?
  end

  aslr_path =
    if file(sysctl_path).exist?
      sysctl_path
    elsif file(runtime_capture_path).exist?
      runtime_capture_path
    end

  aslr_value = file(aslr_path).content.strip

  # Provide evidence summary
  describe 'ASLR kernel.randomize_va_space origin' do
    it "examined the contents of #{aslr_path}" do
      expect(aslr_path.length).to be > 0
    end
  end

  describe 'ASLR setting (kernel.randomize_va_space)' do
    it 'should be set to 2 (full randomization)' do
      if aslr_value == '2'
        expect(aslr_value).to cmp('2'), "ASLR fully enabled: kernel.randomize_va_space = #{aslr_value}"
      else
        expect(aslr_value).to cmp('2'), "ASLR not fully enabled: kernel.randomize_va_space = #{aslr_value} (expected: 2)"
      end
    end
  end
end
