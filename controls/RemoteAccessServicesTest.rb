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

control 'oval:org.RemoteAccessServices:def:1' do
  impact 0.5
  title 'Check for installed Remote Access packages'
  desc 'Ensure that remote-access packages are not installed on the system.'

  # STIG Rule Mappings

  tag stig_rules: [

    'SV-263652r982557_rule',

    'SV-203736r958848_rule',

    'SV-203737r958850_rule',

    'SV-203653r958510_rule',

    'SV-203603r958408_rule',

    'SV-203669r991554_rule',

    'SV-203782r991591_rule',

    'SV-203597r958398_rule',

    'SV-203718r958796_rule',

    'SV-203738r958852_rule',

    'SV-203734r982217_rule',

    'SV-203735r958846_rule',

    'SV-203659r970703_rule',

    'SV-203723r1050789_rule',

    'SV-203727r982216_rule',

    'SV-203729r958818_rule',

    'SV-203728r958816_rule',

    'SV-203624r958452_rule',

    'SV-203622r958448_rule',

    'SV-203623r958450_rule',

    'SV-203683r958636_rule',

    'SV-203686r958672_rule',

    'SV-203687r958674_rule',

    'SV-203684r958638_rule',

    'SV-203685r958640_rule',

    'SV-203636r958472_rule',

    'SV-203744r958868_rule',

    'SV-203698r958736_rule',

    'SV-203598r958400_rule',

    'SV-203599r958402_rule',

    'SV-203596r958392_rule',

    'SV-203594r958388_rule',

    'SV-203595r958390_rule',

    'SV-203602r958406_rule',

    'SV-203600r982194_rule',

    'SV-203601r958404_rule',

    'SV-203665r958586_rule',

    'SV-203779r991588_rule',

    'SV-203771r991582_rule',

    'SV-203646r982206_rule',

    'SV-203644r982205_rule',

    'SV-203645r958494_rule',

    'SV-203642r982203_rule',

    'SV-203643r982204_rule',

    'SV-203640r958484_rule',

    'SV-203641r958486_rule'

  ]

  tag stig_severities: ['medium', 'high', 'low']

  tag ccis: [
    'CCI-004047', 'CCI-002890', 'CCI-003123', 'CCI-000877',
    'CCI-000068', 'CCI-001453', 'CCI-000366', 'CCI-000054',
    'CCI-001813', 'CCI-002891', 'CCI-004068', 'CCI-002884',
    'CCI-001133', 'CCI-002038', 'CCI-004046', 'CCI-001954',
    'CCI-001953', 'CCI-000187', 'CCI-000185', 'CCI-000186',
    'CCI-002361', 'CCI-002314', 'CCI-002322', 'CCI-002363',
    'CCI-002364', 'CCI-000213', 'CCI-002470', 'CCI-002238',
    'CCI-000056', 'CCI-000057', 'CCI-000050', 'CCI-000044',
    'CCI-000048', 'CCI-000067', 'CCI-000060', 'CCI-001384',
    'CCI-000172', 'CCI-001941', 'CCI-004045', 'CCI-000765',
    'CCI-000766'
  ]

  rootfs = ENV['ROOTFS_DIR'] || input('rootfs')
  installed_db_path = File.join(rootfs, 'usr/lib/apk/db/installed')
  installed_db = file(installed_db_path)

  describe installed_db do
    it { should exist }
  end

  banned_packages = Array(input('banned_remote_packages') || [])

  # Flag a banned name and its version-stream variants (openssh -> openssh-9.7)
  # but NOT a separate subpackage (openssh-keygen) unless that subpackage is
  # itself listed. The digit-led-suffix discrimination lives in the ApkDb
  # helper (libraries/apk_db.rb).
  db_content = ApkDb.installed_db_content(self, installed_db_path)
  present_packages = banned_packages.select { |pkg| ApkDb.package_present?(db_content, pkg) }

  describe 'Remote access packages' do
    it 'should not have any banned remote access packages installed' do
      if present_packages.empty?
        evidence = "No remote access packages found. Scanned #{banned_packages.length} banned packages: #{banned_packages.first(5).join(', ')}#{banned_packages.length > 5 ? '...' : ''}"
      else
        evidence = "Found #{present_packages.length} banned remote access package(s): #{present_packages.join(', ')}"
      end
      expect(present_packages).to be_empty, evidence
    end
  end
end
