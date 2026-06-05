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

control 'oval:org.NoUsers:def:1' do
  impact 0.5
  title 'Check for Unauthorized Users'
  desc "Ensure there are no unauthorized users in /etc/passwd or /etc/shadow after the 'nobody' account."


  # STIG Rule Mappings

  tag stig_rules: [

    'SV-263650r982553_rule',

    'SV-203695r958726_rule',

    'SV-203781r991590_rule',

    'SV-203650r958504_rule',

    'SV-203652r958508_rule',

    'SV-203655r958514_rule',

    'SV-203725r1050791_rule',

    'SV-203724r1050790_rule',

    'SV-203680r991565_rule',

    'SV-203681r991566_rule',

    'SV-203639r958482_rule',

    'SV-203696r958730_rule',

    'SV-203692r958702_rule',

    'SV-203592r958364_rule',

    'SV-203591r958362_rule',

    'SV-203783r991592_rule',

    'SV-203610r958422_rule',

    'SV-203648r982189_rule'

  ]

  tag stig_severities: ['medium', 'high']

  tag ccis: [
    'CCI-003628', 'CCI-002235', 'CCI-000366', 'CCI-000804',
    'CCI-001682', 'CCI-001082', 'CCI-002038', 'CCI-000015',
    'CCI-000764', 'CCI-002233', 'CCI-002165', 'CCI-000016',
    'CCI-000135', 'CCI-003627'
  ]

  allowed_usernames = input('allowed_extra_users')
  allowed_shells = %w[/sbin/nologin /usr/sbin/nologin /bin/false]

  rootfs = ENV['ROOTFS_DIR'] || input('rootfs')
  shadow_path = File.join(rootfs, 'etc/shadow')
  passwd_path = File.join(rootfs, 'etc/passwd')
  apko_path = File.join(rootfs, 'etc/apko.json')

  shadow_resource = file(shadow_path)
  passwd_resource = file(passwd_path)
  apko_resource = file(apko_path)

  describe shadow_resource do
    it { should exist }
  end

  describe passwd_resource do
    it { should exist }
    its('content') { should_not be_empty }
  end

  # look up username in apko image configuration json
  # returns uid of user as a string if found, nil if not
  def find_uid_by_username(data, username)
    users = data.dig('accounts', 'users')
    user = users&.find { |u| u['username'] == username }
    user&.dig('uid')&.to_s
  end

  passwd_lines = passwd_resource.content.split("\n")

  # Structural validity of /etc/passwd: every non-blank entry must have exactly
  # 7 colon-separated fields. A malformed (e.g. truncated) line means we cannot
  # reliably evaluate account correctness — a crafted short line such as
  # "evil:x:0:0" must not silently evade the unauthorized-account check below.
  # split(':', -1) preserves trailing empty fields so a legitimately empty shell
  # ("svc:x:1:1:svc:/home/svc:") still counts as 7 fields, not 6.
  malformed_passwd_entries = passwd_lines.reject { |line| line.strip.empty? }
                                         .reject { |line| line.split(':', -1).length == 7 }

  describe 'Structural validity of /etc/passwd' do
    it 'every entry has exactly 7 colon-separated fields' do
      evidence = malformed_passwd_entries.map(&:inspect).join(', ')
      expect(malformed_passwd_entries).to be_empty,
        "Malformed /etc/passwd entr#{malformed_passwd_entries.length == 1 ? 'y' : 'ies'} " \
        "(expected 7 colon-separated fields): #{evidence}"
    end
  end

  # Find nobody in passwd file
  nobody_index = passwd_lines.index { |line| line.start_with?('nobody:') }
  describe 'Passwd file contains nobody entry' do
    it 'should include the nobody account' do
      expect(nobody_index).not_to be_nil
    end
  end

  # Get all accounts after nobody from /etc/passwd
  accounts_after_nobody = if nobody_index
                            passwd_lines[(nobody_index + 1)..-1].reject { |line| line.strip.empty? }
                          else
                            []
                          end

  account_details = accounts_after_nobody.map do |entry|
    parts = entry.split(':')

    next unless parts.length >= 7

    {
      username: parts[0],
      uid: parts[2],
      gid: parts[3],
      shell: parts[6],
      raw: entry
    }
  end.compact

  allowed_accounts = account_details.select do |acct|
    if apko_resource.exist?
      apko_uid = find_uid_by_username(apko_resource.content_as_json, acct[:username])
      (apko_uid && apko_uid == acct[:uid]) || allowed_shells.include?(acct[:shell])
    else
      allowed_usernames.include?(acct[:username]) || allowed_shells.include?(acct[:shell])
    end
  end

  unauthorized_accounts = account_details.reject do |acct|
    allowed_accounts.include?(acct)
  end

  # List all accounts found after nobody with their compliance status
  if account_details.empty?
    describe 'Accounts after nobody in /etc/passwd' do
      it 'should have no accounts after nobody (distroless baseline)' do
        expect(account_details.length).to eq 0
      end
    end
  else
    # Output all users with their status
    account_details.each do |acct|
      is_allowed = if apko_resource.exist?
                     apko_uid = find_uid_by_username(apko_resource.content_as_json, acct[:username])
                     (apko_uid && apko_uid == acct[:uid]) || allowed_shells.include?(acct[:shell])
                   else
                     allowed_usernames.include?(acct[:username]) || allowed_shells.include?(acct[:shell])
                   end
      shell_display = acct[:shell] || 'no shell set'
      uid_display = acct[:uid] || 'unknown'

      describe "User: #{acct[:username]} (UID: #{uid_display})" do
        it "status: #{is_allowed ? 'ALLOWED' : 'UNAUTHORIZED'} (shell: #{shell_display})" do
          if is_allowed
            # Pass for allowed accounts
            expect(true).to eq true
          else
            # Fail for unauthorized accounts
            fail_msg = "Unauthorized user '#{acct[:username]}' (UID: #{uid_display}) with shell '#{shell_display}' found after nobody in /etc/passwd. "
            fail_msg += "Must use allowed shell (#{allowed_shells.join(', ')}) or be in allowed list: #{allowed_usernames.join(', ')}"
            expect(false).to eq(true), fail_msg
          end
        end
      end
    end
  end

  # Summary check
  describe 'User account compliance summary' do
    it "should have no unauthorized accounts (Found: #{account_details.length} total, #{allowed_accounts.length} allowed, #{unauthorized_accounts.length} unauthorized)" do
      if unauthorized_accounts.empty?
        evidence = 'All accounts are compliant. '
        if account_details.any?
          evidence += 'Users found after nobody: ' + account_details.map { |a| "#{a[:username]} (UID:#{a[:uid]}, shell:#{a[:shell]})" }.join(', ')
        else
          evidence += 'No accounts found after nobody (distroless baseline).'
        end
      else
        evidence = "Found #{unauthorized_accounts.length} unauthorized account(s): "
        evidence += unauthorized_accounts.map { |a| "#{a[:username]} (UID:#{a[:uid]}, shell:#{a[:shell]})" }.join(', ')
      end
      expect(unauthorized_accounts).to be_empty, evidence
    end
  end
end
