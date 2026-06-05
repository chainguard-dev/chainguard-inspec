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

control 'oval:org.PackageSignature:def:1' do
  impact 0.5
  title 'Check /etc/apk/repositories for HTTPS'
  desc 'Ensure all repositories in /etc/apk/repositories use HTTPS.'

  # STIG Rule Mappings

  tag stig_rules: [

    'SV-203720r982212_rule'

  ]

  tag stig_severities: ['high']

  tag ccis: ['CCI-003992']

  rootfs = ENV['ROOTFS_DIR'] || input('rootfs')
  allowed_repos = Array(input('allowed_repositories') || [])
  repositories_path = File.join(rootfs, 'etc/apk/repositories')
  repositories_resource = file(repositories_path)

  # Repository allow-listing is host-anchored and fails closed; the URL/host
  # parsing and the equal-or-subdomain decision live in libraries/repo_matcher.rb
  # (unit-tested in test/spec/libraries/repo_matcher_spec.rb). Allowed entries
  # may be bare domains or full URLs; an empty list denies all repositories.
  allowed_domains = RepoMatcher.allowed_domains(allowed_repos)

  only_if 'An APK archive reference must exist' do
    repositories_resource.exist?
  end

  content = repositories_resource.content

  # Display full file contents
  describe "/etc/apk/repositories file contents (#{content.lines.count} lines)" do
    it "Full contents:\n#{content}" do
      expect(content.length).to be > 0
    end
  end

  repo_lines = content.split("\n").reject { |line| line.strip.empty? || line.strip.start_with?('#') }
  non_https = repo_lines.reject { |line| line.match?(%r{^https://}) }
  disallowed = repo_lines.reject { |line| RepoMatcher.allowed?(line, allowed_domains) }

  # Summary check
  describe 'APK repositories compliance summary' do
    it "should all use HTTPS protocol (#{repo_lines.length} total, #{repo_lines.length - non_https.length} HTTPS, #{non_https.length} non-HTTPS)" do
      expect(non_https).to be_empty
    end

    it 'should all use an approved repository host (equal to or a subdomain of an allowed domain)' do
      expect(disallowed).to be_empty,
        "Disallowed repositor#{disallowed.length == 1 ? 'y' : 'ies'} " \
        "(host is not an allowed domain or subdomain): #{disallowed.join(', ')}"
    end
  end
end
