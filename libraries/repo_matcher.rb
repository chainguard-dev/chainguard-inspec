# Copyright (c) 2026 Chainguard Inc.
# SPDX-License-Identifier: Apache-2.0
#
# libraries/repo_matcher.rb
#
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

# Helper for deciding whether an apk repository URL is from an approved
# repository, used by the PackageSignature control. The decision is
# host-anchored and fails closed:
#
#   - A repository is allowed iff its HOST equals, or is a subdomain of, one of
#     the allowed domains. Customer subdomains therefore need no enumeration.
#   - The host is extracted WITHOUT URL-decoding, so a percent-encoded path
#     separator (%2F) stays literal and cannot smuggle a different host past the
#     first '/'. Any host containing a character outside [a-z0-9.-] (e.g. a
#     literal '%') is rejected regardless of how apk/apko might later decode it.
#     (Non-blocking aside: this does not rely on apk/apko %-decoding behavior.)
#   - Scheme and path are NOT part of the decision; the PackageSignature control
#     enforces HTTPS via a separate assertion.
#
# Explicit top-level anchor: define the module as a constant on Object so it is
# visible from any InSpec evaluation context. This mirrors libraries/apk_db.rb
# and libraries/find_helper.rb.
module ::RepoMatcher

  # Characters permitted in a DNS host once extracted. A host containing
  # anything else (notably '%', '@', '/') is treated as untrusted.
  VALID_HOST = /\A[a-z0-9.-]+\z/.freeze

  # Remove userinfo credentials: https://token@domain/path -> https://domain/path
  # (also https://user:pass@domain/path). Note this strips through the LAST '@'
  # of the userinfo, so the real host is whatever follows it.
  def self.normalize_repo_url(url)
    url.to_s.sub(%r{^(https?://)([^@]+@)}, '\1')
  end

  # The lowercased host of a repo URL or bare domain: strip any userinfo
  # credentials and the scheme, then take everything up to the first *literal*
  # '/' or ':'. Not URL-decoded.
  def self.host(url)
    no_scheme = normalize_repo_url(url).sub(%r{^https?://}, '')
    no_scheme[%r{\A[^/:]*}].to_s.downcase
  end

  # Reduce a list of allowed entries (bare domains or full URLs) to their hosts,
  # dropping blanks. An empty result denies all repositories.
  def self.allowed_domains(entries)
    Array(entries).map { |entry| host(entry) }.reject(&:empty?)
  end

  # Whether repo_url's host equals, or is a subdomain of, one of allowed_domains
  # (already host-normalized). Fails closed on a non-DNS host.
  def self.allowed?(repo_url, allowed_domains)
    repo_host = host(repo_url)
    return false unless repo_host.match?(VALID_HOST)

    allowed_domains.any? { |domain| repo_host == domain || repo_host.end_with?(".#{domain}") }
  end
end
