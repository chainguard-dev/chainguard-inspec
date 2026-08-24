require 'spec_helper'
require 'yaml'

# Static guard on the banned_remote_packages default.
#
# The banned set must match oval:org.RemoteAccessServices:obj:6 in
# chainguard-dev/stigs. That datastream is not vendored here (see
# libraries/stig_mappings.rb, which treats benchmarks/ as optional), so this
# spec cannot diff against the OVAL directly. Instead it pins the expected list
# as a literal: any change to the default must also change this spec, which
# makes drift a deliberate, reviewable edit rather than a silent one.
#
# When syncing to a new XCCDF release, update the `expected` list below from the
# OVAL pattern, update the commented example in examples/inputs.yml to match,
# and record the release in the comment below.
#
# Source: XCCDF 3.2.16, oval:org.RemoteAccessServices:obj:6.
# Deliberately absent: openssh-client (un-banned upstream in stigs 2e346ee;
# FIPS ssh_config policy governs the client instead of a package ban).
RSpec.describe 'banned_remote_packages default' do
  # Local variables rather than constants, mirroring
  # metadata_consistency_spec.rb's `canonical_tags`: a constant assigned inside
  # a describe block leaks into the global namespace for the whole suite and
  # warns on reload. Locals are visible inside `it` blocks via closure.
  expected = %w[
    openssh
    openssh-server
    openssh-sftp-server
    dropbear
    tigervnc
    tigervnc-server
    tigervnc-viewer
    xrdp
    xorgxrdp
    vsftpd
    proftpd
    webmin
    cockpit
    cockpit-ws
    cockpit-bridge
    nfs-utils
    samba
    samba-server
    samba-client
    samba-common
    rsh
    telnet
  ].freeze

  inspec_yml_path = File.expand_path('../../inspec.yml', __dir__)
  declared = YAML.safe_load(File.read(inspec_yml_path))
                 .fetch('inputs')
                 .find { |i| i['name'] == 'banned_remote_packages' }
  actual = declared ? Array(declared['value']) : []

  it 'declares a banned_remote_packages input' do
    expect(declared).not_to be_nil,
      "no banned_remote_packages input found in #{inspec_yml_path}"
  end

  it 'matches the OVAL banned set exactly, in OVAL order' do
    expect(actual).to eq(expected),
      "banned_remote_packages drifted from oval:org.RemoteAccessServices:obj:6.\n" \
      "missing (in OVAL, not in inspec.yml): #{(expected - actual).inspect}\n" \
      "extra   (in inspec.yml, not in OVAL): #{(actual - expected).inspect}\n" \
      "got:  #{actual.inspect}\n" \
      "want: #{expected.inspect}"
  end

  it 'does not ban openssh-client' do
    expect(actual).not_to include('openssh-client'),
      'openssh-client was un-banned upstream in stigs 2e346ee; banning it here ' \
      'reports a finding oscap does not. FIPS ssh_config policy governs the ' \
      'client instead; those checks are not yet implemented in this profile.'
  end

  it 'still bans the openssh server-side packages' do
    expect(actual).to include('openssh', 'openssh-server', 'openssh-sftp-server')
  end

  it 'is reproduced verbatim in examples/inputs.yml' do
    example = File.read(File.expand_path('../../examples/inputs.yml', __dir__))
    commented = example.scan(/^#   - ([a-z0-9-]+)/).flatten - ['myforbiddenpkg']
    expect(commented).to eq(actual),
      "examples/inputs.yml drifted from the inspec.yml default.\n" \
      "in inspec.yml, missing from the example: #{(actual - commented).inspect}\n" \
      "in the example, not in inspec.yml: #{(commented - actual).inspect}\n" \
      "example: #{commented.inspect}\n" \
      "default: #{actual.inspect}"
  end
end
