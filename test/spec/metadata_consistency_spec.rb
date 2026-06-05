require 'spec_helper'

# Static consistency check of STIG tag metadata across all controls.
#
# Every control in this profile is expected to declare the same canonical set
# of `tag` keys so the XCCDF/HTML report generator and downstream tooling can
# rely on them being present and consistently named. This spec reads the
# control source files directly (no cinc-auditor / Docker needed) so it runs
# fast and is not subject to a control being skipped at evaluation time.
#
# It guards against two failure modes:
#   1. A control missing one of the canonical tag keys (drift / omission).
#   2. A control using an unrecognized tag key — e.g. a typo such as
#      `stig_priorities` instead of `stig_severities`.
RSpec.describe 'control tag-metadata consistency' do
  controls_dir = File.expand_path('../../controls', __dir__)
  canonical_tags = %w[stig_rules stig_severities ccis]
  control_files = Dir.glob(File.join(controls_dir, '*.rb')).sort

  it 'finds control files to check' do
    expect(control_files).not_to be_empty
  end

  # Extract the declared `tag <key>:` keys from a control source file.
  def declared_tag_keys(path)
    File.readlines(path).filter_map do |line|
      m = line.match(/^\s*tag\s+([a-z_]+):/)
      m && m[1]
    end
  end

  control_files.each do |path|
    name = File.basename(path)

    context "controls/#{name}" do
      it "declares all canonical tag keys (#{canonical_tags.join(', ')})" do
        missing = canonical_tags - declared_tag_keys(path)
        expect(missing).to be_empty,
          "controls/#{name} is missing canonical tag key(s): #{missing.join(', ')}"
      end

      it 'declares no unrecognized tag keys' do
        unrecognized = declared_tag_keys(path).uniq - canonical_tags
        expect(unrecognized).to be_empty,
          "controls/#{name} declares unrecognized tag key(s): #{unrecognized.join(', ')} " \
          "(expected only: #{canonical_tags.join(', ')})"
      end
    end
  end
end
