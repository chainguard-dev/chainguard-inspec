require 'spec_helper'
require 'tmpdir'
require_relative '../../../libraries/stig_mappings'

# Pure-Ruby unit tests for StigMappings (the XCCDF parser behind the HTML report
# generator). The focus is the rexml dependency: rexml is a *bundled* gem, not
# guaranteed on Ruby 3.4+, and the XCCDF enrichment it powers is optional — so
# StigMappings must degrade gracefully (still construct, empty mappings) rather
# than crash at load when rexml is unavailable.
RSpec.describe StigMappings do
  # Minimal XCCDF: one Group wrapping one Rule with a CCI and an OVAL check ref.
  # Uses the ns0: prefix exactly as the real ssg-chainguard-gpos-ds.xml does
  # (<ns0:Rule>, <ns0:title>, ...). A default-namespace style (xmlns=...) parses
  # on older rexml but NOT on newer rexml (matched the parser's prefix-mapped
  # `//ns0:Rule` XPath only on <= 3.2.x), so mirror the real document's prefixing.
  let(:xccdf_xml) do
    <<~XML
      <?xml version="1.0" encoding="UTF-8"?>
      <ns0:Benchmark xmlns:ns0="http://checklists.nist.gov/xccdf/1.2" id="test_benchmark">
        <ns0:Group id="xccdf_org.test_group_Open_Ssl">
          <ns0:Rule id="xccdf_mil.disa.stig_rule_SV-12345r1_rule" severity="high">
            <ns0:title>Example OpenSSL rule</ns0:title>
            <ns0:description>An example rule for the parser test.</ns0:description>
            <ns0:ident system="http://cyber.mil/cci">CCI-000366</ns0:ident>
            <ns0:check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
              <ns0:check-content-ref href="DetectOpenSslTest.xml" name="oval:org.OpenSsl:def:1"/>
            </ns0:check>
          </ns0:Rule>
        </ns0:Group>
      </ns0:Benchmark>
    XML
  end

  around do |example|
    Dir.mktmpdir do |dir|
      @xccdf_path = File.join(dir, 'bench.xml')
      File.write(@xccdf_path, xccdf_xml)
      example.run
    end
  end

  # rexml is optional (the whole point of this code) and not guaranteed in every
  # environment — notably it's absent under `bundle exec` here, since it's a
  # bundled gem not listed in test/Gemfile. The enrichment-present path can only
  # be exercised where rexml is actually loadable.
  def rexml_available?
    require 'rexml/document'
    true
  rescue LoadError
    false
  end

  context 'when rexml and an XCCDF file are present' do
    before { skip 'rexml is not loadable in this environment' unless rexml_available? }

    it 'parses rules and maps them to their OVAL check' do
      mappings = StigMappings.new(@xccdf_path)
      expect(mappings.total_mapped_rules).to be > 0
      expect(mappings.rules_for_check('DetectOpenSslTest')).not_to be_empty
      expect(mappings.all_rules).to have_key('xccdf_mil.disa.stig_rule_SV-12345r1_rule')
    end
  end

  context 'when the XCCDF file is absent' do
    it 'constructs with empty mappings (and never needs rexml)' do
      mappings = StigMappings.new(File.join(Dir.tmpdir, 'does-not-exist-xccdf.xml'))
      expect(mappings.all_rules).to be_empty
      expect(mappings.total_mapped_rules).to eq(0)
    end
  end

  context 'when rexml is unavailable (bundled gem missing on Ruby 3.4+)' do
    before do
      # Simulate `require 'rexml/document'` failing, as it does on a Ruby where
      # rexml is not installed / not in the Gemfile.
      allow_any_instance_of(described_class).to receive(:require)
        .with('rexml/document').and_raise(LoadError)
    end

    it 'degrades gracefully: warns, does not raise, and yields empty mappings' do
      mappings = nil
      expect { mappings = StigMappings.new(@xccdf_path) }
        .to output(/rexml gem not available/).to_stderr
      expect(mappings.all_rules).to be_empty
      expect(mappings.total_mapped_rules).to eq(0)
    end
  end
end
