require 'spec_helper'
require 'tmpdir'
require 'fileutils'

RSpec.describe 'oval:org.example:def:3' do
  let(:rootfs) { Dir.mktmpdir }
  let(:shadow_dir) { File.join(rootfs, 'etc') }
  let(:shadow_path) { File.join(shadow_dir, 'shadow') }

  before { FileUtils.mkdir_p(shadow_dir) }
  after { FileUtils.rm_rf(rootfs) }

  context 'when all shadow entries have locked passwords (! or *)' do
    before do
      File.write(shadow_path, <<~SHADOW)
        root:!:19000:0:99999:7:::
        daemon:*:18000:0:99999:7:::
        nobody:!:18000:0:99999:7:::
      SHADOW
    end

    it 'passes' do
      expect(run_control('oval:org.example:def:3', rootfs: rootfs)).to be_passing
    end
  end

  context 'when an account has a real password hash' do
    before do
      # $6$ prefix indicates SHA-512 crypt — a real password hash
      File.write(shadow_path, <<~SHADOW)
        root:$6$salt$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:19000:0:99999:7:::
        daemon:*:18000:0:99999:7:::
        nobody:!:18000:0:99999:7:::
      SHADOW
    end

    it 'fails' do
      expect(run_control('oval:org.example:def:3', rootfs: rootfs)).to be_failing
    end
  end

  # An empty password field ("") means no password is set, which is distinct
  # from a locked account (! or *). The control selects entries where
  # password !~ /^[!*]+$/; an empty field does not match, so it is flagged.
  # emptyacct has the correct 9 fields, so the A4 malformed-count check does not
  # pre-empt it — the failure comes from the empty-password detection itself.
  context 'when an account has an empty password field (no password set)' do
    before do
      File.write(shadow_path, <<~SHADOW)
        root:!:19000:0:99999:7:::
        emptyacct::19000:0:99999:7:::
        nobody:!:18000:0:99999:7:::
      SHADOW
    end

    it 'fails' do
      expect(run_control('oval:org.example:def:3', rootfs: rootfs)).to be_failing
    end
  end

  # /etc/shadow absent: by design this control is a pure password-content check
  # and does NOT require the file to exist — matching the upstream SCAP rules,
  # which use check_existence="none_exist" (Chainguard SSG oval:org.example:def:3
  # and ComplianceAsCode no_empty_passwords_etc_shadow), so an absent /etc/shadow
  # scores compliant (no passwords to check; verified with oscap). NoUsersCheck
  # owns the /etc/shadow existence requirement. Documented so a future change
  # that either silently stops the content check or wrongly adds an existence
  # requirement here is visible as an intentional vs accidental behavior change.
  context 'when /etc/shadow is absent' do
    it "passes (existence is NoUsersCheck's responsibility, not this content check)" do
      expect(run_control('oval:org.example:def:3', rootfs: rootfs)).to be_passing
    end
  end

  # A structurally malformed /etc/shadow entry (wrong field count) must be a
  # failing finding. The InSpec `shadow` resource does its own parsing and may
  # silently skip such lines, so a malformed entry could otherwise evade the
  # password-hash check entirely — we cannot assert password correctness against
  # an unparseable file. Standard shadow = 9 colon-separated fields.
  context 'when /etc/shadow has a structurally malformed (truncated) entry' do
    before do
      # All passwords locked, but one line is truncated to 3 fields.
      File.write(shadow_path, <<~SHADOW)
        root:!:19000:0:99999:7:::
        truncated:!:19000
        nobody:!:18000:0:99999:7:::
      SHADOW
    end

    it 'fails (cannot assert password correctness against a malformed entry)' do
      expect(run_control('oval:org.example:def:3', rootfs: rootfs)).to be_failing
    end
  end

  # A valid entry whose trailing fields are legitimately empty still has 9
  # colon-separated fields and must NOT be flagged as malformed (guards against
  # naive String#split dropping trailing empty fields).
  context 'when a shadow entry has empty trailing fields but the right field count' do
    before do
      File.write(shadow_path, <<~SHADOW)
        root:!:19000:0:99999:7:::
        nobody:*:::::::
      SHADOW
    end

    it 'passes' do
      expect(run_control('oval:org.example:def:3', rootfs: rootfs)).to be_passing
    end
  end
end
