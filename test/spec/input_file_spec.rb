require 'spec_helper'
require 'tmpdir'
require 'fileutils'

# Dogfood the shipped examples/inputs.yml through the production --input-file
# override mechanism. This proves two things at once:
#   1. The shipped example file is valid and InSpec accepts it as an input file.
#   2. A value defined ONLY in the file (not in inspec.yml) reaches the control.
#
# examples/inputs.yml lists `myappuser` in allowed_extra_users, which is NOT in
# the inspec.yml default (_apt/messagebus/nonroot). So a fixture placing an
# interactive `myappuser` after nobody fails under the defaults and passes only
# when the file's allow-list is applied — isolating the input-file mechanism.
# (This is the control-spec-level override test that issue #56 says belongs
# here; the docker-transport *script* fix is #56 itself.)
RSpec.describe 'examples/inputs.yml (--input-file dogfood)' do
  let(:rootfs) { Dir.mktmpdir }
  let(:etc_dir) { File.join(rootfs, 'etc') }
  let(:example_inputs) { File.join(InspecRunner::REPO_ROOT, 'examples', 'inputs.yml') }

  before do
    FileUtils.mkdir_p(etc_dir)
    File.write(File.join(etc_dir, 'passwd'), <<~PASSWD)
      root:x:0:0:root:/root:/sbin/nologin
      nobody:x:65534:65534:nobody:/:/sbin/nologin
      myappuser:x:1000:1000:App User:/home/myappuser:/bin/bash
    PASSWD
    File.write(File.join(etc_dir, 'shadow'), <<~SHADOW)
      root:!:19000:0:99999:7:::
      nobody:!:19000:0:99999:7:::
      myappuser:!:19000:0:99999:7:::
    SHADOW
  end

  after { FileUtils.rm_rf(rootfs) }

  it 'exists as a shipped artifact' do
    expect(File).to exist(example_inputs)
  end

  it 'fails without the input file (myappuser not in the inspec.yml default)' do
    expect(run_control('oval:org.NoUsers:def:1', rootfs: rootfs)).to be_failing
  end

  it 'passes when examples/inputs.yml supplies allowed_extra_users' do
    result = run_control('oval:org.NoUsers:def:1', rootfs: rootfs, input_file: example_inputs)
    expect(result).to be_passing
  end

  # Precedence: an inline --input on the command line overrides the same key from
  # an --input-file. Here the file admits myappuser (would pass) but an empty CLI
  # --input allowed_extra_users wins, so myappuser is unauthorized and the control
  # fails. This documents/guards the precedence noted in examples/inputs.yml:
  #   --input key=value  >  --input-file  >  inspec.yml default.
  it 'lets an inline --input override the same key from the input file' do
    result = run_control('oval:org.NoUsers:def:1', rootfs: rootfs,
                         input_file: example_inputs, allowed_extra_users: '[]')
    expect(result).to be_failing
  end
end
