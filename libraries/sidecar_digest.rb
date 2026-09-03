# Copyright (c) 2026 Chainguard Inc.
# SPDX-License-Identifier: Apache-2.0
#
# libraries/sidecar_digest.rb
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

# Reads an apko trust-store sidecar: one sha256sum-format line recording the
# digest of the file it sits beside.
#
# apko writes these at image build time (pkg/build/certificates.go), after
# assembling the final rootfs — so a sidecar describes the shipped artefact
# including any merged trust anchors. No package owns one; `apk info -W` on a
# sidecar reports "Could not find owner package".
#
# This is drift detection, not tamper evidence: whoever can rewrite the file
# can rewrite the sidecar beside it. What it catches is a file changed after
# the image was built.
#
# Explicit top-level anchor so the constant is visible from any InSpec
# evaluation context, matching FindHelper.
module ::SidecarDigest
  # Outcome of reading one sidecar. Exactly one of #digest / #detail is set:
  # #digest is the single recorded digest, lowercased; #detail says why no
  # single digest could be read, phrased for a control's failure message.
  Result = Struct.new(:digest, :detail) do
    def resolved?
      !digest.nil?
    end
  end

  # The OVAL matches each sidecar with `^([0-9a-fA-F]{64})[ \t]+\*?<basename>$`
  # — see oval:org.CABundleHash:obj:4 and :obj:6. The optional asterisk is
  # sha256sum's binary-mode marker. Regexp.escape because the basename is
  # interpolated: a dot in "ca-certificates.crt" must not match any character.
  def self.pattern(basename)
    /^([0-9a-fA-F]{64})[ \t]+\*?#{Regexp.escape(basename)}$/
  end

  # context is the InSpec control context (pass `self` from a control) so
  # file() resolves against the scan target rather than the scanner's host.
  def self.resolve(context, sidecar_path, basename)
    sidecar = context.file(sidecar_path)
    # The literal phrase "file does not exist" is load-bearing: it's the
    # contiguous substring test/spec/controls/ca_bundle_hash_spec.rb pins the
    # missing-stamp failure to, and that spec cannot be edited. Don't rephrase
    # this away without checking it.
    return Result.new(nil, "#{sidecar_path}: file does not exist") unless sidecar.exist?

    content = sidecar.content
    if content.nil?
      reason = sidecar.file? ? 'not readable' : 'not a regular file'
      return Result.new(nil, "#{sidecar_path} is #{reason}")
    end

    # .scrub because a sidecar is adversary-influenceable in exactly the
    # scenario this check exists for, and non-UTF8 bytes would otherwise raise
    # ArgumentError from the match — at control-body scope that turns the whole
    # control into a code error and discards every other assertion. A clean
    # finding is strictly better.
    #
    # Downcased for the case-insensitive comparison the OVAL states specify
    # (operation="case insensitive equals").
    digests = content.to_s.scrub.lines.filter_map { |l| l[pattern(basename), 1] }.map(&:downcase)

    case digests.length
    when 1 then Result.new(digests.first, nil)
    when 0 then Result.new(nil, "#{sidecar_path} has no line matching #{pattern(basename).source}")
    else
      # instance=1 on the OVAL objects restricts collection to the first match,
      # so only_one_exists cannot actually fail on duplicates upstream. We fail
      # closed regardless: no packaging path emits duplicate lines, and
      # silently trusting the first is the worse default. Deliberate
      # divergence — do not "fix" it to match only_one_exists literally when
      # syncing a future datastream release.
      Result.new(nil, "#{sidecar_path} records #{digests.length} digest lines: #{digests.inspect}")
    end
  end
end
