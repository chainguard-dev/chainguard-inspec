# Copyright (c) 2026 Chainguard Inc.
# SPDX-License-Identifier: Apache-2.0
#
# libraries/apk_db.rb
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

# Helper for matching package names against the apk installed database
# (`/usr/lib/apk/db/installed`). Centralizes the `P:`-line matching used by
# the banned- and required-package controls.
#
# Version streams (the non-obvious bit):
#   Chainguard/Wolfi ships parallel supported upstream branches as separate
#   *named* packages with a version suffix, e.g. `openssl-3.0` / `openssl-3.1`,
#   `python-3.12`, LTS kernels `linux-6.12` / `linux-6.18`. The `P:` line is the
#   package *name* (the version itself is the separate `V:` line), so a stream's
#   `P:` carries the version suffix. A check for `openssl` must therefore also
#   match `openssl-3.1`.
#
#   But it must NOT match a *separate subpackage* such as `openssl-dev` or
#   `openssh-keygen` — those are distinct packages, and banning `openssh` should
#   not implicitly ban `openssh-keygen`. The discriminator is the suffix's first
#   character: a digit-led suffix (`-3.1`, `-9.7`) is a version stream and
#   matches; a word-led suffix (`-dev`, `-keygen`, `-server`) is a subpackage and
#   does not match unless that subpackage name is listed explicitly (it then
#   matches via its own exact entry).
#
# Explicit top-level anchor: define the module as a constant on Object so it is
# visible from any InSpec evaluation context (ProfileContext, ControlEvalContext,
# etc.) rather than being scoped to whichever anonymous class instance_eval'd
# this file. This mirrors libraries/find_helper.rb.
module ::ApkDb

  # Regexp matching the `P:` line for `pkg`, accepting a version-stream suffix
  # (digit-led) but rejecting separate (word-led) subpackages.
  #
  #   openssh        -> matches  P:openssh, P:openssh-9.7
  #                     rejects  P:openssh-keygen, P:opensshd
  #   openssl        -> matches  P:openssl, P:openssl-3.1
  #                     rejects  P:openssl-dev
  #   python-3.12    -> matches  P:python-3.12
  #                     rejects  P:python-3.12-dev
  def self.package_line_pattern(pkg)
    /^P:#{Regexp.escape(pkg)}(?:-\d[\w.+~]*)?$/
  end

  # Given installed-db content (a String) and a package name, return the full
  # matched package name (the `P:` line value, version suffix included) for use
  # as audit evidence, or nil when the package (or a version-stream variant) is
  # not present. Never raises.
  def self.matched_package_name(content, pkg)
    pattern = package_line_pattern(pkg)
    line = content.to_s.split("\n").find { |l| l.match?(pattern) }
    line&.sub(/^P:/, '')
  end

  # Whether `pkg` (or a version-stream variant of it) is present in the
  # installed-db content. Never raises.
  def self.package_present?(content, pkg)
    !matched_package_name(content, pkg).nil?
  end

  # Read the installed-db at `path` through the transport-safe InSpec `file`
  # resource (pass `self` from within a control as `context`) and return its
  # content, or '' when the file is absent. Returning data rather than raising
  # keeps callers simple and matches the find_helper idiom.
  def self.installed_db_content(context, path)
    resource = context.file(path)
    resource.exist? ? resource.content.to_s : ''
  end
end
