require 'shellwords'
require_relative 'support/inspec_runner'
require_relative 'support/fixture_helpers'
require_relative 'support/scan_smoke'

RSpec.configure do |config|
  config.include InspecHelpers
  config.include FixtureHelpers
  config.include ScanSmokeHelpers

  # Use expect syntax only
  config.expect_with :rspec do |expectations|
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
  end

  config.mock_with :rspec do |mocks|
    mocks.verify_partial_doubles = true
  end

  config.shared_context_metadata_behavior = :apply_to_host_groups

  # Run specs in random order to surface order dependencies
  config.order = :random
  Kernel.srand config.seed
end
