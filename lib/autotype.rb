# frozen_string_literal: true

require_relative "autotype/version"
require_relative "autotype/type_string"
require_relative "autotype/profile"
require_relative "autotype/discovery_profile"
require_relative "autotype/engine"
require_relative "autotype/analysis"

module Autotype
  class << self
    def run(argv = ARGV)
      CLI.run(argv)
    end
  end
end
