# frozen_string_literal: true

module Autotype
  class << self
    def configuration
      @configuration ||= Configuration.new
    end

    def configure
      yield(configuration) if block_given?
      configuration
    end

    def profile
      configure.load_profile
    end

    def reset_configuration!
      @configuration = nil
    end
  end

  class Configuration
    attr_accessor :config_path

    def initialize
      @config_path = ENV["AUTOTYPE_CONFIG"]
    end

    def skipped_files
      load_profile.skipped_files
    end

    def load_profile
      return @profile if defined?(@profile) && @profile

      path = config_path || DiscoveryProfile.find
      @profile = path ? DiscoveryProfile.load_overrides(path) : DiscoveryProfile.new
    end

    def reload_profile!
      remove_instance_variable(:@profile) if defined?(@profile)
      load_profile
    end
  end
end
