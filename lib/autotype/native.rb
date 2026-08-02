# frozen_string_literal: true

module AutotypeNative
  class << self
    def available?
      load_extension!
      const_get(:Solver)
      true
    rescue LoadError, StandardError
      false
    end

    def load_extension!
      return if @extension_loaded

      ext_dir = File.expand_path("../../ext/autotype", __dir__)
      bundle = File.join(ext_dir, "autotype.#{RbConfig::CONFIG['DLEXT']}")
      native_sources = Dir[File.expand_path("../../native/autotype/src/*.c", __dir__)]
      extension_source = File.join(ext_dir, "autotype.c")
      sources = native_sources + [extension_source]

      stale =
        !File.exist?(bundle) ||
        sources.any? { |source| File.exist?(source) && File.mtime(source) > File.mtime(bundle) }

      if stale
        Dir.chdir(ext_dir) { system("ruby extconf.rb && make", exception: true) }
      end

      require bundle
      @extension_loaded = true
    end
  end
end
