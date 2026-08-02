# frozen_string_literal: true

require_relative "lib/autotype/version"

Gem::Specification.new do |spec|
  spec.name = "autotype"
  spec.version = Autotype::VERSION
  spec.authors = ["Doximity"]
  spec.email = ["engineering@doximity.com"]

  spec.summary = "Syntax-less Ruby type inference from method usage"
  spec.description = "Infers Ruby method signatures from Prism AST analysis and fixed-point constraint solving."
  spec.homepage = "https://github.com/doximity/autotype"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage

  spec.files = Dir.chdir(__dir__) do
    Dir.glob("{exe,ext,lib,native,spec}/**/*", File::FNM_DOTMATCH).select do |path|
      File.file?(path) &&
        !path.end_with?(".o", ".bundle", ".so", ".dylib", "stc_solve", "/.DS_Store") &&
        !path.include?("/.git/")
    end + %w[README.md LICENSE autotype.gemspec Gemfile Rakefile autotype.example.yml .rspec]
  end
  spec.bindir = "exe"
  spec.executables = ["autotype"]
  spec.require_paths = ["lib"]
  spec.extensions = ["ext/autotype/extconf.rb"]

  spec.add_runtime_dependency "async", "~> 2.0"
  spec.add_runtime_dependency "faraday", "~> 2.0"
  spec.add_runtime_dependency "prism", "~> 1.0"

  spec.add_development_dependency "dotenv", "~> 3.0"
  spec.add_development_dependency "rspec", "~> 3.13"
end
