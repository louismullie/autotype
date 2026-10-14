# frozen_string_literal: true

module Autotype
  class << self
    # Analyzes files, directories, or glob patterns and returns an Analysis.
    # Prints nothing and leaves Autotype.configuration untouched, so it is
    # safe to call repeatedly from a long-running process.
    def analyze(paths, config: nil)
      Pipeline.new(expand_paths(paths), profile: build_profile(config)).run
    end

    # Analyzes an in-memory buffer as if it were the file at `path`.
    def analyze_source(source, path: "inline.rb", config: nil)
      Pipeline.new([path], profile: build_profile(config), sources: { path => source }).run
    end

    def expand_paths(paths)
      Array(paths).flat_map do |path|
        if File.directory?(path)
          Dir.glob(File.join(path, "**", "*.rb")).sort
        elsif File.exist?(path) || !path.match?(/[*?\[{]/)
          [path]
        else
          Dir.glob(path).sort
        end
      end.uniq
    end

    private

    def build_profile(config)
      configuration = Configuration.new
      configuration.config_path = config if config
      configuration.load_profile
    end
  end

  # One analyzed method. `signature` is the one-line form; `text` adds the
  # helper and constraint sections the CLI prints.
  MethodReport = Data.define(
    :path, :name, :line, :end_line, :signature, :helpers, :constraints, :send_constraint_count, :locals, :text
  )

  class Analysis
    attr_reader :files, :diagnostics, :iterations

    def initialize(files:, renderers:, diagnostics:, iterations:, converged:)
      @files = files
      @renderers = renderers
      @diagnostics = diagnostics
      @iterations = iterations
      @converged = converged
    end

    def converged? = @converged

    def method_reports
      @method_reports ||= @renderers.map do |path, renderer|
        MethodReport.new(path: path, text: renderer.text, **renderer.as_json)
      end
    end

    def find(name)
      method_reports.find { |report| report.name == name }
    end

    # The `autotype --json` document: file path => method entries.
    def to_h
      @renderers.group_by(&:first).transform_values { |entries| entries.map { |_, renderer| renderer.as_json } }
    end

    def to_json(*arguments)
      to_h.to_json(*arguments)
    end
  end

  # A whole run: parse and collect every file, resolve constants, solve, and
  # name helpers. CLI.run formats the result; nothing here prints.
  class Pipeline
    attr_reader :files, :diagnostics, :helper_registry, :iterations

    def self.parse(path, sources = {})
      sources.key?(path) ? Prism.parse(sources.fetch(path), filepath: path) : Prism.parse_file(path)
    end

    def self.expand_referenced_type_files(files, profile:, sources: {})
      referenced = Set.new
      files.each do |path|
        next unless sources.key?(path) || File.file?(path)

        result = parse(path, sources)
        next unless result.success?

        collector = Collector.new(path, profile: profile)
        result.value.accept(collector)
        locate_referenced_type_files(collector, profile, referenced)
      rescue StandardError
        # The main pass records this file's diagnostic.
        next
      end
      (files + referenced.to_a).uniq
    end

    def self.locate_referenced_type_files(collector, profile, referenced)
      collector.referenced_types.each do |type_name|
        type_path = profile.locate_type_file(type_name)
        referenced << type_path if type_path
      end
    end

    def self.build_metadata(collectors, profile:)
      profile.finalize!(collectors) if profile.respond_to?(:finalize!)
      metadata = InferenceMetadata.new(
        member_type_hints: profile.member_type_hints,
        option_type_hints: profile.option_type_hints,
        side_effect_methods: profile.side_effect_methods,
        structured_type_prefixes: profile.structured_type_prefixes,
        port_wiring: profile.port_wiring,
        output_emit: profile.output_emit,
        config_hash: profile.config_hash,
        framework_self_fallbacks: profile.framework_self_fallbacks,
        type_locators: [profile.method(:locate_type_file)]
      )
      collectors.each do |collector|
        metadata.merge_ports!(collector.declared_ports)
        metadata.merge_member_types!(collector.declared_member_types)
        metadata.merge_config_options!(collector.declared_config_options)
        collector.structured_owners.each { |owner| metadata.structured_owners << owner }
        collector.referenced_types.each { |type| metadata.referenced_types << type }
      end
      metadata
    end

    def initialize(files, profile:, sources: {})
      @profile = profile
      @sources = sources
      @files = files.reject { |path| profile.skipped_files.include?(path.delete_prefix("./")) }
      @diagnostics = []
    end

    def converged? = @converged

    # Everything up to rendering, so callers can rename helpers first.
    def solve
      @profile.prepare_search!(@files) if @profile.respond_to?(:prepare_search!)
      located, solved_methods = infer
      analyzed_methods = located.map(&:last)
      @method_reports = located.map(&:first).zip(solved_methods, analyzed_methods)
      @helper_registry = UniversalHelperRegistry.new(analyzed_methods)
      # Deterministic LLM-free names first; callers may override them.
      HeuristicCapabilityNamer.new(@helper_registry).name!
      self
    end

    def renderers(capability_names: nil)
      @renderers ||= begin
        @helper_registry.apply_names!(capability_names) if capability_names
        memo = Renderer.memo
        @method_reports.map do |path, method, analyzed_method|
          [path, Renderer.new(method, analyzed_method: analyzed_method, helper_registry: @helper_registry, memo: memo)]
        end
      end
    end

    def analysis(capability_names: nil)
      Analysis.new(
        files: @files,
        renderers: renderers(capability_names: capability_names),
        diagnostics: @diagnostics,
        iterations: @iterations,
        converged: @converged
      )
    end

    def run = solve.analysis

    private

    # [[path, constant-resolved method]..., solved methods]. The solver's
    # tables outweigh everything built after them, so the solver goes out
    # of reach with this frame instead of being marked by every collection
    # until rendering ends.
    def infer
      located, inferencer = prepare_inference
      solved_methods = inferencer.run
      @iterations = inferencer.iterations
      @converged = inferencer.converged?
      [located, solved_methods]
    end

    # [[path, constant-resolved method]..., inferencer]. The collectors and
    # their unresolved methods stay here: kept alive through solving, they
    # would be marked by every garbage collection.
    def prepare_inference
      collected = collect_with_referenced_type_files
      collectors = collected.map { |_path, collector| collector }

      includes = Hash.new { |hash, key| hash[key] = [] }
      collectors.each { |collector| collector.includes.each { |owner, mods| includes[owner].concat(mods) } }
      includes.transform_values!(&:uniq)
      resolver = ConstantResolver.new(
        collectors.map(&:constants).reduce({}, :merge),
        collectors.map(&:defined_namespaces).reduce(Set.new, :|)
      )
      located = collected.flat_map do |path, collector|
        collector.methods.map { |method| [path, resolver.resolve(method)] }
      end

      metadata = self.class.build_metadata(collectors, profile: @profile)
      # A stale stack slot can still reach a collector's method list, so it
      # is emptied rather than merely dropped.
      collectors.each { |collector| collector.methods.clear }
      inferencer = FixedPointInferencer.new(
        located.map(&:last), constants: resolver.constants, includes: includes, metadata: metadata
      )
      [located, inferencer]
    end

    # What expand_referenced_type_files then a collect of every file would
    # produce, parsing and collecting each file once: a collector's output
    # depends only on its file, so the given files' collectors also supply
    # the referenced types. Referenced files are collected but not expanded.
    def collect_with_referenced_type_files
      collected = {}
      referenced = Set.new
      @files.each do |path|
        next if collected.key?(path)

        entry = collected[path] = collect(path)
        next unless entry && entry[2]

        begin
          self.class.locate_referenced_type_files(entry[1], @profile, referenced)
        rescue StandardError
          next
        end
      end
      @files = (@files + referenced.to_a).uniq
      @files.filter_map { |path| collected.fetch(path) { collect(path) } }
    end

    # [path, collector, whether the whole file was visited]
    def collect(path)
      result = self.class.parse(path, @sources)
      unless result.success?
        result.errors.each do |error|
          @diagnostics << Diagnostic.new(
            kind: :parse, path: path, line: error.location.start_line, name: nil, message: error.message
          )
        end
        return nil
      end

      collector = Collector.new(path, profile: @profile)
      visited = begin
        result.value.accept(collector)
        true
      rescue StandardError => error
        # Methods collected before the failure are still sound.
        @diagnostics << Diagnostic.new(
          kind: :analysis, path: path, line: nil, name: nil, message: "#{error.class}: #{error.message}"
        )
        false
      end
      @diagnostics.concat(collector.diagnostics)
      [path, collector, visited]
    rescue SystemCallError => error
      @diagnostics << Diagnostic.new(kind: :parse, path: path, line: nil, name: nil, message: error.message)
      nil
    end
  end
end
