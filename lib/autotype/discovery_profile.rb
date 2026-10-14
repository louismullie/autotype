# frozen_string_literal: true

require "yaml"

module Autotype
  # Infers framework wiring, entity layout, and type hints from Ruby source and
  # the filesystem. Optional autotype.yml supplies skip globs and overrides when
  # heuristics are wrong — nothing else is required.
  class DiscoveryProfile
    PORT_CALLS = %i[input output].freeze
    OPTION_CALLS = %i[option].freeze
    FIELD_CALLS = %i[field].freeze
    HANDLER_METHOD_CANDIDATES = %i[process handle call perform run execute].freeze
    DISPATCH_PARAM_CANDIDATES = %i[from source port input_name].freeze
    EMIT_MESSAGES = %i[emit publish send emit_entity].freeze
    EMIT_PORT_KEYWORDS = %i[to port output].freeze

    def self.load_overrides(path, root: File.dirname(path))
      raw = YAML.safe_load_file(path, aliases: true) || {}
      new(root: root, overrides: raw, config_path: path)
    end

    def self.find(start_dir = Dir.pwd)
      dir = File.expand_path(start_dir)
      loop do
        candidate = File.join(dir, "autotype.yml")
        return candidate if File.file?(candidate)

        parent = File.dirname(dir)
        break if parent == dir

        dir = parent
      end
      nil
    end

    def initialize(root: Dir.pwd, overrides: {}, config_path: nil)
      @root = File.expand_path(root)
      @overrides = stringify_keys(overrides)
      @config_path = config_path
      @search_roots = Set.new([@root])
      @port_dsl_owners = Set.new
      @referenced_constants = Set.new
      reset_inference!
    end

    attr_reader :root

    def path
      @config_path
    end

    def prepare_search!(paths)
      paths.each do |file|
        next unless File.file?(file)

        @search_roots << find_project_root(File.dirname(File.expand_path(file)))
      end
    end

    def finalize!(collectors)
      methods = collectors.flat_map(&:methods)
      ports = merge_ports(collectors)

      @port_wiring ||= infer_port_wiring(methods, ports)
      @output_emit ||= infer_output_emit(methods, ports)
      @config_hash ||= infer_config_hash(methods, collectors)
      @side_effect_methods ||= infer_side_effect_methods(methods, ports)
      @structured_type_prefixes = infer_structured_prefixes(collectors, ports) if @structured_type_prefixes.empty?
      @framework_self_fallbacks = infer_self_fallbacks(methods, ports) if @framework_self_fallbacks.empty?
      collectors.each { collect_referenced_constants(_1) }
      @finalized = true
    end

    def skipped_files
      Array(@overrides.fetch("skip", [])).to_set
    end

    def member_type_hints
      @member_type_hints ||= parse_type_map(@overrides.dig("types", "members"))
    end

    def option_type_hints
      @option_type_hints ||= parse_type_map(@overrides.dig("types", "options"))
    end

    def side_effect_methods
      @side_effect_methods || Set.new
    end

    def structured_type_prefixes
      @structured_type_prefixes || []
    end

    def port_wiring
      @port_wiring
    end

    def output_emit
      @output_emit
    end

    def config_hash
      @config_hash
    end

    def framework_self_fallbacks
      @framework_self_fallbacks || {}
    end

    def pipeline_class?(collector, owner)
      return false if collector.singleton_context? || collector.namespace_empty?

      return true if @port_dsl_owners.include?(owner)

      superclass = collector.superclass_for(owner)
      superclass == "Actor" || superclass&.end_with?("::Actor")
    end

    def entity_define_receiver?(receiver_slice)
      return false unless receiver_slice

      receiver_slice == "Entity" ||
        receiver_slice == "Data" ||
        receiver_slice.end_with?("::Entity")
    end

    def visit_call_node(collector, node)
      return unless node.receiver.nil?
      return if collector.singleton_context?

      owner = collector.current_owner
      if port_call?(node.name)
        record_port(collector, node)
        @port_dsl_owners << owner
      elsif option_call?(node.name)
        record_option(collector, node)
        @port_dsl_owners << owner
      elsif field_call?(node.name) && collector.structured_field_context?
        record_field(collector, node)
      end
    end

    def metadata_from(collector)
      InferenceMetadata.from_collector(
        collector,
        member_type_hints: member_type_hints,
        option_type_hints: option_type_hints,
        side_effect_methods: side_effect_methods,
        structured_type_prefixes: structured_type_prefixes,
        port_wiring: port_wiring,
        output_emit: output_emit,
        config_hash: config_hash,
        framework_self_fallbacks: framework_self_fallbacks,
        type_locators: [method(:locate_type_file)]
      )
    end

    def locate_type_file(type_name)
      return @type_path_cache[type_name] if @type_path_cache.key?(type_name)

      explicit = explicit_locator(type_name)
      return cache_type_path(type_name, explicit) if explicit

      basename = type_name.split("::").last
      file_name = "#{underscore(basename)}.rb"
      candidates = @search_roots.flat_map { |search_root| ruby_files_under(search_root).fetch(file_name, []) }.uniq

      path = candidates.find { defines_type?(_1, type_name, basename) }
      cache_type_path(type_name, path)
    end

    private

    # Walked once per root: a glob per type name rewalks the whole tree (vendor/ included) on every lookup.
    def ruby_files_under(search_root)
      @ruby_files_by_root[search_root] ||= Dir.glob(File.join(search_root, "**", "*.rb")).group_by { File.basename(_1) }
    end

    def reset_inference!
      @finalized = false
      @port_wiring = explicit_port_wiring
      @output_emit = explicit_output_emit
      @config_hash = explicit_config_hash
      @side_effect_methods = explicit_side_effect_methods
      @structured_type_prefixes = Array(@overrides.dig("structured", "prefixes"))
      @framework_self_fallbacks = explicit_self_fallbacks
      @type_path_cache = {}
      @ruby_files_by_root = {}
    end

    def cache_type_path(type_name, path)
      @type_path_cache[type_name] = path
    end

    def explicit_locator(type_name)
      Array(@overrides.fetch("locators", [])).each do |locator|
        prefix = locator.fetch("prefix")
        next unless type_name.start_with?(prefix)

        basename = type_name.split("::").last
        snake = underscore(basename)
        Array(locator.fetch("paths")).each do |template|
          path = File.expand_path(template.gsub("{snake}", snake), @root)
          return path if File.file?(path)
        end
      end
      nil
    end

    def explicit_port_wiring
      raw = @overrides.dig("wiring", "ports")
      return unless raw

      InferenceMetadata::PortWiring.new(
        handler_method: raw.fetch("handler").to_sym,
        dispatch_param: raw.fetch("dispatch_param").to_sym,
        dispatch_param_type: TypeString.parse(raw.fetch("dispatch_type", "Symbol")),
        entity_param: raw.fetch("entity_param", "first_required").to_sym
      )
    end

    def explicit_output_emit
      raw = @overrides.dig("wiring", "emit")
      return unless raw

      InferenceMetadata::OutputEmitWiring.new(
        message: raw.fetch("message").to_sym,
        port_keyword: raw.fetch("port_keyword").to_sym,
        argument_index: raw.fetch("argument_index")
      )
    end

    def explicit_config_hash
      raw = @overrides.dig("wiring", "config_hash")
      return unless raw

      InferenceMetadata::ConfigHashWiring.new(
        init_param: raw.fetch("init_param").to_sym,
        reader_method: raw.fetch("reader").to_sym,
        ivar: raw.fetch("ivar")
      )
    end

    def explicit_side_effect_methods
      methods = Array(@overrides.dig("pipeline", "side_effect_methods"))
      return if methods.empty?

      methods.map(&:to_sym).to_set
    end

    def explicit_self_fallbacks
      @overrides.fetch("self_types", {}).each_with_object({}) do |(message, type_string), fallbacks|
        type = TypeString.parse(type_string)
        fallbacks[message.to_sym] = ->(_method, _capability) { type }
      end
    end

    def merge_ports(collectors)
      ports = Hash.new { |hash, key| hash[key] = { inputs: {}, outputs: {} } }
      collectors.each do |collector|
        collector.declared_ports.each do |owner, declared|
          ports[owner][:inputs].merge!(declared[:inputs])
          ports[owner][:outputs].merge!(declared[:outputs])
        end
      end
      ports
    end

    def infer_port_wiring(methods, ports)
      owners = ports.select { |_owner, declared| declared[:inputs].any? }.keys
      observations = owners.filter_map do |owner|
        observe_port_handler(methods, owner)
      end
      return observations.first if observations.length == 1

      grouped = observations.group_by { |observation| [observation.handler_method, observation.dispatch_param] }
      grouped.values.max_by(&:length)&.first
    end

    def observe_port_handler(methods, owner)
      candidates = methods.select do |method|
        method.owner == owner &&
          method.kind == :instance &&
          method.parameters.any? { |parameter| dispatch_param?(parameter) }
      end
      return if candidates.empty?

      handler = HANDLER_METHOD_CANDIDATES.filter_map { |name| candidates.find { |method| method.method_name == name } }.first
      handler ||= candidates.min_by { |method| method.line.to_i }

      dispatch = handler.parameters.find { |parameter| dispatch_param?(parameter) }
      InferenceMetadata::PortWiring.new(
        handler_method: handler.method_name,
        dispatch_param: dispatch.name,
        dispatch_param_type: Named.new("Symbol"),
        entity_param: :first_required
      )
    end

    def dispatch_param?(parameter)
      DISPATCH_PARAM_CANDIDATES.include?(parameter.name) &&
        %i[keyword optional_keyword].include?(parameter.kind)
    end

    def infer_output_emit(methods, ports)
      owners_with_outputs = ports.select { |_owner, declared| declared[:outputs].any? }.keys.to_set
      observations = []
      methods.each do |method|
        next unless owners_with_outputs.include?(method.owner)

        method.capabilities.each do |capability|
          next unless capability.receiver == method.self_type
          next unless EMIT_MESSAGES.include?(capability.message)

          EMIT_PORT_KEYWORDS.each do |keyword|
            next unless capability.keywords.key?(keyword)

            observations << {
              message: capability.message,
              port_keyword: keyword,
              argument_index: 0
            }
          end
        end
      end
      return if observations.empty?

      grouped = observations.group_by { |observation| observation.values_at(:message, :port_keyword, :argument_index) }
      winner = grouped.max_by { |_key, group| group.length }&.last&.first
      InferenceMetadata::OutputEmitWiring.new(
        message: winner.fetch(:message),
        port_keyword: winner.fetch(:port_keyword),
        argument_index: winner.fetch(:argument_index)
      )
    end

    def infer_config_hash(methods, collectors)
      option_owners = collectors.flat_map { |collector| collector.declared_config_options.keys }.to_set
      return if option_owners.empty?

      observations = option_owners.filter_map do |owner|
        reader = methods.find do |method|
          method.owner == owner &&
            method.kind == :instance &&
            method.method_name == :options &&
            method.parameters.empty?
        end
        next unless reader

        {
          init_param: :options,
          reader_method: :options,
          ivar: "@options"
        }
      end
      return if observations.empty?

      grouped = observations.group_by(&:itself)
      winner = grouped.max_by { |_key, group| group.length }&.first
      InferenceMetadata::ConfigHashWiring.new(
        init_param: winner.fetch(:init_param),
        reader_method: winner.fetch(:reader_method),
        ivar: winner.fetch(:ivar)
      )
    end

    def infer_side_effect_methods(methods, ports)
      explicit = explicit_side_effect_methods
      return explicit if explicit

      pipeline_owners = ports.keys.to_set | @port_dsl_owners
      methods.filter_map do |method|
        next unless pipeline_owners.include?(method.owner)
        next unless method.method_name.to_s.match?(/\Aon_[a-z_]+\z/)

        method.method_name
      end.to_set
    end

    def infer_structured_prefixes(collectors, ports)
      explicit = Array(@overrides.dig("structured", "prefixes"))
      return explicit if explicit.any?

      constants = Set.new
      collectors.each do |collector|
        collector.referenced_types.each { constants << _1 }
        collector.structured_owners.each { constants << _1 }
        collector.declared_ports.each_value do |declared|
          declared[:inputs].each_value { |type| constants << type.name if type.is_a?(Named) }
          declared[:outputs].each_value { |type| constants << type.name if type.is_a?(Named) }
        end
      end

      prefixes = constants
        .select { |name| name.include?("::") }
        .map { |name| name.sub(/::[^:]+\z/, "::") }
        .group_by(&:itself)
        .select { |_prefix, group| group.length >= 1 }
        .keys
      prefixes.sort_by { |prefix| -prefix.length }
    end

    def infer_self_fallbacks(methods, ports)
      fallbacks = explicit_self_fallbacks
      pipeline_owners = ports.keys.to_set | @port_dsl_owners
      hash_type = Generic.new("Hash", [Named.new("Symbol"), Named.new("Object")])

      %i[inputs outputs].each do |message|
        next if fallbacks.key?(message)

        used = methods.any? do |method|
          pipeline_owners.include?(method.owner) &&
            method.capabilities.any? { |capability| capability.message == message && capability.receiver == method.self_type }
        end
        fallbacks[message] = ->(_method, _capability) { hash_type } if used
      end
      fallbacks
    end

    def collect_referenced_constants(collector)
      collector.referenced_types.each { @referenced_constants << _1 }
    end

    def port_call?(name) = PORT_CALLS.include?(name)
    def option_call?(name) = OPTION_CALLS.include?(name)
    def field_call?(name) = FIELD_CALLS.include?(name)

    def record_port(collector, node)
      port_name = collector.symbol_arguments(node).first
      type_name = collector.keyword_constant(node.arguments, :type)
      return unless port_name && type_name

      owner = collector.current_owner
      bucket = node.name == :input ? :inputs : :outputs
      collector.declared_ports[owner][bucket][port_name] = Named.new(type_name)
      collector.referenced_types << type_name if structured_constant?(type_name)
    end

    def record_option(collector, node)
      option_name = collector.symbol_arguments(node).first
      return unless option_name

      collector.declared_config_options[collector.current_owner][option_name] =
        option_type_hints[option_name] || infer_option_type(option_name)
    end

    def record_field(collector, node)
      field_name = collector.symbol_arguments(node).first
      return unless field_name

      hint = member_type_hints[field_name] || infer_member_type(field_name)
      collector.declared_member_types[collector.current_owner][field_name] = hint if hint
    end

    def infer_member_type(name)
      type_name = CORE_MEMBER_NAME_TYPES[name]
      Named.new(type_name) if type_name
    end

    def infer_option_type(name)
      return member_type_hints[name] if member_type_hints.key?(name)

      inferred = infer_member_type(name) || infer_name_pattern_type(name.to_s)
      inferred || Named.new("Object")
    end

    def infer_name_pattern_type(name)
      case name
      when /\A(?:is_|has_|allow_|enable_|disable_)/ then Named.new("bool")
      when /_(?:url|uri|path|token|model|mode|collection|actor|source|id|key|name|label)\z/ then Named.new("String")
      when /_(?:timeout|size|count|batch|limit|max|min|page|step|iteration)\z/ then Named.new("Integer")
      when /_(?:min|max|score|distance|ratio|threshold)\z/ then Named.new("Float")
      end
    end

    def structured_constant?(type_name)
      type_name.match?(/\A[A-Z]\w*(?:::[A-Z]\w*)+\z/)
    end

    def defines_type?(path, type_name, basename)
      return false unless File.file?(path)

      source = File.read(path)
      return true if source.match?(/\b#{Regexp.escape(type_name)}(?:\s*=|\s*\n)/)
      return true if source.match?(/\bmodule\s+\w+(?:\s*;\s*\w+)*\s*\n(?:.*\n)*?\s*(?:#{Regexp.escape(basename)}\s*=|class\s+#{Regexp.escape(basename)}\b)/m)
      return true if source.match?(/\bclass\s+#{Regexp.escape(basename)}\b/)
      return true if source.match?(/\b#{Regexp.escape(basename)}\s*=\s*\w+(?:::)?(?:Entity|Data)\.define\b/)

      false
    rescue StandardError
      false
    end

    def find_project_root(start_dir)
      dir = File.expand_path(start_dir)
      loop do
        markers = %w[Gemfile .git autotype.yml].map { |name| File.join(dir, name) }
        return dir if markers.any? { File.exist?(_1) }

        parent = File.dirname(dir)
        break if parent == dir

        dir = parent
      end
      File.expand_path(start_dir)
    end

    def parse_type_map(map)
      (map || {}).transform_keys(&:to_sym).transform_values { |type_string| TypeString.parse(type_string) }
    end

    def underscore(name)
      name
        .gsub(/([A-Z]+)([A-Z][a-z])/, '\1_\2')
        .gsub(/([a-z\d])([A-Z])/, '\1_\2')
        .downcase
    end

    def stringify_keys(value)
      case value
      when Hash
        value.each_with_object({}) { |(key, entry), hash| hash[key.to_s] = stringify_keys(entry) }
      when Array
        value.map { stringify_keys(_1) }
      else
        value
      end
    end
  end
end
