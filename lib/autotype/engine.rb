# frozen_string_literal: true

# Syntax-less Ruby type inference engine.
#
# This is deliberately intraprocedural. Each method is analyzed independently:
# parameters and unknown values receive fresh type variables, message sends add
# structural capabilities, and the method boundary generalizes the variables.

require "json"
require "optparse"
require "prism"
require "set"
require "cgi"
require "digest"
begin
  require "dotenv/load"
rescue LoadError
end
require "faraday"
require "async"
require "async/semaphore"

module Autotype
  # Type terms are built by the million while solving, and a Data instance
  # costs twice the allocations of a plain frozen object. These keep Data's
  # equality and inspect output; composite hashes are computed once, since
  # unions are deduplicated constantly.
  class Named
    attr_reader :name, :hash

    def initialize(name)
      @name = name
      @hash = name.hash
      freeze
    end

    def ==(other) = equal?(other) || (other.instance_of?(Named) && name == other.name)
    def eql?(other) = equal?(other) || (other.instance_of?(Named) && name.eql?(other.name))
    def inspect = "#<data #{self.class.name} name=#{name.inspect}>"
    alias to_s inspect
  end

  class Generic
    attr_reader :name, :arguments, :hash

    def initialize(name, arguments)
      @name = name
      @arguments = arguments.freeze
      @hash = name.hash ^ arguments.hash
      freeze
    end

    # Equal terms have equal hashes, so comparing those first rejects most
    # unequal pairs without walking them.
    def ==(other)
      equal?(other) ||
        (other.instance_of?(Generic) && hash == other.hash && name == other.name && arguments == other.arguments)
    end

    def eql?(other)
      equal?(other) ||
        (other.instance_of?(Generic) && hash == other.hash && name.eql?(other.name) && arguments.eql?(other.arguments))
    end

    def inspect = "#<data #{self.class.name} name=#{name.inspect}, arguments=#{arguments.inspect}>"
    alias to_s inspect
  end

  class Union
    attr_reader :members, :hash

    # Hashing every member of a union tens of thousands wide costs more than
    # building it, and most such unions are never hashed at all. Any function
    # of the members agrees with eql?, so wide ones hash a spread of them.
    SAMPLED_HASH_MIN = 64
    HASH_SAMPLES = 16

    def initialize(members)
      @members = members.freeze
      @hash = members.length < SAMPLED_HASH_MIN ? ~members.hash : Union.sampled_hash(members)
      freeze
    end

    def self.sampled_hash(members)
      last = members.length - 1
      sample = Array.new(HASH_SAMPLES) { |index| members[index * last / (HASH_SAMPLES - 1)] }
      ~(sample << members.length).hash
    end

    def ==(other) = equal?(other) || (other.instance_of?(Union) && hash == other.hash && members == other.members)
    def eql?(other) = equal?(other) || (other.instance_of?(Union) && hash == other.hash && members.eql?(other.members))
    def inspect = "#<data #{self.class.name} members=#{members.inspect}>"
    alias to_s inspect
  end

  class Function
    attr_reader :parameters, :result, :hash

    def initialize(parameters, result)
      @parameters = parameters.freeze
      @result = result
      @hash = parameters.hash ^ result.hash ^ 1
      freeze
    end

    def ==(other)
      equal?(other) ||
        (other.instance_of?(Function) && hash == other.hash && parameters == other.parameters && result == other.result)
    end

    def eql?(other)
      equal?(other) ||
        (other.instance_of?(Function) && hash == other.hash && parameters.eql?(other.parameters) && result.eql?(other.result))
    end

    def inspect = "#<data #{self.class.name} parameters=#{parameters.inspect}, result=#{result.inspect}>"
    alias to_s inspect
  end
  Capability = Data.define(:receiver, :message, :arguments, :keywords, :result, :line)
  # Most sends pass no keywords and most methods assign no ivars; sharing
  # these keeps a few hundred thousand empty containers out of the live heap.
  EMPTY_ARRAY = [].freeze
  EMPTY_HASH = {}.freeze
  Parameter = Data.define(:name, :type, :kind)
  # A helper-type argument for consolidated definitions: a normalized slot
  # string whose T-references are filled from the occurrence's own arguments.
  TemplateArgument = Data.define(:template, :arguments)
  MethodResult = Data.define(
    :name, :owner, :kind, :method_name, :superclass, :line, :end_line,
    :parameters, :result, :capabilities, :self_type, :ivars, :locals, :port_assignments,
    :case_narrowings
  )
  # A file or method autotype could not analyze. `kind` is :parse or
  # :analysis; `name` is the qualified method name, or nil for the file.
  Diagnostic = Data.define(:kind, :path, :line, :name, :message)

  class InferenceMetadata
    PortWiring = Data.define(:handler_method, :dispatch_param, :dispatch_param_type, :entity_param)
    OutputEmitWiring = Data.define(:message, :port_keyword, :argument_index)
    ConfigHashWiring = Data.define(:init_param, :reader_method, :ivar)

    attr_reader :member_types, :ports, :config_options, :structured_owners, :referenced_types,
                :member_type_hints, :option_type_hints, :side_effect_methods,
                :structured_type_prefixes, :port_wiring, :output_emit, :config_hash,
                :framework_self_fallbacks, :type_locators

    def self.empty
      new
    end

    def self.from_collector(collector, **overrides)
      new(
        member_types: deep_copy_nested(collector.declared_member_types),
        ports: deep_copy_ports(collector.declared_ports),
        config_options: deep_copy_nested(collector.declared_config_options),
        structured_owners: collector.structured_owners.dup,
        referenced_types: collector.referenced_types.dup,
        **overrides
      )
    end

    def self.deep_copy_nested(source)
      source.transform_values(&:dup)
    end

    def self.deep_copy_ports(source)
      source.transform_values do |ports|
        { inputs: ports[:inputs].dup, outputs: ports[:outputs].dup }
      end
    end

    def initialize(
      member_types: nil,
      ports: nil,
      config_options: nil,
      structured_owners: nil,
      referenced_types: nil,
      member_type_hints: {},
      option_type_hints: {},
      side_effect_methods: nil,
      structured_type_prefixes: [],
      port_wiring: nil,
      output_emit: nil,
      config_hash: nil,
      framework_self_fallbacks: {},
      type_locators: []
    )
      @member_types = member_types || Hash.new { |hash, key| hash[key] = {} }
      @ports = ports || Hash.new { |hash, key| hash[key] = { inputs: {}, outputs: {} } }
      @config_options = config_options || Hash.new { |hash, key| hash[key] = {} }
      @structured_owners = structured_owners || Set.new
      @referenced_types = referenced_types || Set.new
      @member_type_hints = member_type_hints
      @option_type_hints = option_type_hints
      @side_effect_methods = side_effect_methods || Set.new
      @structured_type_prefixes = structured_type_prefixes
      @port_wiring = port_wiring
      @output_emit = output_emit
      @config_hash = config_hash
      @framework_self_fallbacks = framework_self_fallbacks
      @type_locators = type_locators
    end

    def merge_ports!(source)
      source.each do |owner, ports|
        @ports[owner] ||= { inputs: {}, outputs: {} }
        @ports[owner][:inputs].merge!(ports[:inputs])
        @ports[owner][:outputs].merge!(ports[:outputs])
      end
    end

    def merge_member_types!(source)
      source.each { |owner, fields| @member_types[owner].merge!(fields) }
    end

    def merge_config_options!(source)
      source.each { |owner, options| @config_options[owner].merge!(options) }
    end

    def port_wiring? = @port_wiring && @ports.values.any? { |ports| ports[:inputs].any? }
    def output_emit? = @output_emit && @ports.values.any? { |ports| ports[:outputs].any? }
    def config_hash? = @config_hash && @config_options.values.any?(&:any?)

    def structured_type?(name)
      return true if @structured_owners.include?(name)
      return true if @member_types.key?(name) && @member_types[name].any?

      @structured_type_prefixes.any? { |prefix| name.start_with?(prefix) }
    end

    def locate_type_file(type_name)
      @type_locators.lazy.filter_map { |locator| locator.call(type_name) }.first
    end
  end

  # Heuristic member-name -> type mappings used when no explicit declaration
  # exists. Common field names across Ruby codebases, not framework-specific.
  CORE_MEMBER_NAME_TYPES = {
    name: "String",
    id: "String",
    text: "String",
    content: "String",
    title: "String",
    url: "String",
    uri: "String",
    email: "String",
    description: "String",
    status: "String",
    type: "String",
    kind: "String",
    key: "String",
    label: "String",
    path: "String",
    token: "String",
    query: "String",
    message: "String",
    body: "String",
    uuid: "String",
    code: "String",
    role: "String",
    object: "String",
    source: "String",
    step: "Integer",
    sequence_id: "Integer",
    count: "Integer",
    size: "Integer",
    page: "Integer",
    per_page: "Integer",
    timeout: "Integer",
    iteration: "Integer",
    status_code: "Integer",
    total_count: "Integer",
    concept_type: "String",
    core_phrase: "String",
    hashed_id: "String",
    collection: "String",
    distance: "Float"
  }.freeze

  # Kernel module functions invoked without an explicit receiver (`Array(x)`).
  KERNEL_CLASS_CALLS = %i[Array Integer Float String Symbol Hash].freeze

  # Type names that must not be treated as literal hash key strings.
  RESERVED_TYPE_NAMES = %w[String Symbol Integer Float Rational Complex bool nil Object].freeze

  # Identity is equality: every (scope, id) pair is minted exactly once, so
  # the default C-level hash/eql? stay correct and allocate nothing.
  #
  # Variables belong to one run, so the solver keeps its substitution on the
  # variable itself (link) instead of in a table keyed by it, and clears it
  # when solving ends. rebindable marks variables path compression must keep.
  class TypeVariable
    attr_reader :scope, :id, :hint
    attr_accessor :link, :rebindable

    def initialize(scope, id, hint = nil)
      @scope = scope
      @id = id
      @hint = hint
      @link = nil
      @rebindable = false
    end
  end

  class Analyzer
    attr_reader :capabilities

    def initialize
      @next_id = 0
      @environment = {}
      @local_bindings = {}
      @block_locals = {}
      @ivars = {}
      @capabilities = []
      @return_types = []
      @port_assignments = []
      @scope = Object.new
      @self_type = fresh("self")
    end

    def analyze(node, qualified_name, owner:, kind:, superclass:)
      @infer_cache = {}
      @case_narrowings = Hash.new { |hash, key| hash[key] = [] }
      parameters = bind_parameters(node.parameters)
      result = infer(node.body)
      result = Named.new("nil") unless result
      @return_types.each { |return_type| result = union(result, return_type) }
      if @yield_function && parameters.none? { |parameter| parameter.kind == :block }
        parameters += [Parameter.new(name: :block, type: @yield_function, kind: :block)]
      end

      # A name bound both at method level and inside blocks (e.g.
      # `x = nil` reassigned within an each) carries both types.
      locals = @block_locals.merge(@environment) { |_name, inner, outer| union(inner, outer) }
      MethodResult.new(
        name: qualified_name,
        owner: owner,
        kind: kind,
        method_name: node.name,
        superclass: superclass,
        line: node.location.start_line,
        end_line: node.location.end_line,
        parameters: parameters.empty? ? EMPTY_ARRAY : parameters,
        result: result,
        capabilities: capabilities,
        self_type: @self_type,
        ivars: @ivars.empty? ? EMPTY_HASH : @ivars.dup,
        locals: locals.empty? ? EMPTY_HASH : locals,
        port_assignments: @port_assignments.empty? ? EMPTY_ARRAY : @port_assignments.dup,
        case_narrowings: @case_narrowings.empty? ? EMPTY_HASH : @case_narrowings.transform_values { |types| types.uniq }
      )
    end

    private

    def fresh(hint = nil)
      variable = TypeVariable.new(@scope, @next_id, hint)
      @next_id += 1
      variable
    end

    def bind_parameters(parameters_node)
      return [] unless parameters_node

      parameters = []
      required = parameters_node.requireds + parameters_node.posts
      required.each do |node|
        parameters << if node.is_a?(Prism::MultiTargetNode)
          Parameter.new(name: node.slice.to_sym, type: bind_block_parameter(node), kind: :required)
        else
          bind_parameter(node.name, :required)
        end
      end
      parameters_node.optionals.each do |node|
        parameters << bind_parameter(node.name, :optional, default_node: node.value)
      end

      if parameters_node.rest
        name = parameters_node.rest.name || :anonymous_rest
        element = fresh(name)
        @environment[name] = Generic.new("Array", [element])
        parameters << Parameter.new(name: name, type: @environment[name], kind: :rest)
      end

      parameters_node.keywords.each do |node|
        kind = node.is_a?(Prism::OptionalKeywordParameterNode) ? :optional_keyword : :keyword
        default_node = node.value if node.is_a?(Prism::OptionalKeywordParameterNode)
        parameters << bind_parameter(node.name, kind, default_node: default_node)
      end

      if parameters_node.keyword_rest
        if parameters_node.keyword_rest.is_a?(Prism::ForwardingParameterNode)
          type = fresh("forwarding")
          parameters << Parameter.new(name: :"...", type: type, kind: :forwarding)
        else
          name = parameters_node.keyword_rest.name || :anonymous_keywords
          key = Named.new("Symbol")
          value = fresh(name)
          @environment[name] = Generic.new("Hash", [key, value])
          parameters << Parameter.new(name: name, type: @environment[name], kind: :keyword_rest)
        end
      end

      if parameters_node.block
        name = parameters_node.block.name || :anonymous_block
        type = fresh(name)
        @environment[name] = type
        parameters << Parameter.new(name: name, type: type, kind: :block)
      end

      parameters
    end

    def bind_parameter(name, kind, default_node: nil)
      type = if default_node
        default_type = infer(default_node)
        if nil_default_type?(default_type)
          union(fresh(name), default_type)
        else
          default_type
        end
      else
        fresh(name)
      end
      @environment[name] = type
      Parameter.new(name: name, type: type, kind: kind)
    end

    def nil_default_type?(type)
      type.is_a?(Named) && type.name == "nil"
    end

    def infer(node)
      return Named.new("nil") unless node
      return @infer_cache[node.object_id] if @infer_cache&.key?(node.object_id)

      result = infer_node(node)
      @infer_cache[node.object_id] = result if cache_infer_node?(node)
      result
    end

    def cache_infer_node?(node)
      case node
      when Prism::CallNode, Prism::ArrayNode, Prism::HashNode, Prism::KeywordHashNode,
           Prism::StringNode, Prism::IntegerNode, Prism::FloatNode, Prism::SymbolNode,
           Prism::InterpolatedSymbolNode, Prism::RegularExpressionNode,
           Prism::TrueNode, Prism::FalseNode, Prism::NilNode, Prism::RangeNode,
           Prism::RationalNode, Prism::ImaginaryNode
        true
      else
        false
      end
    end

    def infer_node(node)
      case node
      when Prism::StatementsNode
        infer_statements(node)
      when Prism::LocalVariableReadNode
        @environment[node.name] ||= @local_bindings[node.name] ||= fresh(node.name)
      when Prism::ItLocalVariableReadNode
        @environment[:it] ||= fresh(:it)
      when Prism::LocalVariableWriteNode
        value = infer(node.value)
        @environment[node.name] = value
        @local_bindings[node.name] = value
      when Prism::LocalVariableAndWriteNode, Prism::LocalVariableOrWriteNode,
           Prism::LocalVariableOperatorWriteNode
        current = @environment[node.name] ||= @local_bindings[node.name] ||= fresh(node.name)
        value = infer(node.value)
        @environment[node.name] = union(current, value)
        @local_bindings[node.name] = @environment[node.name]
      when Prism::InstanceVariableReadNode
        @ivars[node.name] ||= fresh(node.name)
      when Prism::InstanceVariableWriteNode
        @ivars[node.name] = infer(node.value)
      when Prism::CallNode
        infer_call(node)
      when Prism::YieldNode
        infer_yield(node)
      when Prism::InterpolatedStringNode
        infer_interpolated_string(node)
      when Prism::StringNode
        Named.new("String")
      when Prism::IntegerNode
        Named.new("Integer")
      when Prism::FloatNode
        Named.new("Float")
      when Prism::RationalNode
        Named.new("Rational")
      when Prism::ImaginaryNode
        Named.new("Complex")
      when Prism::SymbolNode, Prism::InterpolatedSymbolNode
        Named.new("Symbol")
      when Prism::TrueNode, Prism::FalseNode
        Named.new("bool")
      when Prism::NilNode
        Named.new("nil")
      when Prism::ArrayNode
        elements = node.elements.map { |element| infer(element) }
        Generic.new("Array", [union_all(elements)])
      when Prism::HashNode, Prism::KeywordHashNode
        infer_hash(node)
      when Prism::RangeNode
        Generic.new("Range", [union(infer(node.left), infer(node.right))])
      when Prism::IfNode
        infer(node.predicate)
        union(infer(node.statements), infer(node.subsequent))
      when Prism::UnlessNode
        infer(node.predicate)
        union(infer(node.statements), infer(node.else_clause&.statements))
      when Prism::CaseNode
        infer_case(node)
      when Prism::AndNode, Prism::OrNode
        union(infer(node.left), infer(node.right))
      when Prism::ReturnNode
        value = infer(node.arguments)
        @return_types << value
        value
      when Prism::BreakNode, Prism::NextNode
        infer(node.arguments)
      when Prism::ArgumentsNode
        values = node.arguments.map { |argument| infer(argument) }
        values.length == 1 ? values.first : Generic.new("Tuple", values)
      when Prism::ParenthesesNode
        infer(node.body)
      when Prism::BeginNode
        infer_begin(node)
      when Prism::BlockNode
        infer_block(node)
      when Prism::LambdaNode
        infer_lambda(node)
      when Prism::ConstantReadNode, Prism::ConstantPathNode,
           Prism::ConstantPathTargetNode, Prism::ConstantTargetNode
        Named.new("Class[#{node.slice}]")
      when Prism::SelfNode
        @self_type
      when Prism::SourceFileNode, Prism::SourceLineNode, Prism::SourceEncodingNode
        Named.new("String")
      else
        infer_children(node)
      end
    end

    def infer_statements(node)
      result = Named.new("nil")
      node.body.each { |statement| result = infer(statement) }
      result
    end

    def infer_call(node)
      receiver =
        if node.receiver
          infer(node.receiver)
        elsif KERNEL_CLASS_CALLS.include?(node.name)
          Named.new("Class[#{node.name}]")
        else
          @self_type
        end
      positional = []
      keywords = {}

      node.arguments&.arguments&.each do |argument|
        if argument.is_a?(Prism::KeywordHashNode)
          argument.elements.each do |element|
            if element.is_a?(Prism::AssocNode) && element.key.is_a?(Prism::SymbolNode)
              keywords[element.key.unescaped.to_sym] = infer_keyword_argument(element.value)
            elsif element.is_a?(Prism::AssocNode)
              # Non-symbol keys (`3 => io` for Process.spawn) are hash
              # entries that cannot bind a keyword parameter.
              infer(element.key)
              infer(element.value)
            else
              positional << infer(element)
            end
          end
        else
          positional << infer_index_argument(node.name, argument)
        end
      end

      if node.block
        block_type = if node.block.is_a?(Prism::BlockNode)
          infer_block(node.block)
        else
          infer(node.block.expression)
        end
        positional << block_type
      end
      result = fresh(node.name)
      capabilities << Capability.new(
        receiver: receiver,
        message: node.name,
        arguments: positional.empty? ? EMPTY_ARRAY : positional,
        keywords: keywords.empty? ? EMPTY_HASH : keywords,
        result: result,
        line: node.location.start_line
      )
      result
    end

    def infer_interpolated_string(node)
      node.parts.each do |part|
        next unless part.is_a?(Prism::EmbeddedStatementsNode)

        value = infer(part.statements)
        capabilities << Capability.new(
          receiver: value,
          message: :to_s,
          arguments: EMPTY_ARRAY,
          keywords: EMPTY_HASH,
          result: Named.new("String"),
          line: part.location.start_line
        )
      end
      Named.new("String")
    end

    def infer_index_argument(message, node)
      return infer(node) unless message == :[]

      infer_literal_key(node)
    end

    def infer_literal_key(node)
      case node
      when Prism::StringNode then Named.new(node.unescaped)
      when Prism::SymbolNode then Named.new(node.unescaped)
      else infer(node)
      end
    end

    def infer_keyword_argument(node)
      case node
      when Prism::SymbolNode then Named.new(node.unescaped)
      else infer(node)
      end
    end

    def infer_hash(node)
      keys = []
      values = []
      node.elements.each do |element|
        next unless element.is_a?(Prism::AssocNode)

        keys << infer(element.key)
        values << infer(element.value)
      end
      Generic.new("Hash", [union_all(keys), union_all(values)])
    end

    # `yield` gives the method an implicit block parameter; sharing one
    # function type across yields lets call sites flow their block's return
    # type into the yield expression.
    def infer_yield(node)
      arguments = Array(node.arguments&.arguments).map { |argument| infer(argument) }
      @yield_function ||= Function.new(arguments, fresh("yield"))
      @yield_function.result
    end

    def infer_case(node)
      predicate_name = case_predicate_name(node.predicate)
      result = Named.new("nil")
      node.conditions.each do |when_node|
        next unless when_node.is_a?(Prism::WhenNode)

        port = when_port_name(when_node)
        record_port_assignment(when_node, port) if predicate_name == :from && port
        saved_environment = @environment.dup
        narrow_case_branch!(node.predicate, when_node)
        result = union(result, infer(when_node.statements))
        @environment = saved_environment
      end
      result = union(result, infer(node.consequent)) if node.consequent
      result
    end

    def narrow_case_branch!(predicate, when_node)
      branch_type = type_from_when_conditions(when_node.conditions)
      return unless branch_type

      case predicate
      when Prism::LocalVariableReadNode
        @case_narrowings[predicate.name] << branch_type
      end
    end

    def type_from_when_conditions(conditions)
      types = conditions.filter_map { |condition| type_from_when_condition(condition) }
      return nil if types.empty?

      types.reduce { |left, right| union(left, right) }
    end

    def type_from_when_condition(condition)
      class_name =
        case condition
        when Prism::ConstantReadNode, Prism::ConstantPathNode
          condition.slice.to_s.delete_prefix("::")
        end
      return nil unless class_name

      case class_name
      when "Hash"
        Generic.new("Hash", [union(Named.new("String"), Named.new("Symbol")), Named.new("Object")])
      when "Array"
        Generic.new("Array", [Named.new("Object")])
      when "String"
        Named.new("String")
      when "Integer"
        Named.new("Integer")
      when "Float"
        Named.new("Float")
      when "Symbol"
        Named.new("Symbol")
      end
    end

    def case_predicate_name(predicate)
      case predicate
      when Prism::LocalVariableReadNode
        predicate.name
      when Prism::CallNode
        if predicate.name == :to_sym && predicate.receiver.is_a?(Prism::LocalVariableReadNode)
          predicate.receiver.name
        end
      end
    end

    def when_port_name(when_node)
      condition = when_node.conditions.first
      case condition
      when Prism::SymbolNode then condition.unescaped.to_sym
      when Prism::StringNode then condition.unescaped.to_sym
      when Prism::IntegerNode then condition.value
      end
    end

    def record_port_assignment(when_node, port)
      assignment = port_assignment_from_statements(when_node.statements)
      return unless assignment

      @port_assignments << assignment.merge(port: port)
    end

    def port_assignment_from_statements(statements_node)
      walk = lambda do |node|
        return nil unless node

        case node
        when Prism::StatementsNode
          node.body.each { |statement| (result = walk.call(statement)) && (return result) }
        when Prism::InstanceVariableWriteNode
          if node.value.is_a?(Prism::LocalVariableReadNode)
            return { param: node.value.name, ivar: node.name }
          end
        when Prism::CallNode
          return { param: node.receiver.name, ivar: nil } if node.receiver.is_a?(Prism::LocalVariableReadNode)
        end
        nil
      end
      walk.call(statements_node)
    end

    def infer_begin(node)
      result = infer(node.statements)
      rescue_clause = node.rescue_clause
      while rescue_clause
        bind_rescue_reference(rescue_clause)
        result = union(result, infer(rescue_clause.statements))
        rescue_clause = rescue_clause.subsequent
      end
      infer(node.ensure_clause.statements) if node.ensure_clause
      result
    end

    # `rescue SomeError => e` names an exception whose class is written right
    # there; binding it makes `e.message` and friends resolvable.
    def bind_rescue_reference(clause)
      reference = clause.reference
      return unless reference.is_a?(Prism::LocalVariableTargetNode)

      exceptions = clause.exceptions.filter_map do |exception|
        case exception
        when Prism::ConstantReadNode, Prism::ConstantPathNode
          Named.new(exception.slice.delete_prefix("::"))
        end
      end
      @environment[reference.name] =
        if exceptions.empty?
          Named.new("StandardError")
        elsif exceptions.length == 1
          exceptions.first
        else
          Union.new(exceptions)
        end
    end

    def infer_block(node)
      saved_environment = @environment.dup
      parameter_types = bind_implicit_parameters(node.parameters)

      if node.parameters.is_a?(Prism::BlockParametersNode) && node.parameters.parameters
        block_parameters = node.parameters.parameters
        (block_parameters.requireds + block_parameters.posts).each do |parameter|
          parameter_types << bind_block_parameter(parameter)
        end
      end

      result = infer(node.body)
      capture_block_locals(saved_environment)
      @environment = saved_environment
      Function.new(parameter_types, result)
    end

    # Block-scoped bindings vanish when the outer environment is restored,
    # but they are exactly what editor hovers need. Only bindings the block
    # introduced or changed are kept, so a later block's view of an outer
    # variable cannot clobber an earlier block's assignment.
    def capture_block_locals(saved_environment)
      @environment.each do |name, type|
        next if saved_environment[name].equal?(type)

        recorded = @block_locals[name]
        @block_locals[name] = recorded ? union(recorded, type) : type
      end
    end

    def bind_block_parameter(parameter)
      if parameter.is_a?(Prism::MultiTargetNode)
        members = (parameter.lefts + parameter.rights).map { |member| bind_block_parameter(member) }
        if parameter.rest&.expression
          rest_type = fresh(parameter.rest.expression.name)
          @environment[parameter.rest.expression.name] = Generic.new("Array", [rest_type])
          members << @environment[parameter.rest.expression.name]
        end
        return Generic.new("Tuple", members)
      end

      type = fresh(parameter.name)
      @environment[parameter.name] = type
      type
    end

    # `_1`/`_2` and `it` blocks carry no ParametersNode, only an arity.
    def bind_implicit_parameters(parameters_node)
      names =
        case parameters_node
        when Prism::NumberedParametersNode then (1..parameters_node.maximum).map { |index| :"_#{index}" }
        when Prism::ItParametersNode then [:it]
        else []
        end
      names.map { |name| @environment[name] = fresh(name) }
    end

    def infer_lambda(node)
      saved_environment = @environment.dup
      parameter_types =
        if node.parameters.is_a?(Prism::BlockParametersNode)
          bind_parameters(node.parameters.parameters).map(&:type)
        else
          bind_implicit_parameters(node.parameters)
        end
      result = infer(node.body)
      capture_block_locals(saved_environment)
      @environment = saved_environment
      Function.new(parameter_types, result)
    end

    def infer_children(node)
      result = Named.new("nil")
      node.compact_child_nodes.each { |child| result = infer(child) }
      result
    end

    def union_all(types)
      types.compact.reduce { |left, right| union(left, right) } || fresh("element")
    end

    def union(left, right)
      return right unless left
      return left unless right
      return left if left == right

      members = []
      members.concat(left.members) if left.is_a?(Union)
      members << left unless left.is_a?(Union)
      members.concat(right.members) if right.is_a?(Union)
      members << right unless right.is_a?(Union)
      Union.new(members.uniq)
    end
  end

  class Collector < Prism::Visitor
    attr_reader :methods, :constants, :includes, :declared_ports, :declared_config_options,
                :declared_member_types, :structured_owners, :referenced_types, :diagnostics,
                :defined_namespaces

    def initialize(path, profile: nil)
      @path = path
      @profile = profile
      @namespace = []
      @singleton = false
      @methods = []
      @diagnostics = []
      @defined_namespaces = Set.new
      @superclasses = {}
      @constants = {}
      @includes = Hash.new { |hash, key| hash[key] = [] }
      @declared_ports = Hash.new { |hash, key| hash[key] = { inputs: {}, outputs: {} } }
      @declared_config_options = Hash.new { |hash, key| hash[key] = {} }
      @declared_member_types = Hash.new { |hash, key| hash[key] = {} }
      @structured_owners = Set.new
      @referenced_types = Set.new
      @structured_field_context = false
    end

    def singleton_context? = @singleton
    def namespace_empty? = @namespace.empty?
    def structured_field_context? = @structured_field_context

    def superclass_for(owner)
      @superclasses[owner]
    end

    def current_owner
      @namespace.empty? ? File.basename(@path, ".rb") : @namespace.join("::")
    end

    def visit_module_node(node)
      @defined_namespaces << qualified_owner(node.constant_path.slice)
      within_namespace(node.constant_path.slice) { super }
    end

    def visit_class_node(node)
      name = node.constant_path.slice
      @defined_namespaces << qualified_owner(name)
      @superclasses[qualified_owner(name)] = node.superclass&.slice
      within_namespace(name) { super }
    end

    def visit_singleton_class_node(node)
      previous = @singleton
      @singleton = node.expression.is_a?(Prism::SelfNode)
      super
    ensure
      @singleton = previous
    end

    def visit_def_node(node)
      singleton = @singleton || !node.receiver.nil?
      separator = singleton ? "." : "#"
      owner = current_owner
      if node.name == :initialize && !singleton
        methods.reject! do |method|
          method.owner == owner &&
            method.method_name == :initialize &&
            method.capabilities.empty?
        end
      end
      name = "#{owner}#{separator}#{node.name}"
      begin
        methods << Analyzer.new.analyze(
          node,
          name,
          owner: owner,
          kind: singleton ? :singleton : :instance,
          superclass: @superclasses[owner]
        )
      rescue StandardError => error
        diagnostics << Diagnostic.new(
          kind: :analysis, path: @path, line: node.location.start_line, name: name,
          message: "#{error.class}: #{error.message}"
        )
      end
      # A nested def has its own scope and is collected by the normal traversal.
      super
    end

    def visit_call_node(node)
      synthesize_attribute_methods(node) if node.receiver.nil?
      record_include(node) if node.receiver.nil? && node.name == :include
      @profile&.visit_call_node(self, node)
      super
    end

    # `Hit = App::Entity.define do ... end`, `Foo = Class.new(Base) do ... end`,
    # and similar block-based definitions are class bodies: methods defined
    # inside belong to the assigned constant, not the enclosing module.
    def visit_constant_write_node(node)
      record_constant(node.name.to_s, node.value)
      within_constant_definition(node.name.to_s, node.value) { super }
    end

    def visit_constant_path_write_node(node)
      record_constant(node.target.slice, node.value)
      within_constant_definition(node.target.slice, node.value) { super }
    end

    def symbol_arguments(node)
      Array(node.arguments&.arguments).filter_map do |argument|
        argument.unescaped.to_sym if argument.is_a?(Prism::SymbolNode)
      end
    end

    def keyword_constant(arguments_node, key)
      return nil unless arguments_node

      Array(arguments_node.arguments).each do |argument|
        next unless argument.is_a?(Prism::KeywordHashNode)

        argument.elements.each do |element|
          next unless element.is_a?(Prism::AssocNode)
          next unless element.key.slice.delete_suffix(":").to_sym == key

          return constant_argument_slice(element.value) || element.value.slice
        end
      end
      nil
    end

    def core_member_type_hint(member)
      type_name = CORE_MEMBER_NAME_TYPES[member]
      Named.new(type_name) if type_name
    end

    private

    def within_constant_definition(name, value, &)
      if value.is_a?(Prism::CallNode) && record_definition_members(name, value) && !value.block
        return yield
      end
      return yield unless value.is_a?(Prism::CallNode) && value.block

      if value.name == :new && value.receiver&.slice == "Class"
        @superclasses[qualified_owner(name)] = value.arguments&.arguments&.first&.slice
      end
      within_namespace(name, &)
    end

    # `Entity.define(:url, :title) { ... }`, `Data.define`, and `Struct.new`
    # generate member readers and a keyword constructor. Without synthesizing
    # them, every attribute read in the repo is an unresolvable send.
    def record_definition_members(name, value)
      entity_define = value.name == :define &&
        @profile&.entity_define_receiver?(value.receiver&.slice)
      members =
        if entity_define || value.name == :define && %w[Entity Data].include?(value.receiver&.slice)
          symbol_arguments(value)
        elsif value.name == :new && value.receiver&.slice == "Struct"
          symbol_arguments(value)
        elsif value.name == :define && value.receiver&.slice == "Data"
          symbol_arguments(value)
        end
      return false if members.nil? || members.empty?

      within_namespace(name) do
        @structured_field_context = entity_define
        @structured_owners << current_owner
        members.each { |member| methods << synthesized_accessor(member, value, writer: false) }
        methods << synthesized_member_initializer(members, value)
        members.each do |member|
          hint = @profile&.member_type_hints&.fetch(member, nil) || core_member_type_hint(member)
          declared_member_types[current_owner][member] = hint if hint
        end
      ensure
        @structured_field_context = false
      end
      true
    end

    # A Data-style keyword constructor: each keyword parameter shares its
    # type variable with the backing member ivar, so call-site argument
    # types flow into the synthesized readers.
    def synthesized_member_initializer(members, node)
      scope = Object.new
      parameters = []
      ivars = {}
      members.each_with_index do |member, index|
        value = TypeVariable.new(scope, index, member)
        parameters << Parameter.new(name: member, type: value, kind: :keyword)
        ivars[:"@#{member}"] = value
      end
      owner = current_owner
      MethodResult.new(
        name: "#{owner}#initialize",
        owner: owner,
        kind: :instance,
        method_name: :initialize,
        superclass: @superclasses[owner],
        line: node.location.start_line,
        end_line: node.location.start_line,
        parameters: parameters,
        result: TypeVariable.new(scope, members.length, "instance"),
        capabilities: [],
        self_type: TypeVariable.new(scope, members.length + 1, "self"),
        ivars: ivars,
        locals: {},
        port_assignments: [],
        case_narrowings: {}
      )
    end

    # Constants assigned literals (regexes, frozen hashes, word lists) are
    # ubiquitous; recording their types lets the solver treat `RE.match?(x)`
    # or `PATTERNS.fetch(key)` like sends on the literal itself.
    def record_constant(name, value)
      if class_factory_call?(value)
        @defined_namespaces << qualified_owner(name)
      elsif (type = literal_constant_type(value))
        @constants[qualified_owner(name)] = type
      end
    end

    def literal_constant_type(node)
      case node
      when Prism::StringNode, Prism::InterpolatedStringNode then Named.new("String")
      when Prism::SymbolNode then Named.new("Symbol")
      when Prism::IntegerNode then Named.new("Integer")
      when Prism::FloatNode then Named.new("Float")
      when Prism::TrueNode, Prism::FalseNode then Named.new("bool")
      when Prism::RegularExpressionNode, Prism::InterpolatedRegularExpressionNode then Named.new("Regexp")
      when Prism::ArrayNode then literal_array_type(node)
      when Prism::HashNode then literal_hash_type(node)
      when Prism::LambdaNode then Named.new("Proc")
      when Prism::ParenthesesNode
        statements = node.body&.body
        literal_constant_type(statements.first) if statements&.length == 1
      # Aliases (`DEFAULT = PI`) stay references until ConstantResolver sees
      # every file's constants.
      when Prism::ConstantReadNode, Prism::ConstantPathNode then Named.new("Class[#{node.slice}]")
      when Prism::CallNode then literal_call_type(node)
      end
    end

    def literal_array_type(node)
      elements = node.elements.map { |element| literal_constant_type(element) }
      return nil if elements.empty? || elements.any?(&:nil?)

      unique = elements.uniq
      Generic.new("Array", [unique.length == 1 ? unique.first : Union.new(unique)])
    end

    def literal_hash_type(node)
      keys = []
      values = []
      node.elements.each do |element|
        return nil unless element.is_a?(Prism::AssocNode)

        keys << literal_constant_type(element.key)
        values << literal_constant_type(element.value)
      end
      return nil if keys.empty? || keys.any?(&:nil?) || values.any?(&:nil?)

      key = keys.uniq.length == 1 ? keys.first : Union.new(keys.uniq)
      value = values.uniq.length == 1 ? values.first : Union.new(values.uniq)
      Generic.new("Hash", [key, value])
    end

    STRING_LITERAL_CALLS = %i[chomp strip lstrip rstrip squish downcase upcase].to_set.freeze
    FILE_STRING_CALLS = %i[expand_path join basename dirname read].to_set.freeze
    CLASS_FACTORIES = { new: %w[Class Module Struct], define: %w[Data Entity] }.freeze
    ARITHMETIC = %i[+ - * / % ** << >>].to_set.freeze

    def literal_call_type(node)
      receiver = node.receiver
      if ARITHMETIC.include?(node.name) && receiver && node.arguments&.arguments&.length == 1
        literal_arithmetic_type(node.name, literal_constant_type(receiver),
                                literal_constant_type(node.arguments.arguments.first))
      elsif receiver.nil? && %i[lambda proc].include?(node.name) && node.block
        Named.new("Proc")
      elsif %i[freeze dup].include?(node.name) && receiver
        literal_constant_type(receiver)
      elsif %i[new create_many].include?(node.name) && %w[Fast::Regexp Regexp].include?(receiver&.slice)
        Named.new("Regexp")
      elsif node.name == :to_set && receiver
        inner = literal_constant_type(receiver)
        Generic.new("Set", inner.arguments) if inner.is_a?(Generic) && inner.name == "Array"
      elsif node.name == :new && receiver.nil?
        Named.new(current_owner) unless @namespace.empty?
      elsif node.name == :new && constant_node?(receiver) && !class_factory_call?(node)
        Named.new(receiver.slice)
      elsif STRING_LITERAL_CALLS.include?(node.name) && receiver
        Named.new("String") if literal_constant_type(receiver) == Named.new("String")
      elsif receiver&.slice == "File" && FILE_STRING_CALLS.include?(node.name)
        Named.new("String")
      elsif receiver&.slice == "ENV" && node.name == :fetch
        Named.new("String")
      elsif receiver&.slice == "ENV" && node.name == :[]
        Union.new([Named.new("String"), Named.new("nil")])
      end
    end

    def literal_arithmetic_type(message, left, right)
      numeric = [Named.new("Integer"), Named.new("Float")]
      if numeric.include?(left) && numeric.include?(right)
        [left, right].include?(Named.new("Float")) ? Named.new("Float") : Named.new("Integer")
      elsif left == Named.new("String") && %i[+ *].include?(message)
        Named.new("String")
      end
    end

    def class_factory_call?(node)
      return false unless node.is_a?(Prism::CallNode)

      receiver = node.receiver&.slice
      CLASS_FACTORIES.fetch(node.name, []).include?(receiver) ||
        (node.name == :define && @profile&.entity_define_receiver?(receiver)) || false
    end

    def constant_node?(node)
      node.is_a?(Prism::ConstantReadNode) || node.is_a?(Prism::ConstantPathNode)
    end

    # attr_reader/attr_writer/attr_accessor define real methods, so synthesize
    # entries for them. Their types are tied to the backing instance variable,
    # which lets the solver connect `@foo = ...` in one method to `foo` reads
    # everywhere else.
    def synthesize_attribute_methods(node)
      return unless %i[attr_reader attr_writer attr_accessor].include?(node.name)

      names = Array(node.arguments&.arguments).filter_map do |argument|
        argument.unescaped.to_sym if argument.is_a?(Prism::SymbolNode)
      end
      names.each do |name|
        methods << synthesized_accessor(name, node, writer: false) unless node.name == :attr_writer
        methods << synthesized_accessor(name, node, writer: true) unless node.name == :attr_reader
      end
    end

    def synthesized_accessor(name, node, writer:)
      scope = Object.new
      value = TypeVariable.new(scope, 0, name)
      owner = current_owner
      method_name = writer ? :"#{name}=" : name
      MethodResult.new(
        name: "#{owner}#{@singleton ? "." : "#"}#{method_name}",
        owner: owner,
        kind: @singleton ? :singleton : :instance,
        method_name: method_name,
        superclass: @superclasses[owner],
        line: node.location.start_line,
        end_line: node.location.start_line,
        parameters: writer ? [Parameter.new(name: name, type: value, kind: :required)] : [],
        result: value,
        capabilities: [],
        self_type: TypeVariable.new(scope, 1, "self"),
        ivars: { "@#{name}": value },
        locals: {},
        port_assignments: [],
        case_narrowings: {}
      )
    end

    def within_namespace(name)
      @namespace << name
      yield
    ensure
      @namespace.pop
    end

    def qualified_owner(name)
      (@namespace + [name]).join("::")
    end

    def record_include(node)
      return if @singleton || @namespace.empty?

      owner = current_owner
      Array(node.arguments&.arguments).each do |argument|
        name = constant_argument_slice(argument)
        @includes[owner] << name if name
      end
    end

    def constant_argument_slice(node)
      case node
      when Prism::ConstantReadNode then node.name.to_s
      when Prism::ConstantPathNode then node.slice
      end
    end
  end

  # The analyzer types every constant read as `Class[NAME]`, which is right
  # for classes and modules but not for value constants. Once every file is
  # collected, constants used as values take their value types: recorded
  # literals (`TIMEOUT = 30`, `DEFAULT = PI`), core values (`ENV`), or an
  # unknown for unrecorded SCREAMING_SNAKE names. Direct receivers keep
  # `Class[NAME]` so the solver's class and literal rules still see them.
  class ConstantResolver
    STRING = Named.new("String")
    FLOAT = Named.new("Float")
    CORE_VALUES = {
      "ENV" => Generic.new("Hash", [STRING, STRING]),
      "ARGV" => Generic.new("Array", [STRING]),
      "STDIN" => Named.new("IO"), "STDOUT" => Named.new("IO"), "STDERR" => Named.new("IO"),
      "RUBY_VERSION" => STRING, "RUBY_PLATFORM" => STRING, "RUBY_ENGINE" => STRING,
      "Float::INFINITY" => FLOAT, "Float::NAN" => FLOAT, "Float::EPSILON" => FLOAT,
      "Float::MAX" => FLOAT, "Float::MIN" => FLOAT, "Math::PI" => FLOAT, "Math::E" => FLOAT,
      "File::NULL" => STRING, "File::SEPARATOR" => STRING,
      "Process::CLOCK_MONOTONIC" => Named.new("Integer"), "Process::CLOCK_REALTIME" => Named.new("Integer"),
      "Encoding::UTF_8" => Named.new("Encoding"), "Encoding::BINARY" => Named.new("Encoding")
    }.freeze
    # Single all-caps words (`JSON`, `HTTP`, `SPINNER`) are as often modules
    # as values, so only these two shapes are trusted without a definition.
    VALUE_NAME = /\A[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\z/
    CLASS_NAME = /[a-z]/

    def self.value_name?(name) = VALUE_NAME.match?(name.split("::").last)
    def self.class_name?(name) = CLASS_NAME.match?(name.split("::").last)

    def initialize(constants, namespaces = Set.new)
      @constants = constants
      @namespaces = namespaces
      @values = {}
      @lexical_candidates = {}
      @constant_names = {}
    end

    # Recorded constants with aliases resolved, keyed like the collector's.
    def constants
      @constants.each_key.with_object({}) do |name, values|
        value = recorded_value(name)
        values[name] = value if value
      end
    end

    def resolve(method)
      scope = Object.new
      unknowns = {}
      substitute = lambda do |type|
        substitute_values(type, method.owner) do |name|
          unknowns[name] ||= TypeVariable.new(scope, unknowns.length, name.split("::").last.downcase)
        end
      end
      parameters = method.parameters
      method.with(
        parameters: parameters.empty? ? parameters : parameters.map { |parameter| parameter.with(type: substitute.(parameter.type)) },
        result: substitute.(method.result),
        capabilities: method.capabilities.map do |capability|
          arguments = capability.arguments
          keywords = capability.keywords
          capability.with(
            receiver: constant_name(capability.receiver) ? capability.receiver : substitute.(capability.receiver),
            arguments: arguments.empty? ? arguments : arguments.map(&substitute),
            keywords: keywords.empty? ? keywords : keywords.transform_values(&substitute)
          )
        end,
        ivars: method.ivars.empty? ? method.ivars : method.ivars.transform_values(&substitute),
        locals: method.locals.empty? ? method.locals : method.locals.transform_values(&substitute)
      )
    end

    private

    def substitute_values(type, owner, visiting = nil, &unknown)
      case type
      when Named
        name = constant_name(type)
        (name && value_type(name, owner, visiting, &unknown)) || type
      when Generic
        Generic.new(type.name, type.arguments.map { |inner| substitute_values(inner, owner, visiting, &unknown) })
      when Union
        members = type.members.map { |inner| substitute_values(inner, owner, visiting, &unknown) }
        members = members.flat_map { _1.is_a?(Union) ? _1.members : [_1] }.uniq
        members.length == 1 ? members.first : Union.new(members)
      when Function
        Function.new(
          type.parameters.map { |inner| substitute_values(inner, owner, visiting, &unknown) },
          substitute_values(type.result, owner, visiting, &unknown)
        )
      else
        type
      end
    end

    def value_type(name, owner, visiting, &unknown)
      constant = name.delete_prefix("::")
      lexical_candidates(name, owner).each do |candidate|
        return nil if @namespaces.include?(candidate)
        return recorded_value(candidate, visiting) if @constants.key?(candidate)
      end
      return CORE_VALUES[constant] if CORE_VALUES.key?(constant)

      unknown&.call(constant) if self.class.value_name?(constant)
    end

    # Nearest enclosing namespace first, as Ruby's lexical lookup does.
    def lexical_candidates(name, owner)
      memo = @lexical_candidates[owner] ||= {}
      memo[name] ||= begin
        if name.start_with?("::")
          [name.delete_prefix("::")]
        else
          parts = owner.split("::")
          parts.length.downto(0).map { |length| (parts.first(length) + [name]).join("::") }
        end.freeze
      end
    end

    def recorded_value(qualified, visiting = nil)
      return @values[qualified] if @values.key?(qualified)

      visiting ||= Set.new
      return nil unless visiting.add?(qualified)

      value = substitute_values(@constants[qualified], qualified.rpartition("::").first, visiting)
      visiting.delete(qualified)
      @values[qualified] = constant_name(value) ? nil : value
    end

    def constant_name(type)
      return unless type.is_a?(Named)

      name = type.name
      @constant_names.fetch(name) { @constant_names[name] = name[/\AClass\[(.+)\]\z/, 1].freeze }
    end
  end

  class FixedPointInferencer
    MAX_ITERATIONS = 30
    PREDICATES = %i[
      == != < <= > >= all? any? blank? connected? empty? eql? include?
      is_a? key? member? nil? present? respond_to? start_with? end_with? zero?
    ].to_set.freeze
    INTEGER_RESULTS = %i[count length size bytesize].to_set.freeze
    STRING_RESULTS = %i[
      strip lstrip rstrip chomp chop squeeze tr downcase upcase capitalize
      swapcase gsub sub join to_json encode truncate squish
      strip! chomp! gsub! sub! downcase! upcase! squish!
    ].to_set.freeze
    STRING_LIST_RESULTS = %i[split lines chars].to_set.freeze
    # Rules keyed only by message name that describe instances of core
    # collections and strings.
    INSTANCE_MESSAGES = (
      INTEGER_RESULTS | STRING_RESULTS | STRING_LIST_RESULTS |
      %i[map collect flat_map filter_map each_with_object reduce inject presence
         << clear push append unshift prepend concat sort! uniq! compact! reverse! flatten! map!]
    ).freeze
    ZERO_ARITY_READERS = %i[length size bytesize].to_set.freeze
    NORETURN = Named.new("noreturn")
    NIL = Named.new("nil")

    attr_reader :iterations

    def initialize(methods, constants: {}, includes: {}, metadata: InferenceMetadata.empty)
      # `initialize` is only reachable through `new`, which returns the
      # instance, so its meaningful type is the owner class.
      @methods = methods.map do |method|
        next method unless method.kind == :instance && method.method_name == :initialize

        method.with(result: Named.new(method.owner))
      end
      @index = @methods.to_h { |method| [[method.owner, method.kind, method.method_name], method] }
      @owners = @methods.to_set(&:owner)
      @hierarchy_cache = {}
      @named_owner_cache = {}
      @receiver_targets = {}.compare_by_identity
      @structured_names = {}
      @union_elements = {}
      @constant_literals = {}
      @class_names = {}
      @superclasses = methods.filter_map do |method|
        [method.owner, method.superclass] if method.superclass
      end.to_h
      @constants = constants
      @includes = resolve_includes(includes)
      @metadata = metadata
      @duck_index = Hash.new { |hash, key| hash[key] = [] }
      @methods.each do |method|
        next unless method.kind == :instance && method.method_name != :initialize

        @duck_index[method.method_name] << method
      end
      # Bound variables, in binding order; their count bounds every chain.
      @bound = []
      # Variables compare by identity, so their tables do too.
      @resolved = {}.compare_by_identity
      @dependents = {}.compare_by_identity
      # Skipping settled capabilities (see settled?): who read what, and who
      # is clean as of which generation (with the duck unions it saw).
      @readers = {}.compare_by_identity
      @clean = {}.compare_by_identity
      @generation = 0
      @flushes = 0
      @reads = nil
      @read_buffer = {}.compare_by_identity
      @union_states = {}.compare_by_identity
      @wrote = false
      @tracking_chains = false
      @methods.each do |method|
        mark_rebindable(method.result)
        method.capabilities.each { |capability| mark_rebindable(capability.result) }
      end
      @call_mappings = {}
      @instantiated_parameters = {}
      @instantiated_results = {}
      @result_copies = {}
      @stable_variables = {}
      @fresh_scope = Object.new
      @fresh_id = 0
      @iterations = 0
      @converged = false
      # What the current and previous solving pass bound, and where their
      # minting started (see replayed_pass?).
      @pass_binds = @previous_binds = nil
      @pass_start = @previous_start = 0
      @pass_stable = 0
      @replay_escaped = nil
      @scan = nil
    end

    def run
      apply_declared_annotations!
      anchor_constructor_definitions
      solve_to_fixed_point

      # Newly grounded parameters make more receivers concrete, so another
      # solving round can resolve targets that failed before. The second
      # round lets values flow through one level of indirection (caller ->
      # factory -> constructor).
      2.times do
        flow_call_arguments!
        flow_structural_arguments!
        solve_to_fixed_point
      end

      apply_late_send_defaults!
      apply_definition_conventions!
      narrow_residual_returns!
      unify_instance_variables
      solve_to_fixed_point
      apply_intra_method_param_flow!
      apply_chained_send_narrowing!
      apply_block_argument_callee_flow!
      flow_call_arguments!
      solve_to_fixed_point
      reflow_callee_returns!
      solve_to_fixed_point
      apply_mutator_return_nil!
      apply_forced_return_conventions!
      @methods.map { |method| resolved_method(method) }
    ensure
      @bound.each { |variable| variable.link = nil }
      @bound.clear
    end

    def converged? = @converged

    def apply_declared_annotations!
      apply_declared_member_types!
      apply_factory_param_bindings!
      apply_case_branch_narrowing!
      apply_core_member_type_conventions!
      apply_initialize_param_bindings!
      apply_port_handler_wiring! if @metadata.port_wiring?
      apply_output_emit_wiring! if @metadata.output_emit?
      apply_config_hash_wiring! if @metadata.config_hash?
    end

    def apply_core_member_type_conventions!
      CORE_MEMBER_NAME_TYPES.each do |member, type_name|
        type = Named.new(type_name)
        @duck_index[member].each do |accessor|
          unify(accessor.result, type)
          # Only the backing ivar: `def size = @items.length` says nothing
          # about `@items`.
          ivar = accessor.ivars[:"@#{member}"]
          unify(ivar, type) if ivar
        end
      end
    end

    def apply_initialize_param_bindings!
      @methods.each do |method|
        next unless method.kind == :instance && method.method_name == :initialize

        method.parameters.each do |parameter|
          ivar = method.ivars[:"@#{parameter.name}"]
          unify(parameter.type, ivar) if ivar
        end
      end
    end

    def apply_declared_member_types!
      @metadata.member_types.each do |owner, fields|
        fields.each do |member, type|
          accessor = @index[[owner, :instance, member]]
          next unless accessor

          unify(accessor.result, type)
          accessor.ivars.each_value { |ivar| unify(ivar, type) }
        end
      end
    end

    def apply_factory_param_bindings!
      @metadata.member_types.each do |owner, fields|
        %i[create new].each do |method_name|
          factory = @index[[owner, :singleton, method_name]]
          next unless factory

          factory.parameters.each do |parameter|
            next unless %i[keyword optional_keyword].include?(parameter.kind)

            type = fields[parameter.name]
            unify(parameter.type, type) if type
          end
        end
      end
    end

    def apply_case_branch_narrowing!
      @methods.each do |method|
        method.case_narrowings.each do |name, types|
          parameter = method.parameters.find { |candidate| candidate.name == name }
          next unless parameter

          merged = merge_unions(types)
          unify(parameter.type, merged) if merged
        end
      end
    end

    def apply_port_handler_wiring!
      wiring = @metadata.port_wiring
      @metadata.ports.each do |owner, ports|
        inputs = ports[:inputs]
        next if inputs.empty?

        handler = @index[[owner, :instance, wiring.handler_method]]
        next unless handler

        entity_param = handler_entity_param(handler, wiring.entity_param)
        dispatch_param = handler.parameters.find do |parameter|
          parameter.name == wiring.dispatch_param &&
            %i[keyword optional_keyword].include?(parameter.kind)
        end

        if entity_param
          entity_type = port_type_for_param(entity_param.name, inputs)
          unify(entity_param.type, entity_type) if entity_type
        end

        unify(dispatch_param.type, wiring.dispatch_param_type) if dispatch_param
      end
      apply_port_assignments!
    end

    def handler_entity_param(handler, selector)
      case selector
      when :first_required
        handler.parameters.find { |parameter| parameter.kind == :required }
      when Symbol
        handler.parameters.find { |parameter| parameter.name == selector }
      end
    end

    def apply_output_emit_wiring!
      wiring = @metadata.output_emit
      methods_by_owner = @methods.group_by(&:owner)
      @metadata.ports.each do |owner, ports|
        outputs = ports[:outputs]
        next if outputs.empty?

        methods_by_owner.fetch(owner, []).each do |method|
          method.capabilities.each do |capability|
            next unless capability.message == wiring.message
            next unless capability.receiver == method.self_type

            port_key = literal_symbol_key(capability.keywords[wiring.port_keyword])
            next unless port_key

            output_type = outputs[port_key]
            next unless output_type

            payload = capability.arguments[wiring.argument_index]
            unify(payload, output_type) if payload
          end
        end
      end
    end

    def port_type_for_param(param_name, inputs)
      return inputs.values.first if inputs.length == 1

      matched = inputs.find { |port_name, _| param_matches_port?(param_name, port_name) }
      return matched.last if matched

      members = inputs.values.uniq
      members.length == 1 ? members.first : Union.new(members)
    end

    def param_matches_port?(param_name, port_name)
      param = param_name.to_s
      port = port_name.to_s
      return true if param == port
      return true if port == "#{param}s" || port == "#{param}es"
      return true if port.end_with?("_#{param}") || port.start_with?("#{param}_")

      false
    end

    def apply_port_assignments!
      @methods.each do |method|
        next if method.port_assignments.empty?

        ports = @metadata.ports.dig(method.owner, :inputs) || {}
        method.port_assignments.each do |assignment|
          port_type = ports[assignment.fetch(:port)]
          next unless port_type

          param = method.parameters.find { |parameter| parameter.name == assignment.fetch(:param) }
          unify(param.type, port_type) if param

          ivar = method.ivars[assignment.fetch(:ivar)]
          unify(ivar, port_type) if assignment.fetch(:ivar) && ivar
        end
      end
    end

    def apply_config_hash_wiring!
      wiring = @metadata.config_hash
      @metadata.config_options.each do |owner, options|
        next if options.empty?

        init = @index[[owner, :instance, :initialize]]
        next unless init

        config_param = init.parameters.find { |parameter| parameter.name == wiring.init_param }
        next unless config_param

        value_type = options.values.uniq
        value_type = value_type.length == 1 ? value_type.first : Union.new(value_type)
        unify(config_param.type, Generic.new("Hash", [Named.new("Symbol"), value_type]))
      end

      @methods.each do |method|
        options = @metadata.config_options[method.owner]
        next unless options

        method.capabilities.each do |capability|
          next unless %i[fetch [] dig].include?(capability.message)
          next unless config_hash_receiver?(method, capability.receiver, wiring)

          key = literal_symbol_key(capability.arguments.first)
          next unless key

          option_type = options[key]
          unify(capability.result, option_type) if option_type
        end
      end
    end

    def config_hash_receiver?(method, receiver, wiring)
      terminal = dereference(resolve(receiver))
      return true if terminal == Named.new("Hash")

      method.ivars.key?(wiring.ivar) && dereference(method.ivars[wiring.ivar]) == terminal
    end

    def literal_symbol_key(key)
      case key
      when Named then key.name.to_sym
      end
    end

    def literal_hash_key?(hash_type, key)
      literal_key = literal_symbol_key(key) || literal_integer_key(key)
      return false unless literal_key

      case hash_type
      when Generic
        return false unless hash?(hash_type)

        key_type = dereference(hash_type.arguments[0])
        case key_type
        when Named then key_type.name == "Symbol" || key_type.name == "Integer"
        else false
        end
      when Union
        hash_type.members.any? { |member| literal_hash_key?(member, key) }
      else
        false
      end
    end

    def literal_integer_key(key)
      case key
      when Named
        return key.name.to_i if key.name.match?(/\A-?\d+\z/)

        nil
      end
    end

    def literal_key_name(key)
      case key
      when Named
        return key.name unless RESERVED_TYPE_NAMES.include?(key.name)

        nil
      end
    end

    def core_member_type_for_key(key_arg)
      name = literal_key_name(key_arg)&.to_sym
      return unless name

      if (type_name = CORE_MEMBER_NAME_TYPES[name])
        return Named.new(type_name)
      end

      @metadata.member_type_hints[name]
    end

    def hash_new_block_value_type(block)
      resolved = resolve(block.result)
      return resolved if hash?(resolved) || array?(resolved)
      return resolved if ground?(resolved) && !resolved.is_a?(Named)

      nil
    end

    def unify_hash_key_argument!(hash_type, key_arg)
      return unless hash?(hash_type)

      terminal = dereference(key_arg)
      case terminal
      when Named
        if terminal.name == "Integer" || terminal.name == "Symbol"
          unify(hash_type.arguments[0], terminal)
        elsif terminal.name.match?(/\A-?\d+\z/)
          unify(hash_type.arguments[0], Named.new("Integer"))
        elsif literal_symbol_key(terminal)
          unify(hash_type.arguments[0], Named.new("Symbol"))
        end
      end
    end

    def hash_key_type_compatible?(hash_type, key_arg)
      case hash_type
      when Generic
        return false unless hash?(hash_type)

        dereference(hash_type.arguments[0]) == dereference(key_arg)
      when Union
        hash_type.members.any? { |member| hash_key_type_compatible?(member, key_arg) }
      else
        false
      end
    end

    def hash_dig_type(hash_type, keys)
      current = hash_type
      keys.each do |key|
        return nil unless hash?(current)

        if literal_hash_key?(current, key) || hash_key_type_compatible?(current, key)
          current = current.arguments[1]
        else
          current = current.arguments[1]
        end
      end
      current
    end

    def structured_type?(type, _method)
      terminal = dereference(type)
      return false unless terminal.is_a?(Named)

      structured_owner?(terminal.name)
    end

    # The metadata stays fixed while solving.
    def structured_name?(name)
      @structured_names.fetch(name) { @structured_names[name] = @metadata.structured_type?(name) }
    end

    def structured_owner?(owner)
      return true if structured_name?(owner)

      init = @index[[owner, :instance, :initialize]]
      return false unless init

      init.parameters.any? do |parameter|
        %i[keyword optional_keyword].include?(parameter.kind) &&
          (parameter.name == :id || @metadata.member_type_hints.key?(parameter.name))
      end
    end

    def structured_owner_name(type)
      terminal = dereference(type)
      terminal.is_a?(Named) && structured_owner?(terminal.name) ? terminal.name : nil
    end

    def entity_hash_type(owner)
      fields = @metadata.member_types[owner]
      if fields.nil? || fields.empty?
        return Generic.new("Hash", [Named.new("String"), Named.new("Object")])
      end

      value_type = merge_unions(fields.values)
      Generic.new("Hash", [Named.new("String"), value_type])
    end

    private

    def solve_to_fixed_point
      next_replay_check = 1
      replay_misses = 0
      @scan = scan_order
      MAX_ITERATIONS.times do |iteration|
        @changed = false
        @duck_cache = {}
        @previous_binds = @pass_binds
        @previous_start = @pass_start
        @pass_binds = []
        @pass_start = @fresh_id
        @pass_stable = @stable_variables.size
        if @scan
          scan_pass(@scan)
        else
          @methods.each do |method|
            method.capabilities.each do |capability|
              evaluate_tracked(method, capability) unless settled?(capability)
            end
          end
        end
        @iterations = iteration + 1
        unless @changed
          @converged = true
          break
        end
        next if iteration < next_replay_check

        case replayed_pass?
        when true
          # Every remaining pass would replay this one, binding again, so
          # the loop would only have stopped at the cap.
          @iterations = MAX_ITERATIONS
          break
        when :mismatch
          replay_misses += 1
          next_replay_check = iteration + (1 << replay_misses)
        end
      end
    ensure
      @pass_binds = @previous_binds = nil
      @scan = nil
    end

    # A pass visits capabilities in method order and evaluates the unsettled
    # ones. Skipping one that is clean as of this generation changes nothing
    # (settled? only has effects for duck observations), so after a full
    # sweep a pass only visits, in the same order, the capabilities that
    # were not clean after their last visit or were unsettled since.
    Scan = Struct.new(:capabilities, :methods, :positions, :current, :full, :pending, :queue, :extra)

    # Capabilities only change between solving rounds. One listed twice
    # shares its clean state between its positions, which a scan by
    # position does not track.
    def scan_order
      capabilities = []
      methods = []
      @methods.each do |method|
        method.capabilities.each do |capability|
          capabilities << capability
          methods << method
        end
      end
      positions = {}.compare_by_identity
      capabilities.each_with_index { |capability, position| positions[capability] = position }
      return unless positions.size == capabilities.size

      Scan.new(capabilities, methods, positions, -1, true, [], [], [])
    end

    def scan_pass(scan)
      if scan.full
        scan.pending.clear
        sweep(scan, 0)
      else
        queue = scan.queue.replace(scan.pending.sort!.uniq)
        scan.pending.clear
        generation = @generation
        last = -1
        index = 0
        extra = scan.extra
        while index < queue.length || !extra.empty?
          if extra.empty? || (index < queue.length && queue[index] < extra.first)
            position = queue[index]
            index += 1
          else
            position = heap_pop(extra)
          end
          next if position <= last

          last = position
          visit(scan, position)
          next if @generation == generation

          # Every clean capability went stale: sweep the rest of the pass.
          extra.clear
          sweep(scan, position + 1)
          scan.full = true
          break
        end
      end
      scan.current = -1
    end

    def sweep(scan, from)
      scan.full = true
      generation = @generation
      position = from
      length = scan.capabilities.length
      while position < length
        visit(scan, position)
        position += 1
      end
      scan.full = @generation != generation
    end

    def visit(scan, position)
      scan.current = position
      capability = scan.capabilities[position]
      evaluate_tracked(scan.methods[position], capability) unless settled?(capability)
      clean = @clean[capability]
      scan.pending << position unless clean.instance_of?(Integer) && clean == @generation
    end

    # During a pass, a capability unsettled ahead of the scan is visited
    # in this pass, and one behind it (or the one being evaluated) in the
    # next.
    def unsettle(capability)
      @clean.delete(capability)
      scan = @scan
      return unless scan

      position = scan.positions[capability]
      return unless position

      if position <= scan.current
        scan.pending << position
      elsif !scan.full
        heap_push(scan.extra, position)
      end
    end

    def heap_push(heap, value)
      index = heap.length
      heap << value
      while index.positive?
        parent = (index - 1) >> 1
        break if heap[parent] <= value

        heap[index] = heap[parent]
        index = parent
      end
      heap[index] = value
    end

    def heap_pop(heap)
      top = heap.first
      last = heap.pop
      return top if heap.empty?

      index = 0
      length = heap.length
      loop do
        child = (2 * index) + 1
        break if child >= length

        child += 1 if child + 1 < length && heap[child + 1] < heap[child]
        break if heap[child] >= last

        heap[index] = heap[child]
        index = child
      end
      heap[index] = last
      top
    end

    # Call cycles keep minting copies of copies, so a pass can bind again
    # without telling the solver anything new: it only moves unbound ends
    # onto variables it minted. Solving reads the state through resolved
    # types, mapping lookups, and stable variables, never through variable
    # identities beyond equality (see replayed_mappings? for the caches), so
    # a pass from a state equal to the previous one up to renaming does the
    # same, renamed. This holds when every older variable the pass bound now
    # ends at its own unbound variable minted by the pass, and the call
    # mappings it extended correspond to the ones it retired; then every
    # later pass replays it and the final state, rendered by identity, is
    # this one renamed. Rebindable variables keep their place on chains (see
    # compress_path) and get rebound later, so they must not move at all;
    # analyzer variables must not either, since rendering compares solved
    # types against them.
    def replayed_pass?
      return false unless @stable_variables.size == @pass_stable

      images = {}.compare_by_identity
      preimages = {}.compare_by_identity
      binds = @pass_binds
      index = 0
      while index < binds.length
        variable = binds[index]
        index += 2
        next if pass_mint?(variable)
        return false unless variable.scope.equal?(@fresh_scope) && !variable.rebindable

        image = replay_end(variable)
        return false unless image.is_a?(TypeVariable) && pass_mint?(image)
        return false if image.link || preimages.key?(image)

        images[variable] = image
        preimages[image] = variable
      end
      replayed_mappings?(images, preimages) || :mismatch
    end

    # Mapping entries are only looked up by unbound variables, so an entry
    # whose key the pass bound is retired and must reappear under the key's
    # image with a copy that resolves alike; any other entry the pass added
    # has no counterpart. The instantiation caches memoize these mappings
    # and are skipped. Retired copies nothing ever bound into the state
    # (see renamed_copy?) need not stay equal: they are out of reach.
    def replayed_mappings?(images, preimages)
      renaming = [{}.compare_by_identity, {}.compare_by_identity]
      @call_mappings.each_value do |mapping|
        mapping.each do |key, copy|
          if (image = images[key])
            next if pass_mint?(copy)

            replacement = mapping[image]
            return false unless replacement && replayed_copy?(replacement, copy, preimages, renaming)
          elsif pass_mint?(copy) && !key.link
            original = preimages[key]
            return false unless original && (retired = mapping[original]) && !pass_mint?(retired)
          end
        end
      end
      true
    ensure
      @replay_escaped = nil
    end

    REPLAY_MATCH_BUDGET = 10_000

    # Walks both copies' bound structure in step. Chains are followed to
    # their end or first rebindable variable, which both must share.
    # renaming holds the stand-ins chosen so far, both ways.
    def replayed_copy?(replacement, retired, preimages, renaming)
      stack = [replacement, retired]
      budget = REPLAY_MATCH_BUDGET
      until stack.empty?
        old = stack.pop
        new = stack.pop
        return false if (budget -= 1).negative?
        next if new.equal?(old)

        new = replay_end(new)
        old = replay_end(old)
        next if new.equal?(old)

        case new
        when TypeVariable
          return false unless old.is_a?(TypeVariable) && renamed_copy?(new, old, preimages, renaming)
        when Generic
          return false unless old.is_a?(Generic) && old.name == new.name && old.arguments.length == new.arguments.length

          new.arguments.each_with_index { |argument, position| stack << argument << old.arguments[position] }
        when Union
          return false unless old.is_a?(Union) && old.members.length == new.members.length

          new.members.each_with_index { |member, position| stack << member << old.members[position] }
        when Function
          return false unless old.is_a?(Function) && old.parameters.length == new.parameters.length

          new.parameters.each_with_index { |parameter, position| stack << parameter << old.parameters[position] }
          stack << new.result << old.result
        else
          return false unless new == old
        end
      end
      true
    end

    # A copy minted last pass that no bind ever referenced is reachable only
    # through its own mapping entry; once that entry retires, a new unbound
    # copy may stand in for it, one for one.
    def renamed_copy?(new, old, preimages, renaming)
      forward, backward = renaming
      return forward[new].equal?(old) if forward.key?(new)
      return false if new.rebindable || old.rebindable
      return false if new.link || old.link
      return false unless pass_mint?(new) && !preimages.key?(new) && previous_pass_mint?(old)
      return false if backward.key?(old) || replay_escaped.key?(old)

      forward[new] = old
      backward[old] = new
    end

    def replay_escaped
      @replay_escaped ||= begin
        referenced = {}.compare_by_identity
        stack = []
        [@previous_binds, @pass_binds].each do |binds|
          index = 1
          while index < binds.length
            stack << binds[index]
            index += 2
          end
        end
        until stack.empty?
          node = stack.pop
          case node
          when TypeVariable then referenced[node] = true
          when Generic then stack.concat(node.arguments)
          when Union then stack.concat(node.members)
          when Function then stack.concat(node.parameters) << node.result
          end
        end
        referenced
      end
    end

    def replay_end(type)
      steps = 0
      while type.is_a?(TypeVariable) && !type.rebindable && (bound = type.link)
        return type if (steps += 1) > @bound.size

        type = bound
      end
      type
    end

    def pass_mint?(variable)
      variable.scope.equal?(@fresh_scope) && variable.id >= @pass_start
    end

    def previous_pass_mint?(variable)
      variable.scope.equal?(@fresh_scope) && variable.id >= @previous_start && variable.id < @pass_start
    end

    # Evaluating a capability is deterministic in the state it reads. One
    # whose last evaluation wrote nothing, and nothing it read has changed
    # since, would write nothing again, so skipping it leaves every pass's
    # sequence of bindings exactly as a full sweep makes it.
    def settled?(capability)
      clean = @clean[capability]
      return clean == @generation unless clean.instance_of?(DuckClean)
      return false unless clean.generation == @generation

      # The duck cache is rebuilt each pass on first use, so its entries are
      # fetched here, where this capability would have asked for them.
      clean.observations.all? { |message, union| duck_union(message) == union }
    end

    # A clean capability's generation, with the duck unions it saw if any.
    DuckClean = Struct.new(:generation, :observations)

    # Clearing a hash costs its peak capacity, so a buffer that one
    # evaluation grew is replaced rather than cleared for every later one.
    READ_BUFFER_LIMIT = 64

    def evaluate_tracked(method, capability)
      buffer = @read_buffer
      @reads = buffer.size > READ_BUFFER_LIMIT ? (@read_buffer = {}.compare_by_identity) : buffer.clear
      @duck_seen = nil
      @wrote = false
      evaluate(method, capability)
      reads = @reads
      @reads = nil
      if @wrote
        @clean.delete(capability)
      else
        @clean[capability] = @duck_seen ? DuckClean.new(@generation, @duck_seen) : @generation
        readers = @readers
        reads.each_key do |source|
          list = readers[source]
          if list.nil?
            readers[source] = capability
          elsif list.instance_of?(Array)
            list << capability unless list.last.equal?(capability)
          elsif !list.equal?(capability)
            readers[source] = [list, capability]
          end
        end
      end
    end

    def evaluate(method, capability)
      apply_builtin(method, capability)
      # Anchor before resolving the target so a delegating `new`
      # override cannot flood the call site with unresolved variables.
      apply_constructor(method, capability)
      target = resolve_target(method, capability)
      if target
        apply_method_call(method, capability, target)
      elsif !apply_union_member_dispatch(method, capability)
        apply_duck_dispatch(method, capability)
        apply_fallback(method, capability)
      end
    end

    # Singleton `new`/`create` definitions return an instance of their owner,
    # whatever their bodies delegate to.
    def anchor_constructor_definitions
      @methods.each do |method|
        next unless method.kind == :singleton && %i[new create].include?(method.method_name)

        anchor = Named.new(method.owner)
        branches = method.result.is_a?(Union) ? method.result.members : [method.result]
        branches.each { |branch| unify(branch, anchor) }
      end
    end

    def unify_instance_variables
      groups = Hash.new { |hash, key| hash[key] = [] }
      @methods.each do |method|
        method.ivars.each { |name, type| groups[[method.owner, name]] << type }
      end

      groups.each_value do |types|
        observed = types.filter_map do |type|
          resolved = resolve(type)
          resolved unless resolved.is_a?(TypeVariable)
        end
        merged = merge_unions(observed)
        next unless merged

        types.each do |type|
          terminal = dereference(type)
          unify(terminal, merged) if terminal.is_a?(TypeVariable)
        end
      end
    end

    def apply_builtin(method, capability)
      receiver = unwrap_nilable(resolve(capability.receiver))
      message = capability.message
      result = capability.result

      if (constant = class_name_from(receiver))
        # Constant reads look like class references; when the constant is
        # actually a typed literal (regex, hash table, word list), sends on
        # it are sends on the literal.
        literal = constant_literal(constant, method.owner)
        if literal
          receiver = literal
        else
          apply_class_builtin(constant, capability)
          receiver = ConstantResolver::CORE_VALUES.fetch(constant, receiver)
        end
      end
      return if INSTANCE_MESSAGES.include?(message) && !instance_rules_apply?(method, capability, receiver)

      if PREDICATES.include?(message)
        unify(result, Named.new("bool"))
      elsif INTEGER_RESULTS.include?(message)
        unify(result, Named.new("Integer"))
      elsif STRING_RESULTS.include?(message)
        unify(result, Named.new("String"))
      elsif STRING_LIST_RESULTS.include?(message)
        unify(result, Generic.new("Array", [Named.new("String")]))
      end

      case message
      when :to_s, :inspect, :String
        unify(result, Named.new("String"))
      when :to_i, :ord, :Integer
        unify(result, Named.new("Integer"))
      when :to_f, :Float
        unify(result, Named.new("Float"))
      when :to_sym
        unify(result, Named.new("Symbol"))
      when :!
        unify(result, Named.new("bool"))
      when :raise, :throw
        unify(result, NORETURN)
      when :puts, :print
        unify(result, Named.new("nil"))
      when :emit, :close_input_queues!, :release_optional_inputs!, :close_input_port!
        unify(result, Named.new("nil")) if capability.keywords.key?(:to) || %i[close_input_queues! release_optional_inputs! close_input_port!].include?(message)
      when :debug, :info, :warn, :error, :fatal
        unify(result, Named.new("nil")) if receiver == Named.new("Logger")
      when :logger
        unify(result, Named.new("Logger"))
      when :tap, :itself, :dup, :clone, :freeze, :deep_dup, :with
        unify(result, receiver)
      when :synchronize
        block = capability.arguments.last
        unify(result, block.result) if receiver == Named.new("Mutex") && block.is_a?(Function)
      when :clock_gettime
        unify(result, Named.new("Float"))
      when :then, :yield_self
        block = capability.arguments.last
        unify(result, block.result) if block.is_a?(Function)
      when :presence
        unify(result, Union.new([receiver, Named.new("nil")].uniq)) unless receiver == Named.new("nil")
      when :new, :create
        class_name = class_name_from(receiver)
        if class_name == "Hash"
          block = capability.arguments.find { |argument| argument.is_a?(Function) }
          if block
            key_type = block.parameters[1] || stable_fresh([capability.object_id, :hash_key], "key")
            value_type = hash_new_block_value_type(block) || block.result
            unify(result, Generic.new("Hash", [key_type, value_type]))
          else
            unify(result, Named.new("Hash"))
          end
        elsif class_name
          unify(result, Named.new(class_name))
        end
      when :Array
        argument = capability.arguments.first || stable_fresh([capability.object_id, :array_element], "element")
        element = array_element(resolve(argument)) || resolve(argument)
        unify(result, Generic.new("Array", [element]))
      when :flatten
        element = array_element(receiver)
        if element
          flattened = array_element(element) || element
          unify(result, Generic.new("Array", [flattened]))
        end
      when :take, :uniq, :sort, :sort_by, :reverse,
           :drop, :take_while, :drop_while, :shuffle, :rotate, :to_a
        unify(result, receiver) if receiver.is_a?(Generic) && receiver.name == "Array"
      when :reject, :select, :filter, :find_all, :grep, :index_by
        apply_enumerable_block(receiver, capability, result, mode: :same_collection)
      when :compact, :compact!
        element = array_element(receiver)
        if element
          unify(result, Generic.new("Array", [strip_nil(element)]))
        elsif hash?(receiver)
          unify(result, Generic.new("Hash", [receiver.arguments[0], strip_nil(receiver.arguments[1])]))
        end
      when :to_set
        element = enumerable_element(receiver)
        unify(result, Generic.new("Set", [element])) if element
      when :<<, :push, :append, :unshift, :prepend
        if array?(receiver)
          capability.arguments.each do |argument|
            unify_array_elements(receiver, argument) unless argument.is_a?(Function)
          end
          unify(result, receiver)
        elsif receiver == Named.new("String")
          unify(result, receiver)
        end
      when :concat
        if array?(receiver)
          capability.arguments.each do |argument|
            unify(receiver, argument) unless argument.is_a?(Function)
          end
          unify(result, receiver)
        elsif receiver == Named.new("String")
          unify(result, receiver)
        end
      when :+, :-, :*, :/, :%, :**
        if receiver.is_a?(Named) && %w[Integer Float String].include?(receiver.name)
          unify(result, receiver)
        elsif array?(receiver) && %i[+ -].include?(message)
          unify(result, receiver)
        end
      when :first, :last, :min, :max, :find, :detect, :sample
        element = enumerable_element(receiver)
        unify(result, Union.new([element, Named.new("nil")])) if element
      when :sum
        element = enumerable_element(receiver)
        unify(result, element) if element.is_a?(Named) && %w[Integer Float].include?(element.name)
      when :map, :collect
        element = enumerable_element(receiver)
        block = capability.arguments.last
        if block.is_a?(Function)
          unify(block.parameters.first, element) if element && block.parameters.first
          unify(result, Generic.new("Array", [block.result]))
        elsif element
          unify(result, Generic.new("Enumerator", [element]))
        end
      when :flat_map
        block = capability.arguments.last
        if block.is_a?(Function)
          element = enumerable_element(receiver)
          unify(block.parameters.first, element) if element && block.parameters.first
          inner = resolve(block.result)
          unify(result, Generic.new("Array", [array_element(inner) || inner]))
        end
      when :filter_map
        block = capability.arguments.last
        unify(result, Generic.new("Array", [strip_nil(resolve(block.result))])) if block.is_a?(Function)
      when :each_with_object
        memo = capability.arguments.find { |argument| !argument.is_a?(Function) }
        block = capability.arguments.last
        if block.is_a?(Function)
          element = enumerable_element(receiver)
          unify(block.parameters[0], element) if element && block.parameters[0]
          unify(block.parameters[1], memo) if memo && block.parameters[1]
        end
        unify(result, memo) if memo
      when :reduce, :inject
        block = capability.arguments.last
        unify(result, block.result) if block.is_a?(Function)
      when :keys
        unify(result, Generic.new("Array", [receiver.arguments[0]])) if hash?(receiver)
      when :values
        unify(result, Generic.new("Array", [receiver.arguments[1]])) if hash?(receiver)
      when :to_h, :to_hash
        if (owner = structured_owner_name(receiver))
          unify(result, entity_hash_type(owner))
        elsif receiver.is_a?(Union)
          hash_types = receiver.members.filter_map { |member| structured_owner_name(member) }.map { |name| entity_hash_type(name) }
          unify(result, merge_unions(hash_types)) if hash_types.any?
        elsif structured_owner?(method.owner) || structured_type?(receiver, method)
          unify(result, entity_hash_type(method.owner))
        elsif hash?(receiver)
          unify(result, receiver)
        end
      when :deep_stringify_keys, :stringify_keys
        if hash?(receiver)
          unify(result, Generic.new("Hash", [Named.new("String"), receiver.arguments[1]]))
        end
      when :merge, :merge!, :except, :slice, :with_indifferent_access, :deep_symbolize_keys, :symbolize_keys
        unify(result, receiver) if hash?(receiver)
      when :transform_values
        block = capability.arguments.last
        if hash?(receiver) && block.is_a?(Function)
          unify(block.parameters.first, receiver.arguments[1]) if block.parameters.first
          unify(result, Generic.new("Hash", [receiver.arguments[0], block.result]))
        end
      when :transform_keys
        block = capability.arguments.last
        if hash?(receiver) && block.is_a?(Function)
          unify(block.parameters.first, receiver.arguments[0]) if block.parameters.first
          unify(result, Generic.new("Hash", [block.result, receiver.arguments[1]]))
        end
      when :each_value
        if hash?(receiver)
          block = capability.arguments.last
          unify(block.parameters.first, receiver.arguments[1]) if block.is_a?(Function) && block.parameters.first
          unify(result, receiver)
        end
      when :each_key
        if hash?(receiver)
          block = capability.arguments.last
          unify(block.parameters.first, receiver.arguments[0]) if block.is_a?(Function) && block.parameters.first
          unify(result, receiver)
        end
      when :fetch
        if hash?(receiver)
          if (option_type = config_option_type(method, capability.arguments.first))
            unify(result, option_type)
          else
            unify(result, receiver.arguments[1])
          end
        elsif array?(receiver)
          unify(result, array_element(receiver))
        end
      when :delete
        if hash?(receiver)
          key_arg = capability.arguments.first
          unify(result, receiver.arguments[1])
          unify_hash_key_argument!(receiver, key_arg)
        end
      when :[]
        if hash?(receiver)
          key_arg = capability.arguments.first
          if (member_type = core_member_type_for_key(key_arg))
            unify(result, member_type)
          elsif (option_type = config_option_type(method, key_arg))
            unify(result, option_type)
          elsif literal_hash_key?(receiver, key_arg) || hash_key_type_compatible?(receiver, key_arg)
            unify(result, receiver.arguments[1])
          else
            unify(result, Union.new([receiver.arguments[1], Named.new("nil")]))
          end
          unify_hash_key_argument!(receiver, key_arg)
        elsif array?(receiver)
          unify(result, Union.new([array_element(receiver), Named.new("nil")]))
        elsif dereference(capability.receiver).is_a?(TypeVariable)
          key_arg = capability.arguments.first
          member_type = core_member_type_for_key(key_arg)
          unify(result, member_type) if member_type
        elsif receiver == Named.new("String") || receiver == Named.new("MatchData")
          unify(result, Union.new([Named.new("String"), Named.new("nil")]))
        end
      when :dig
        if hash?(receiver)
          dug = hash_dig_type(receiver, capability.arguments)
          if dug
            unify(result, Union.new([dug, Named.new("nil")]))
          elsif (option_type = config_option_type(method, capability.arguments.first))
            unify(result, option_type)
          else
            unify(result, Union.new([receiver.arguments[1], Named.new("nil")]))
          end
        elsif array?(receiver)
          unify(result, Union.new([array_element(receiver), Named.new("nil")]))
        end
      when :class
        case receiver
        when Generic
          unify(result, Named.new("Class[#{receiver.name}]"))
        when Named
          if receiver.name.start_with?("Class[") || %w[nil bool noreturn].include?(receiver.name)
            unify(result, Named.new("Class"))
          else
            unify(result, Named.new("Class[#{receiver.name}]"))
          end
        end
      when :name
        if receiver.is_a?(Named) && (receiver.name == "Class" || receiver.name.start_with?("Class["))
          unify(result, Named.new("String"))
        end
      when :message, :full_message
        unify(result, Named.new("String")) if exception_type?(receiver)
      when :backtrace
        if exception_type?(receiver)
          unify(result, Union.new([Generic.new("Array", [Named.new("String")]), Named.new("nil")]))
        end
      when :match
        if [Named.new("Regexp"), Named.new("String")].include?(receiver)
          unify(result, Union.new([Named.new("MatchData"), Named.new("nil")]))
        end
      when :"=~"
        if [Named.new("Regexp"), Named.new("String")].include?(receiver)
          unify(result, Union.new([Named.new("Integer"), Named.new("nil")]))
        end
      when :source
        unify(result, Named.new("String")) if receiver == Named.new("Regexp")
      when :[]=
        if hash?(receiver) && capability.arguments.length >= 2
          unify(receiver.arguments[0], capability.arguments[0])
          unify(receiver.arguments[1], capability.arguments[1])
        elsif array?(receiver) && capability.arguments.length >= 2
          unify(array_element(receiver), capability.arguments.last)
        end
        unify(result, capability.arguments.last) unless capability.arguments.empty?
      when :with_index
        apply_indexed_enumeration(receiver, capability, result)
      when :each, :each_with_index
        apply_each(receiver, capability, result, indexed: message == :each_with_index)
      end

      # Methods that return their receiver regardless of its type: tying the
      # two variables lets either side ground the other.
      if SELF_RETURNING.include?(message) && dereference(result).is_a?(TypeVariable)
        unify(result, capability.receiver)
      end
    end

    # Name-keyed instance rules are guesses about core types. A class
    # receiver (`Constraint.length(n)`), a non-stdlib arity (`size(n)`), or a
    # repository definition for the receiver means the guess is about the
    # wrong method.
    def instance_rules_apply?(method, capability, receiver)
      class_name = class_name_from(receiver)
      return false if class_name && ConstantResolver.class_name?(class_name)
      if ZERO_ARITY_READERS.include?(capability.message) &&
         (capability.arguments.any? { !_1.is_a?(Function) } || capability.keywords.any?)
        return false
      end

      resolve_target(method, capability).nil?
    end

    SELF_RETURNING = %i[
      each each_with_index each_entry tap dup clone freeze itself
      << clear push append unshift prepend concat
      sort! uniq! compact! reverse! flatten! map!
    ].to_set.freeze

    def exception_type?(type)
      type.is_a?(Named) &&
        (type.name == "StandardError" || type.name.end_with?("Error", "Exception"))
    end

    # Last-resort defaults for sends whose result survived every solving
    # pass: `.class` is always a Class, key-conversion methods always yield
    # hashes, `round` is numeric.
    def apply_late_send_defaults!
      @methods.each do |method|
        method.capabilities.each do |capability|
          next unless dereference(capability.result).is_a?(TypeVariable)

          case capability.message
          when :class
            unify(capability.result, Named.new("Class"))
          when :round, :ceil, :floor
            unify(capability.result, capability.arguments.empty? ? Named.new("Integer") : Named.new("Float"))
          when :abs
            unify(capability.result, Named.new("Numeric"))
          when :deep_symbolize_keys, :symbolize_keys
            value = stable_fresh([capability.object_id, :hash_value], "value")
            unify(capability.result, Generic.new("Hash", [Named.new("Symbol"), value]))
          when :deep_stringify_keys, :stringify_keys, :with_indifferent_access, :to_unsafe_h
            value = stable_fresh([capability.object_id, :hash_value], "value")
            unify(capability.result, Generic.new("Hash", [Named.new("String"), value]))
          end
        end
      end
    end

    # Library classes outside the repo with well-known return types.
    def apply_class_builtin(constant, capability)
      result = capability.result
      message = capability.message
      case constant
      when "Time", "DateTime", "Date"
        unify(result, Named.new(constant)) if %i[now at parse current zone today].include?(message)
      when "Process"
        unify(result, Named.new("Float")) if message == :clock_gettime
      when "ENV"
        case message
        when :[] then unify(result, Union.new([Named.new("String"), Named.new("nil")]))
        when :fetch then unify(result, Named.new("String"))
        end
      when "JSON", "YAML", "Oj"
        case message
        when :parse, :load, :safe_load
          value = stable_fresh([constant, :parsed_value], "value")
          unify(result, Generic.new("Hash", [Named.new("String"), value]))
        when :generate, :dump, :pretty_generate then unify(result, Named.new("String"))
        end
      when "Rails"
        case message
        when :logger then unify(result, Named.new("Logger"))
        when :env then unify(result, Named.new("String"))
        when :root then unify(result, Named.new("Pathname"))
        when :application then unify(result, Named.new("Rails::Application"))
        end
      when "File"
        case message
        when :read, :binread, :basename, :dirname, :extname, :join, :expand_path, :absolute_path, :realpath
          unify(result, Named.new("String"))
        when :readlines then unify(result, Generic.new("Array", [Named.new("String")]))
        when :size then unify(result, Named.new("Integer"))
        end
      when "Dir"
        unify(result, Generic.new("Array", [Named.new("String")])) if %i[glob children entries].include?(message)
      when "SecureRandom"
        unify(result, Named.new("String")) if %i[uuid hex urlsafe_base64 alphanumeric base64].include?(message)
      when "Base64"
        unify(result, Named.new("String")) if message.to_s.include?("code64")
      when "Digest::SHA256", "Digest::SHA1", "Digest::MD5"
        unify(result, Named.new("String")) if %i[hexdigest base64digest digest].include?(message)
      when "Regexp"
        case message
        when :escape, :quote then unify(result, Named.new("String"))
        when :union then unify(result, Named.new("Regexp"))
        end
      when "URI"
        case message
        when :parse, :join then unify(result, Named.new("URI"))
        when :encode_www_form, :decode_www_form_component, :encode_www_form_component
          unify(result, Named.new("String"))
        end
      when "Fiber"
        unify(result, Named.new("Fiber")) if %i[current new].include?(message)
      when "Array"
        if message == :Array
          argument = capability.arguments.first
          if argument
            element = array_element(resolve(argument)) || resolve(argument)
            unify(result, Generic.new("Array", [element]))
          else
            unify(result, Generic.new("Array", [fresh("element")]))
          end
        end
      when "Dox::Metrics"
        unify(result, Named.new("nil")) if %i[increment gauge histogram timing measure].include?(message)
      end
    end

    # The constant table is fixed once solving starts.
    def constant_literal(name, lexical_owner)
      memo = @constant_literals[lexical_owner] ||= {}
      memo.fetch(name) { memo[name] = find_constant_literal(name, lexical_owner) }
    end

    def find_constant_literal(name, lexical_owner)
      constant = name.delete_prefix("::")
      return @constants[constant] if name.start_with?("::")

      parts = lexical_owner.split("::")
      parts.length.downto(0) do |length|
        candidate = (parts.first(length) + [constant]).join("::")
        type = @constants[candidate]
        return type if type
      end
      nil
    end

    DUCK_UNION_LIMIT = 8
    DUCK_CORE_RECEIVERS = %w[String Integer Float Symbol bool Time Regexp MatchData Proc noreturn].freeze

    # When the receiver's class is unknown but the message is defined in the
    # repository, dispatch by name: exactly when one method defines it, or by
    # unioning return types when the few definitions agree enough. This is
    # what resolves entity-attribute reads on untyped pipeline inputs.
    def apply_union_member_dispatch(method, capability)
      return false unless dereference(capability.result).is_a?(TypeVariable)

      receiver = resolve(capability.receiver)
      return false unless receiver.is_a?(Union)

      targets = receiver.members.filter_map do |member|
        terminal = dereference(member)
        next unless terminal.is_a?(Named)
        next unless structured_name?(terminal.name)

        resolve_named_owner(terminal.name, method.owner, :instance, capability.message)
      end
      return false if targets.empty?

      if targets.length == 1
        apply_method_call(method, capability, targets.first)
      else
        apply_union_method_call(method, capability, targets)
      end
      true
    end

    def apply_union_method_call(caller, capability, callees)
      # A union unifies with nothing but an unbound variable.
      inert = !dereference(capability.result).is_a?(TypeVariable)
      returns = callees.map do |callee|
        key = [caller.object_id, capability.object_id, callee.object_id]
        bind_arguments(instantiated_parameters(key, callee), capability)
        instantiated_result(key, callee) unless inert
      end
      return if inert

      unified = returns.reduce { |left, right| Union.new([left, right].uniq) }
      unify(capability.result, unified)
    end

    def apply_duck_dispatch(method, capability)
      return unless dereference(capability.result).is_a?(TypeVariable)

      receiver = resolve(capability.receiver)
      return unless duck_receiver?(receiver)

      candidates = @duck_index[capability.message]
      return if candidates.empty?

      if candidates.length == 1
        apply_method_call(method, capability, candidates.first)
      else
        union = duck_union(capability.message)
        unify(capability.result, union) if union
      end
    end

    # The union of ground return types across same-named definitions, cached
    # per solving iteration. Unresolved definitions are excluded: the ground
    # subset is the best evidence available either way.
    def duck_union(message)
      union = @duck_cache.fetch(message) { @duck_cache[message] = untracked { compute_duck_union(message) } }
      # Readers depend on the union itself, which settled? compares each pass.
      (@duck_seen ||= []) << [message, union] if @reads
      union
    end

    def compute_duck_union(message)
      ground = @duck_index[message]
        .map { |candidate| resolve(candidate.result) }
        .select { |type| ground?(type) }
        .uniq
      return nil if ground.empty? || ground.length > DUCK_UNION_LIMIT

      ground.length == 1 ? ground.first : Union.new(ground)
    end

    def untracked
      reads = @reads
      @reads = nil
      yield
    ensure
      @reads = reads
    end

    # A call's effective callee: hierarchy resolution first, then the duck
    # index when it names exactly one repository method.
    def call_target(caller, capability)
      target = resolve_target(caller, capability)
      return target if target
      return unless duck_receiver?(resolve(capability.receiver))

      candidates = @duck_index[capability.message]
      candidates.length == 1 ? candidates.first : nil
    end

    def duck_receiver?(receiver)
      case receiver
      when TypeVariable, Union
        true
      when Named
        return true if structured_name?(receiver.name)
        !DUCK_CORE_RECEIVERS.include?(receiver.name) && !receiver.name.start_with?("Class[")
      else
        false
      end
    end

    # Fallbacks for sends that resolve to no repository method. Ruby's `?`
    # suffix convention is reliable enough for a typedoc, and a bare
    # `new`/`create` inside a singleton method constructs the owner class.
    def apply_fallback(method, capability)
      unify(capability.result, Named.new("bool")) if capability.message.end_with?("?")
      return unless capability.receiver == method.self_type

      # Rails controller/framework conventions for self-sends that resolve
      # to nothing in the repository.
      case capability.message
      when :params
        value = stable_fresh([capability.object_id, :params_value], "value")
        unify(capability.result, Generic.new("Hash", [Named.new("Symbol"), value]))
      when :request
        unify(capability.result, Named.new("ActionDispatch::Request"))
      when :response
        unify(capability.result, Named.new("ActionDispatch::Response"))
      when :logger
        unify(capability.result, Named.new("Logger"))
      when :headers
        unify(capability.result, Generic.new("Hash", [Named.new("String"), Named.new("String")]))
      when :options
        apply_config_hash_reader_fallback(method, capability)
      else
        fallback = @metadata.framework_self_fallbacks[capability.message]
        unify(capability.result, fallback.call(method, capability)) if fallback
      end
    end

    def apply_config_hash_reader_fallback(method, capability)
      wiring = @metadata.config_hash
      options = @metadata.config_options[method.owner]
      reader = wiring&.reader_method || capability.message
      return unless capability.message == reader

      if options&.any?
        values = options.values.uniq
        value_type = values.length == 1 ? values.first : Union.new(values)
        unify(capability.result, Generic.new("Hash", [Named.new("Symbol"), value_type]))
      else
        unify(capability.result, Generic.new("Hash", [Named.new("Symbol"), Named.new("Object")]))
      end
    end

    def config_option_type(method, key)
      literal_symbol_key(key)&.then { |symbol| @metadata.config_options.dig(method.owner, symbol) }
    end

    def nullable_type(inner)
      Generic.new("Nullable", [inner])
    end

    # A bare `new`/`create` inside a singleton method constructs the owner
    # class. Runs even when a `new` override is indexed, so overrides that
    # delegate to un-analyzable aliases still anchor to the nominal type.
    def apply_constructor(method, capability)
      return unless capability.receiver == method.self_type
      return unless method.kind == :singleton
      return unless %i[new create].include?(capability.message)

      unify(capability.result, Named.new(method.owner))
    end

    # The single member that is neither nil nor noreturn, if there is one.
    def unwrap_nilable(type)
      return type unless type.is_a?(Union)

      found = false
      single = nil
      type.members.each do |member|
        next if member == NIL || member == NORETURN
        return type if found

        found = true
        single = member
      end
      found ? single : type
    end

    def strip_nil(type)
      return type unless type.is_a?(Union)

      members = type.members.reject { |member| member == NIL }
      case members.length
      when 0 then type
      when 1 then members.first
      else Union.new(members)
      end
    end

    def array?(type)
      case type
      when Generic
        type.name == "Array"
      when Union
        type.members.any? { |member| array?(member) }
      else
        false
      end
    end

    def hash?(type) = type.is_a?(Generic) && type.name == "Hash" && type.arguments.length == 2

    def hashish?(type)
      case type
      when Generic
        hash?(type)
      when Union
        type.members.any? { |member| hashish?(member) }
      else
        false
      end
    end

    def hash_value_type(type)
      case type
      when Generic
        hash?(type) ? type.arguments[1] : nil
      when Union
        values = type.members.filter_map { |member| hash_value_type(member) }
        merge_unions(values)
      end
    end

    def unify_array_elements(type, value)
      case unwrap_nilable(resolve(type))
      when Generic
        element = array_element(type)
        unify(element, value) if element
      when Union
        type.members.each { |member| unify_array_elements(member, value) }
      end
    end

    def apply_indexed_enumeration(receiver, capability, result)
      element = enumerable_element(receiver)
      block = capability.arguments.last
      return unless block.is_a?(Function)

      unify(block.parameters[0], element) if element && block.parameters[0]
      unify(block.parameters[1], Named.new("Integer")) if block.parameters[1]
      unify(result, Generic.new("Array", [block.result]))
    end

    def apply_enumerable_block(receiver, capability, result, mode:)
      element = enumerable_element(receiver)
      block = capability.arguments.last
      if block.is_a?(Function)
        unify(block.parameters.first, element) if element && block.parameters.first
      end

      case mode
      when :same_collection
        unify(result, receiver) if array?(receiver)
      when :optional_element
        unify(result, Union.new([element, Named.new("nil")])) if element
      when :bool
        unify(result, Named.new("bool"))
      when :integer
        unify(result, Named.new("Integer"))
      end
    end

    def apply_each(receiver, capability, result, indexed:)
      element = enumerable_element(receiver)
      block = capability.arguments.last
      if block.is_a?(Function)
        unify(block.parameters[0], element) if element && block.parameters[0]
        unify(block.parameters[1], Named.new("Integer")) if indexed && block.parameters[1]
      end
      unify(result, receiver)
    end

    # A send's target only changes when its receiver resolves differently,
    # and resolution hands back the same object until then, so the last
    # target is kept with the receiver it was found for.
    def resolve_target(method, capability)
      if capability.receiver == method.self_type
        resolve_in_hierarchy(method.owner, method.kind, capability.message)
      else
        receiver = resolve(capability.receiver)
        return unless receiver.is_a?(Named)

        cached = @receiver_targets[capability]
        return cached[2] if cached && cached[0].equal?(receiver) && cached[1].equal?(method)

        target =
          if (class_name = class_name_from(receiver))
            resolve_named_owner(class_name, method.owner, :singleton, capability.message)
          else
            resolve_named_owner(receiver.name, method.owner, :instance, capability.message)
          end
        @receiver_targets[capability] = [receiver, method, target]
        target
      end
    end

    # Hierarchy lookups only read tables fixed at construction, and dispatch
    # repeats them for every send on every pass.
    def resolve_in_hierarchy(owner, kind, method_name)
      memo = (@hierarchy_cache[owner] ||= {})[kind] ||= {}
      memo.fetch(method_name) { memo[method_name] = find_in_hierarchy(owner, kind, method_name) }
    end

    def find_in_hierarchy(owner, kind, method_name)
      current = owner
      visited = Set.new
      while current && !visited.include?(current)
        visited << current
        target = @index[[current, kind, method_name]]
        return target if target

        current = resolve_superclass(current, @superclasses[current])
      end

      @includes[owner]&.each do |mod|
        target = @index[[mod, kind, method_name]]
        return target if target
      end
      nil
    end

    def resolve_named_owner(name, lexical_owner, kind, method_name)
      memo = ((@named_owner_cache[name] ||= {})[lexical_owner] ||= {})[kind] ||= {}
      memo.fetch(method_name) { memo[method_name] = find_named_owner(name, lexical_owner, kind, method_name) }
    end

    def find_named_owner(name, lexical_owner, kind, method_name)
      constant = name.delete_prefix("::")
      candidates = [constant]
      unless name.start_with?("::")
        parts = lexical_owner.split("::")
        parts.length.downto(1) { |length| candidates << (parts.first(length) + [constant]).join("::") }
      end
      candidates.uniq.each do |owner|
        target = resolve_in_hierarchy(owner, kind, method_name)
        return target if target
      end
      nil
    end

    def resolve_includes(includes)
      result = Hash.new { |hash, key| hash[key] = [] }
      includes.each do |owner, names|
        names.each do |name|
          mod = resolve_module_constant(name, owner)
          result[owner] << mod if mod
        end
      end
      result.transform_values { |mods| mods.uniq }
    end

    def resolve_module_constant(name, lexical_owner)
      return name.delete_prefix("::") if name.start_with?("::")

      segments = name.split("::")
      parts = lexical_owner.split("::")
      parts.length.downto(0) do |length|
        candidate = (parts.first(length) + segments).join("::")
        return candidate if module_defined?(candidate)
      end
      (parts + segments).join("::")
    end

    def module_defined?(name)
      @owners.include?(name)
    end

    def resolve_superclass(owner, superclass)
      return nil unless superclass

      superclass = superclass.delete_prefix("::")
      return superclass if @owners.include?(superclass)

      namespace = owner.split("::")[0...-1]
      namespace.length.downto(0) do |length|
        candidate = (namespace.first(length) + [superclass]).join("::")
        return candidate if @owners.include?(candidate)
      end
      superclass
    end

    def apply_method_call(caller, capability, callee)
      # A recursive call unifies with the method's own variables directly:
      # instantiating them mints an endless chain of fresh variables that
      # prevents the fixed point from converging.
      if callee.equal?(caller)
        bind_arguments(callee.parameters, capability)
        unify(capability.result, callee.result)
        return
      end

      key = [caller.object_id, capability.object_id, callee.object_id]
      bind_arguments(instantiated_parameters(key, callee), capability)
      return if instance_unify_inert?(capability.result, resolve(callee.result), @call_mappings[key])

      unify(capability.result, instantiated_result(key, callee))
    end

    # Whether unify(target, instantiate(source, mapping)) would bind nothing,
    # so the copy need not be built. Unification only descends through
    # matching generics and functions; the walk follows that skeleton and
    # gives up at any variable on either side. Skipping leaves only the call
    # site's own caches behind, and fresh variables nothing else can see.
    def instance_unify_inert?(target, source, mapping)
      left = dereference(target)
      return false if left.is_a?(TypeVariable)

      case source
      when TypeVariable
        mapped = mapping&.[](source)
        mapped ? unify_inert?(left, mapped) : false
      when Generic
        return true unless left.is_a?(Generic) && left.name == source.name && left.arguments.length == source.arguments.length

        left.arguments.each_with_index.all? { |argument, index| instance_unify_inert?(argument, source.arguments[index], mapping) }
      when Function
        return true unless left.is_a?(Function) && left.parameters.length == source.parameters.length

        left.parameters.each_with_index.all? { |parameter, index| instance_unify_inert?(parameter, source.parameters[index], mapping) } &&
          instance_unify_inert?(left.result, source.result, mapping)
      else
        true
      end
    end

    # Whether unify(left, right) on existing terms would bind nothing.
    def unify_inert?(left, right)
      left = dereference(left)
      right = dereference(right)
      return true if left.equal?(right)
      return false if left.is_a?(TypeVariable) || right.is_a?(TypeVariable)

      if left.is_a?(Generic) && right.is_a?(Generic) && left.name == right.name && left.arguments.length == right.arguments.length
        left.arguments.each_with_index.all? { |argument, index| unify_inert?(argument, right.arguments[index]) }
      elsif left.is_a?(Function) && right.is_a?(Function) && left.parameters.length == right.parameters.length
        left.parameters.each_with_index.all? { |parameter, index| unify_inert?(parameter, right.parameters[index]) } &&
          unify_inert?(left.result, right.result)
      else
        true
      end
    end

    # A call site's mapping persists and variables compare by identity, so an
    # equal resolved type instantiates to the same copy; reuse it instead of
    # rebuilding it every pass. The result is resolved after arguments bind.
    def instantiated_parameters(key, callee)
      resolved = callee.parameters.map { |parameter| resolve(parameter.type) }
      cached = @instantiated_parameters[key]
      return cached.last if cached && cached.first == resolved

      mapping = @call_mappings[key] ||= {}.compare_by_identity
      parameters = callee.parameters.each_with_index.map do |parameter, index|
        Parameter.new(name: parameter.name, type: instantiate(resolved[index], mapping), kind: parameter.kind)
      end
      @instantiated_parameters[key] = [resolved, parameters]
      parameters
    end

    def instantiated_result(key, callee)
      resolved = resolve(callee.result)
      cached = @instantiated_results[key]
      return cached.last if cached && cached.first == resolved

      # Callee types change piecemeal, so subtrees copied last time are reused
      # by identity rather than copying the whole type again.
      copies = {}.compare_by_identity
      result = instantiate(resolved, @call_mappings[key] ||= {}.compare_by_identity, copies, @result_copies[key])
      @result_copies[key] = copies
      @instantiated_results[key] = [resolved, result]
      result
    end

    def bind_arguments(parameters, capability)
      positional = capability.arguments.dup
      parameters.each do |parameter|
        case parameter.kind
        when :required, :optional
          unify(parameter.type, positional.shift) unless positional.empty?
        when :rest
          elements = positional.reject { |argument| argument.is_a?(Function) }
          element_type = elements.reduce { |left, right| Union.new([left, right].uniq) } ||
            stable_fresh([capability.object_id, parameter.name, :rest_element], "element")
          unify(parameter.type, Generic.new("Array", [element_type]))
        when :keyword, :optional_keyword
          argument = capability.keywords[parameter.name]
          unify(parameter.type, argument) if argument
        when :block
          block = positional.reverse.find { |argument| argument.is_a?(Function) }
          next unless block

          declared = resolve(parameter.type)
          if declared.is_a?(Function)
            # Block arity rarely matches the callee's yield shape exactly;
            # unify pairwise and always flow the return type.
            declared.parameters.zip(block.parameters).each { |left, right| unify(left, right) if left && right }
            unify(declared.result, block.result)
          else
            unify(parameter.type, block)
          end
        end
      end
    end

    # Callers pass resolved types, whose unions are already duplicate-free, and
    # the renaming is injective, so instantiated unions need no dedupe. A
    # subtree's copy only depends on the mapping, which never forgets, so
    # copies made earlier at the same call site (previous) stay valid.
    def instantiate(type, mapping, copies = nil, previous = nil)
      if type.is_a?(Generic) || type.is_a?(Union) || type.is_a?(Function)
        return instantiate_composite(type, mapping, nil, nil) unless copies

        copies[type] || (copies[type] = previous&.[](type) || instantiate_composite(type, mapping, copies, previous))
      elsif type.is_a?(TypeVariable)
        mapping[type] ||= fresh(type.hint)
      else
        type
      end
    end

    def instantiate_composite(type, mapping, copies, previous)
      case type
      when Generic
        Generic.new(type.name, type.arguments.map { |argument| instantiate(argument, mapping, copies, previous) })
      when Union
        Union.new(type.members.map { |member| instantiate(member, mapping, copies, previous) })
      else
        Function.new(
          type.parameters.map { |parameter| instantiate(parameter, mapping, copies, previous) },
          instantiate(type.result, mapping, copies, previous)
        )
      end
    end

    def unify(left, right)
      return unless left && right

      left = dereference(left)
      right = dereference(right)
      return if left == right

      if left.is_a?(TypeVariable)
        bind(left, right)
      elsif right.is_a?(TypeVariable)
        bind(right, left)
      elsif left.is_a?(Generic) && right.is_a?(Generic) &&
          left.name == right.name && left.arguments.length == right.arguments.length
        left.arguments.zip(right.arguments).each { |pair| unify(*pair) }
      elsif left.is_a?(Function) && right.is_a?(Function) &&
          left.parameters.length == right.parameters.length
        left.parameters.zip(right.parameters).each { |pair| unify(*pair) }
        unify(left.result, right.result)
      end
    end

    def bind(variable, type)
      return if occurs?(variable, type)

      rebinding = !variable.link.nil?
      link(variable, type)
      @wrote = true
      rebinding && !@tracking_chains ? flush_resolved : invalidate(variable)
      # Variable-to-variable links are alpha-moves carrying no new concrete
      # information. Counting them as progress lets recursive call cycles
      # mint fresh-variable chains that never converge.
      @changed = true unless type.is_a?(TypeVariable)
      @pass_binds&.push(variable, type)
    end

    def occurs?(variable, type)
      return false if type.is_a?(Named)

      type = dereference(type)
      case type
      when TypeVariable
        type == variable
      when Generic
        type.arguments.any? { |argument| occurs?(variable, argument) }
      when Union
        # Unions run tens of thousands wide, nearly all Named.
        members = type.members
        index = 0
        length = members.length
        while index < length
          member = members[index]
          return true if !member.is_a?(Named) && occurs?(variable, member)

          index += 1
        end
        false
      when Function
        type.parameters.any? { |parameter| occurs?(variable, parameter) } || occurs?(variable, type.result)
      else
        false
      end
    end

    def link(variable, type)
      @bound << variable unless variable.link
      variable.link = type
    end

    def dereference(type)
      return type unless type.is_a?(TypeVariable)

      current = type
      steps = 0
      while (bound = current.link)
        return dereference_guarded(type) if (steps += 1) > @bound.size

        current = bound
        break unless current.is_a?(TypeVariable)
      end
      compress_path(type, current) if steps > 1
      @reads[current] = true if @reads && current.is_a?(TypeVariable)
      current
    end

    # Method and call results get rebound in place (force_return!,
    # reflow_callee_returns!), so path compression must not skip over them.
    def mark_rebindable(type)
      type.rebindable = true if type.is_a?(TypeVariable)
    end

    # Alpha-links grow chains long enough to make every lookup linear. Each
    # link is pointed at the terminal, but never past a rebindable variable,
    # so a later rebinding still reaches everything behind it.
    def compress_path(type, terminal)
      path = []
      current = type
      until current.equal?(terminal)
        path << current
        current = current.link
      end
      target = terminal
      path.reverse_each do |variable|
        variable.link = target
        target = variable if variable.rebindable
      end
    end

    # A chain longer than the substitution table is a cycle; bind's occurs
    # check should make that impossible, but a cycle must not hang the solver.
    def dereference_guarded(type)
      seen = Set.new
      while type.is_a?(TypeVariable) && type.link && !seen.include?(type)
        seen << type
        type = type.link
      end
      @reads[type] = true if @reads && type.is_a?(TypeVariable)
      type
    end

    # A call cycle re-instantiates a union of unknowns with fresh variables
    # every round, doubling it without bound. Unknowns all render as Object,
    # so only the oldest few are kept; that also stops the fresh minting.
    MAX_UNION_UNKNOWNS = 32

    # A resolution only goes stale when an unbound variable it reached gets
    # bound, so binding drops just the entries derived from that variable
    # (see invalidate). Rebinding an already-bound variable flushes everything.
    # A reader only records the entry it asked for: invalidation reaches that
    # entry from every variable beneath it, so the work below goes untracked.
    # Named types resolve to themselves and nothing depends on them.
    def resolve(type)
      return type if type.is_a?(Named)

      reads = @reads
      return resolve_entry(type) unless reads

      reads[type] = true if changeable?(type)
      @reads = nil
      begin
        resolve_entry(type)
      ensure
        @reads = reads
      end
    end

    def resolve_entry(type)
      cached = @resolved[type]
      return cached if cached

      terminal = dereference(type)
      result = resolve_terminal(terminal)
      @resolved[type] = result
      track_sources(type, terminal)
      result
    end

    # An entry derives from the unbound variable it resolved to, or from the
    # entries of its parts: every part, so members the union cap dropped
    # still invalidate it once they bind.
    def track_sources(type, terminal)
      track_rebindable_chain(type) if @tracking_chains && !terminal.equal?(type)
      case terminal
      when TypeVariable then depend(terminal, type)
      when Generic then terminal.arguments.each { |argument| depend(argument, type) }
      when Union
        # A big union's state was just brought up to date, and stands in for
        # its members (see UnionState).
        if (state = @union_states[terminal.members])
          register(@dependents, state, type)
        else
          terminal.members.each { |member| depend(member, type) unless member.is_a?(Named) }
        end
      when Function
        terminal.parameters.each { |parameter| depend(parameter, type) }
        depend(terminal.result, type)
      end
    end

    # Path compression never skips a rebindable variable, so every one the
    # entry's resolution went through is still on its chain.
    def track_rebindable_chain(type)
      current = type
      steps = 0
      while current.is_a?(TypeVariable) && (bound = current.link) && (steps += 1) <= @bound.size
        depend(current, type) if current.rebindable
        current = bound
      end
    end

    def depend(source, dependent)
      return unless changeable?(source)

      list = @dependents[source]
      if list.nil?
        @dependents[source] = dependent
      elsif list.instance_of?(Array)
        list << dependent unless list.last.equal?(dependent)
      elsif !list.equal?(dependent)
        @dependents[source] = [list, dependent]
      end
    end

    # Most sources only ever get one dependent (or reader), stored bare;
    # neither is ever an Array. Recomputing an entry re-registers it under
    # sources that never changed, usually right after its last registration.
    def register(table, source, dependent)
      list = table[source]
      if list.nil?
        table[source] = dependent
      elsif list.instance_of?(Array)
        list << dependent unless list.last.equal?(dependent)
      elsif !list.equal?(dependent)
        table[source] = [list, dependent]
      end
    end

    def changeable?(type)
      type.is_a?(TypeVariable) || type.is_a?(Generic) || type.is_a?(Union) || type.is_a?(Function)
    end

    # An entry missing from the cache has no cached dependents left: they
    # were dropped with it, or recomputed it when they were rebuilt. Every
    # capability that read a dropped entry must be evaluated again.
    def invalidate(source)
      readers = @readers.delete(source)
      if readers.instance_of?(Array)
        readers.each { |capability| unsettle(capability) }
      elsif readers
        unsettle(readers)
      end
      dependents = @dependents.delete(source)
      if dependents.instance_of?(Array)
        dependents.each { |dependent| invalidate_dependent(dependent, source) }
      elsif dependents
        invalidate_dependent(dependents, source)
      end
    end

    def invalidate_dependent(dependent, source)
      if @resolved.delete(dependent)
        invalidate(dependent)
      elsif dependent.is_a?(UnionState)
        dependent.dirty[source] = true
        invalidate(dependent)
      end
    end

    def flush_resolved
      @resolved.clear
      @dependents.clear
      @readers.clear
      @generation += 1
      @flushes += 1
    end

    # Unchanged types come back as the same object, which keeps them
    # allocation-free and lets call sites detect an unchanged callee by identity.
    def resolve_terminal(type)
      case type
      when Generic
        arguments = resolve_each(type.arguments)
        arguments.equal?(type.arguments) ? type : Generic.new(type.name, arguments)
      when Union
        members = normalized_members(type.members)
        return members.first if members.length == 1
        return type if identical_elements?(members, type.members)

        Union.new(members)
      when Function
        parameters = resolve_each(type.parameters)
        result = resolve(type.result)
        parameters.equal?(type.parameters) && result.equal?(type.result) ? type : Function.new(parameters, result)
      else
        type
      end
    end

    # Members resolved and flattened one level, first occurrences kept (as
    # uniq keeps them), in a single pass. Named types resolve to themselves.
    def normalized_members(source)
      return incremental_members(source) if source.length > MAX_UNION_UNKNOWNS

      seen = {}
      source.each do |member|
        resolved = member.is_a?(Named) ? member : resolve(member)
        if resolved.is_a?(Union)
          resolved.members.each { |inner| seen[inner] = true }
        else
          seen[resolved] = true
        end
      end
      # Raising branches contribute no value, so noreturn disappears from
      # unions unless the method can only raise.
      seen.delete(NORETURN) if seen.size > 1
      cap_unknowns(seen.keys)
    end

    def cap_unknowns(members)
      return members unless members.length > MAX_UNION_UNKNOWNS

      unknowns = 0
      members.select { |member| !member.is_a?(TypeVariable) || (unknowns += 1) <= MAX_UNION_UNKNOWNS }
    end

    # Big unions are re-resolved each time one of their members binds, which
    # usually changes a single position. While a union's last resolution
    # needed no flattening, deduplication, or capping, it is kept as a
    # UnionState, and a re-resolution that keeps it that way only examines
    # the positions whose members were invalidated since.
    def incremental_members(source)
      state = @union_states[source]
      if state
        members = advance_union_state(state, source)
        return members if members
      end

      settle_union_state(source, source.map { |member| member.is_a?(Named) ? member : resolve(member) })
    end

    # A big union's last clean resolution. It sits in the dependency graph
    # between the union's members and the entries resolved through it: a
    # member's invalidation reaches those entries through the state and marks
    # the member dirty. A member that is not dirty still resolves to the
    # cached entry recorded here, unless a flush dropped every entry.
    class UnionState
      attr_accessor :resolved, :unknowns, :flushes
      # index: resolved member => position. watched: positions of members
      # that are not Named, the only ones that can change. positions: their
      # members => position.
      attr_reader :index, :watched, :positions, :dirty

      def initialize(resolved, index, unknowns, watched, flushes)
        @resolved = resolved
        @index = index
        @unknowns = unknowns
        @watched = watched
        @flushes = flushes
        @positions = {}.compare_by_identity
        @dirty = {}.compare_by_identity
      end
    end

    NO_POSITIONS = [].freeze

    # Returns nil when the new resolution needs the full normalization.
    def advance_union_state(state, source)
      previous = state.resolved
      stale = stale_positions(state)
      changed = nil
      stale.each do |position|
        value = resolve(source[position])
        (changed ||= {})[position] = value unless value.equal?(previous[position])
      end
      resolved = changed ? apply_union_changes(state, changed) : previous
      return unless resolved

      # Invalidation and flushes dropped the stale members' registrations.
      stale.each { |position| depend(source[position], state) }
      state.flushes = @flushes
      resolved
    end

    # In position order, as a full scan meets them.
    def stale_positions(state)
      dirty = state.dirty
      if state.flushes != @flushes
        dirty.clear
        state.watched
      elsif dirty.empty?
        NO_POSITIONS
      else
        positions = dirty.each_key.map { |member| state.positions.fetch(member) }.sort!
        dirty.clear
        positions
      end
    end

    def apply_union_changes(state, changed)
      previous = state.resolved
      index = state.index
      unknowns = state.unknowns
      incoming = {} if changed.size > 1
      changed.each do |position, value|
        return nil if value.is_a?(Union) || value.eql?(NORETURN)

        other = index[value]
        return nil if other && other != position && !changed.key?(other)

        if incoming
          return nil if incoming.key?(value)

          incoming[value] = true
        end
        unknowns += 1 if value.is_a?(TypeVariable)
        unknowns -= 1 if previous[position].is_a?(TypeVariable)
      end
      return nil if unknowns > MAX_UNION_UNKNOWNS

      resolved = previous.dup
      changed.each_key { |position| index.delete(previous[position]) }
      changed.each do |position, value|
        index[value] = position
        resolved[position] = value
      end
      state.resolved = resolved.freeze
      state.unknowns = unknowns
      resolved
    end

    def settle_union_state(source, resolved)
      seen = {}
      flattened = false
      resolved.each_with_index do |value, position|
        if value.is_a?(Union)
          flattened = true
          value.members.each { |inner| seen[inner] = true }
        else
          seen[value] = position
        end
      end
      seen.delete(NORETURN) if seen.size > 1
      members = seen.keys
      if !flattened && members.length == resolved.length
        unknowns = members.count { |member| member.is_a?(TypeVariable) }
        if unknowns <= MAX_UNION_UNKNOWNS
          watched = source.each_index.reject { |position| source[position].is_a?(Named) }
          state = UnionState.new(resolved.freeze, seen, unknowns, watched, @flushes)
          watched.each do |position|
            state.positions[source[position]] = position
            depend(source[position], state)
          end
          @union_states[source] = state
          return resolved
        end
      end

      @union_states.delete(source)
      cap_unknowns(members)
    end

    def resolve_each(types)
      resolved = nil
      index = 0
      length = types.length
      while index < length
        type = types[index]
        result = resolve(type)
        if resolved
          resolved << result
        elsif !result.equal?(type)
          resolved = types.first(index) << result
        end
        index += 1
      end
      resolved || types
    end

    def identical_elements?(left, right)
      return false unless left.length == right.length

      index = 0
      while index < left.length
        return false unless left[index].equal?(right[index])

        index += 1
      end
      true
    end

    MAX_NARROWING_SENDS = 8
    NARROWING_ROUNDS = 3

    MAX_CONSTRUCTOR_UNION = 4

    # Calls bind instantiated copies of the callee's parameters, so the
    # originals (and everything downstream: ivars, accessors, receivers)
    # stay unresolved. Accumulating ground argument types from all call
    # sites and binding them into the original parameters narrows those
    # chains at the source.
    def flow_call_arguments!
      accumulated = Hash.new { |hash, key| hash[key] = [] }
      @methods.each do |caller|
        caller.capabilities.each do |capability|
          target = call_target(caller, capability)
          accumulate_call_arguments(target, capability, accumulated) if target
          next unless capability.message == :new

          class_name =
            if capability.receiver == caller.self_type && caller.kind == :singleton
              caller.owner
            else
              class_name_from(resolve(capability.receiver))
            end
          next unless class_name

          init = resolve_named_owner(class_name, caller.owner, :instance, :initialize)
          accumulate_call_arguments(init, capability, accumulated) if init
        end
      end

      accumulated.each do |variable, types|
        next unless dereference(variable).is_a?(TypeVariable)

        members = types.uniq
        next if members.empty? || members.length > MAX_CONSTRUCTOR_UNION

        unify(variable, members.length == 1 ? members.first : Union.new(members))
      end
    end

    def accumulate_call_arguments(callee, capability, accumulated)
      positional = capability.arguments.reject { |argument| argument.is_a?(Function) }
      callee.parameters.each do |parameter|
        argument =
          case parameter.kind
          when :required, :optional then positional.shift
          when :keyword, :optional_keyword then capability.keywords[parameter.name]
          end
        next unless argument

        terminal = dereference(parameter.type)
        next unless terminal.is_a?(TypeVariable)
        next if structural_parameter?(callee, parameter)

        resolved = resolve(argument)
        accumulated[terminal] << resolved if flowable_argument?(resolved)
      end
    end

    def flowable_argument?(type)
      case dereference(type)
      when TypeVariable then false
      when Union then type.members.any? { |member| flowable_argument?(member) }
      when Function then false
      else true
      end
    end

    def structural_parameter?(callee, parameter)
      terminal = dereference(parameter.type)
      return false unless terminal.is_a?(TypeVariable)

      callee.capabilities.any? do |capability|
        capability.message == :[] && dereference(capability.receiver) == terminal
      end
    end

    # When callers pass hashes or arrays into a parameter, the callee body's
    # literal index sends on that parameter tell us which slots to narrow.
    def flow_structural_arguments!
      @methods.each do |caller|
        caller.capabilities.each do |capability|
          callee = call_target(caller, capability)
          next unless callee

          positional = capability.arguments.reject { |argument| argument.is_a?(Function) }
          callee.parameters.each do |parameter|
            next if parameter.kind == :block

            argument = case parameter.kind
            when :required, :optional then positional.shift
            when :keyword, :optional_keyword then capability.keywords[parameter.name]
            end
            next unless argument

            flow_argument_slots(callee, parameter.type, resolve(argument))
          end
        end
      end
    end

    def flow_argument_slots(callee, parameter_type, argument_type)
      parameter_type = dereference(parameter_type)
      return unless parameter_type.is_a?(TypeVariable)

      case unwrap_nilable(argument_type)
      when Generic
        if hash?(argument_type)
          value_type = argument_type.arguments[1]
          index_slots_for(callee, parameter_type).each { |slot| unify(slot, value_type) }
        elsif array?(argument_type)
          element_type = array_element(argument_type)
          index_slots_for(callee, parameter_type).each do |slot|
            unify(slot, Union.new([element_type, Named.new("nil")]))
          end
        end
      when Union
        argument_type.members.each { |member| flow_argument_slots(callee, parameter_type, member) }
      end
    end

    def index_slots_for(callee, parameter_type)
      callee.capabilities.filter_map do |capability|
        next unless capability.message == :[]
        next unless dereference(capability.receiver) == parameter_type

        capability.result
      end
    end

    def ground?(type)
      case type
      when TypeVariable then false
      when Generic then type.arguments.all? { |argument| ground?(argument) }
      when Union then type.members.all? { |member| ground?(member) }
      when Function then type.parameters.all? { |parameter| ground?(parameter) } && ground?(type.result)
      else true
      end
    end

    # The same naming conventions trusted for unresolved sends apply to
    # method definitions whose body defeated inference: `?` methods return
    # bool, `to_*`/`*_hash` converters return their conventional type.
    def apply_definition_conventions!
      @methods.each do |method|
        default = convention_default(method.method_name.to_s)
        next unless default

        parameter_terminals = method.parameters.map { |parameter| dereference(parameter.type) }
        residual = residual_return_variables(method) - parameter_terminals
        residual.each { |variable| unify(variable, default) }
      end
    end

    def apply_intra_method_param_flow!
      @methods.each do |method|
        method.parameters.each do |parameter|
          method.capabilities.each do |capability|
            next unless %i[<< push append unshift prepend].include?(capability.message)

            receiver = resolve(capability.receiver)
            next unless array?(receiver)

            capability.arguments.each do |argument|
              next if argument.is_a?(Function)
              next unless argument.equal?(parameter.type)

              unify_array_elements(receiver, resolve(parameter.type))
            end
          end
        end
      end
    end

    # Nested sends like `hash[key1][key2] << item` create separate capabilities
    # per subexpression; when the inner result is still a variable, propagate
    # the looked-up slot type to the outer receiver before solving `<<`.
    def apply_chained_send_narrowing!
      @methods.each do |method|
        method.capabilities.each do |capability|
          narrow_chained_receiver!(method, capability)
        end
      end
    end

    def narrow_chained_receiver!(method, capability)
      receiver = capability.receiver
      return unless receiver.is_a?(TypeVariable)

      source_type = resolve_chained_source_type(method, capability)
      return unless source_type

      case capability.message
      when :[]
        if hashish?(source_type)
          key_arg = capability.arguments.first
          if literal_hash_key?(source_type, key_arg) || hash_key_type_compatible?(source_type, key_arg)
            value_type = hash_value_type(source_type)
            unify(receiver, value_type) if value_type
          end
        elsif array?(source_type)
          element = array_element(source_type)
          unify(receiver, Union.new([element, Named.new("nil")])) if element
        end
      when :<<, :push, :append, :unshift, :prepend
        if array?(source_type)
          unify(receiver, source_type)
          capability.arguments.each do |argument|
            unify_array_elements(source_type, argument) unless argument.is_a?(Function)
          end
        end
      end
    end

    def resolve_chained_source_type(method, capability, visited = Set.new.compare_by_identity)
      # Unification can close a chain into a cycle (`node = node[:next]` in a loop).
      return nil unless visited.add?(capability)

      receiver = resolve(capability.receiver)
      return receiver unless receiver.is_a?(TypeVariable)

      source = method.capabilities.find { |other| other.result.equal?(receiver) }
      return nil unless source

      parent_type = resolve_chained_source_type(method, source, visited)
      return nil unless parent_type

      case source.message
      when :[]
        if hashish?(parent_type)
          key_arg = source.arguments.first
          if literal_hash_key?(parent_type, key_arg) || hash_key_type_compatible?(parent_type, key_arg)
            hash_value_type(parent_type)
          end
        elsif array?(parent_type)
          array_element(parent_type)
        end
      else
        nil
      end
    end

    # Block parameters from `.each { |x| foo(x) }` are fresh variables that
    # cross-method flow skips; unify callee parameters directly.
    def apply_block_argument_callee_flow!
      @methods.each do |method|
        method.capabilities.each do |capability|
          next unless %i[each each_with_index each_value each_key].include?(capability.message)

          block = capability.arguments.last
          next unless block.is_a?(Function)

          block_params = block.parameters
          next if block_params.empty?

          method.capabilities.each do |inner|
            target = call_target(method, inner)
            next unless target

            positional = inner.arguments.reject { |argument| argument.is_a?(Function) }
            positional.each_with_index do |argument, index|
              block_param = block_params[index]
              next unless block_param && argument.equal?(block_param)

              param = target.parameters[index]
              unify(param.type, block_param) if param
            end
          end
        end
      end
    end

    def apply_mutator_return_nil!
      @methods.each do |method|
        next unless method.method_name.to_s.end_with?("!")
        next if mutator_returns_receiver?(method)

        force_return!(method, Named.new("nil"))
      end
    end

    def mutator_returns_receiver?(method)
      method.capabilities.any? do |capability|
        SELF_RETURNING.include?(capability.message) && capability.receiver == method.self_type
      end
    end

    # Call-site return types can be bound while callees still carry stale
    # intermediate variables (e.g. `<<` before array element narrowing).
    # Re-unify once callees have converged.
    #
    # Nearly every bind here rebinds a call result. Rather than flush the
    # cache each time, entries record the rebindable variables their chains
    # pass through (see track_sources), so a rebinding invalidates just the
    # entries that went through it. No capability is evaluated in between,
    # so the flush beforehand leaves no settled capability or reader behind.
    def reflow_callee_returns!
      flush_resolved
      @tracking_chains = true
      @methods.each do |caller|
        caller.capabilities.each do |capability|
          callee = call_target(caller, capability)
          next unless callee
          next if callee.equal?(caller)

          result_var = capability.result
          next unless result_var.is_a?(TypeVariable)

          bind(result_var, resolve(callee.result))
        end
      end
    ensure
      @tracking_chains = false
    end

    def apply_forced_return_conventions!
      @methods.each do |method|
        default = convention_default(method.method_name.to_s)
        next unless default == Named.new("nil")
        next unless @metadata.side_effect_methods.include?(method.method_name) ||
          method.method_name.to_s.match?(/\Areset(?:_[a-z_]+)?!\z/)

        force_return!(method, default)
      end
    end

    def force_return!(method, type)
      return unless method.result.is_a?(TypeVariable)

      link(method.result, type)
      flush_resolved
      @changed = true
    end

    def convention_default(name)
      return Named.new("bool") if name.end_with?("?")
      return Named.new("nil") if @metadata.side_effect_methods.include?(name.to_sym)
      return Named.new("nil") if name.match?(/\Areset(?:_[a-z_]+)?!\z/)

      case name
      when "to_s", "to_str", "inspect" then Named.new("String")
      when "to_i" then Named.new("Integer")
      when "to_f" then Named.new("Float")
      when "to_sym" then Named.new("Symbol")
      when "count", "size", "length" then Named.new("Integer")
      else
        if name == "to_h" || name == "to_hash" || name.end_with?("_h", "_hash") || name.end_with?("_count")
          name.end_with?("_count") ? Named.new("Integer") : Generic.new("Hash", [fresh(:key), fresh(:value)])
        end
      end
    end

    # Usage-based narrowing: when a method's return stays unresolved, the
    # messages callers send to its result are structural evidence. Attaching
    # them as capabilities lets the renderer show a named structural type
    # instead of Object. Display-only: no unification happens here.
    # Nothing binds while narrowing, so every call target and dereferenced
    # receiver stays what it was when first computed, across all rounds;
    # only the capabilities attached since need computing.
    def narrow_residual_returns!
      targets = {}.compare_by_identity
      receivers = {}.compare_by_identity
      NARROWING_ROUNDS.times do
        break unless narrowing_round(targets, receivers)
      end
    end

    # One narrowing round; returns true when new evidence was attached so a
    # follow-up round can propagate it through forwarding methods.
    def narrowing_round(targets, receivers)
      # Keyed by identity: no two methods are equal (each has its own self
      # variable), and hashing one walks its whole structure.
      observations = {}.compare_by_identity
      @methods.each do |caller|
        caller.capabilities.each do |capability|
          target = targets.fetch(capability) { targets[capability] = call_target(caller, capability) }
          (observations[target] ||= []) << [caller, capability.result] if target
        end
      end

      changed = false
      observations.each do |callee, calls|
        parameter_variables = callee.parameters.map { |parameter| dereference(parameter.type) }
        residual = residual_return_variables(callee) - parameter_variables
        next if residual.empty?

        sends = collect_result_observations(calls, receivers)
        next if sends.empty?

        groups = receiver_groups(callee, receivers)
        residual.each do |variable|
          existing = groups[variable] ||= []
          seen = existing.map { |capability| [capability.message, capability.arguments.length] }.to_set
          budget = MAX_NARROWING_SENDS - seen.size
          break if budget <= 0

          sends.each do |send|
            key = [send.fetch(:message), send.fetch(:arguments).length]
            next if seen.include?(key)

            capability = Capability.new(
              receiver: variable,
              message: send.fetch(:message),
              arguments: send.fetch(:arguments),
              keywords: send.fetch(:keywords),
              result: send.fetch(:result),
              line: callee.line
            )
            callee.capabilities << capability
            existing << capability
            mark_rebindable(send.fetch(:result))
            seen << key
            changed = true
            break if seen.size >= MAX_NARROWING_SENDS
          end
        end
      end
      changed
    end

    # A method's capabilities by dereferenced receiver, for the receivers
    # that end at a variable, in order.
    def receiver_groups(method, receivers)
      receivers[method] ||= method.capabilities.each_with_object({}.compare_by_identity) do |capability, groups|
        terminal = dereference(capability.receiver)
        (groups[terminal] ||= []) << capability if terminal.is_a?(TypeVariable)
      end
    end

    def residual_return_variables(method)
      resolved = resolve(method.result)
      case resolved
      when TypeVariable then [resolved]
      when Union then resolved.members.grep(TypeVariable)
      else []
      end
    end

    def collect_result_observations(calls, receivers)
      groups = {}
      calls.each do |caller, result|
        terminal = dereference(result)
        next unless terminal.is_a?(TypeVariable)

        receiver_groups(caller, receivers)[terminal]&.each do |capability|
          key = [capability.message, capability.arguments.length, capability.keywords.keys.sort]
          entry = groups[key] ||= {
            message: capability.message,
            arguments: capability.arguments.map { |argument| resolve(argument) },
            keywords: capability.keywords.transform_values { |value| resolve(value) },
            result: nil
          }
          observed = resolve(capability.result)
          entry[:result] = entry[:result] ? merge_union(entry[:result], observed) : observed
        end
      end
      groups.values.sort_by { |send| send.fetch(:message).to_s }
    end

    def merge_union(left, right)
      return left if left == right

      members = (left.is_a?(Union) ? left.members : [left]) +
        (right.is_a?(Union) ? right.members : [right])
      Union.new(members.uniq)
    end

    # types.reduce { |left, right| merge_union(left, right) } in one pass.
    # Every merge keeps first occurrences, as uniq does, so it only appends
    # the right side's unseen members; reducing tens of thousands of
    # elements pairwise copies and rehashes the accumulated union per step.
    def merge_unions(types)
      merged = types.first
      members = nil
      seen = nil
      types.each_with_index do |type, index|
        next if index.zero?

        if members
          # The merged union equals type exactly when their members do.
          next if type.instance_of?(Union) && members == type.members
        else
          next if merged == type

          members = []
          seen = {}
          append_union_members(merged, members, seen)
        end
        append_union_members(type, members, seen)
      end
      members ? Union.new(members) : merged
    end

    def append_union_members(type, members, seen)
      (type.is_a?(Union) ? type.members : [type]).each do |member|
        next if seen.key?(member)

        seen[member] = true
        members << member
      end
    end

    def resolved_method(method)
      parameters = method.parameters
      MethodResult.new(
        name: method.name,
        owner: method.owner,
        kind: method.kind,
        method_name: method.method_name,
        superclass: method.superclass,
        line: method.line,
        end_line: method.end_line,
        parameters: parameters.empty? ? parameters : parameters.map do |parameter|
          Parameter.new(name: parameter.name, type: resolve(parameter.type), kind: parameter.kind)
        end,
        result: resolve(method.result),
        capabilities: method.capabilities.map do |capability|
          arguments = capability.arguments
          keywords = capability.keywords
          Capability.new(
            receiver: resolve(capability.receiver),
            message: capability.message,
            arguments: arguments.empty? ? arguments : arguments.map { |argument| resolve(argument) },
            keywords: keywords.empty? ? keywords : keywords.transform_values { |value| resolve(value) },
            result: resolve(capability.result),
            line: capability.line
          )
        end,
        self_type: resolve(method.self_type),
        ivars: method.ivars.empty? ? method.ivars : method.ivars.transform_values { |type| resolve(type) },
        locals: method.locals.empty? ? method.locals : method.locals.transform_values { |type| resolve(type) },
        port_assignments: method.port_assignments,
        case_narrowings: method.case_narrowings
      )
    end

    def fresh(hint = nil)
      variable = TypeVariable.new(@fresh_scope, @fresh_id, hint)
      @fresh_id += 1
      variable
    end

    def stable_fresh(key, hint = nil)
      @stable_variables[key] ||= fresh(hint)
    end

    def class_name_from(type)
      return unless type.is_a?(Named)

      name = type.name
      @class_names.fetch(name) do
        match = name.match(/\AClass\[(.+)\]\z/)
        @class_names[name] = match && match[1].delete_prefix("::").freeze
      end
    end

    def array_element(type)
      case type
      when Generic
        type.arguments.first if type.name == "Array"
      when Union
        elements = type.members.filter_map { |member| array_element(member) }
        merge_unions(elements)
      end
    end

    def enumerable_element(type)
      case type
      when Generic
        return type.arguments.first if %w[Array Enumerator Set].include?(type.name)
      when Union
        return union_element(type) unless type.members.length >= Union::SAMPLED_HASH_MIN

        # Purely structural, and wide receivers recur unchanged.
        return @union_elements.fetch(type) { @union_elements[type] = union_element(type) }
      end

      nil
    end

    def union_element(union)
      elements = union.members.filter_map { |member| enumerable_element(member) }
      merge_unions(elements) unless elements.empty?
    end
  end

  class UniversalHelperRegistry
    def initialize(methods)
      @occurrences = {}
      @definitions = {}
      methods.each { |method| register_method(method) }
      consolidate!
    end

    def occurrence(method, receiver)
      @occurrences[[method.object_id, receiver]]
    end

    def occurrences_for(method)
      @occurrences.filter_map { |(method_id, _), occurrence| occurrence if method_id == method.object_id }
    end

    def definitions
      @definitions.values.sort_by { |definition| definition.fetch(:name) }
    end

    def apply_names!(names)
      @definitions.each_value do |definition|
        semantic_name = normalize_semantic_name(names[definition.fetch(:id)])
        definition[:name] = semantic_name if semantic_name
      end
    end

    # Clusters of distinct definitions that would receive the same normalized
    # name. The namer re-prompts these cluster by cluster until empty.
    def collisions(names)
      @definitions.each_value
        .group_by { |definition| normalize_semantic_name(names[definition.fetch(:id)]) }
        .select { |name, definitions| name && definitions.length > 1 }
    end

    def normalize_semantic_name(name)
      return nil if name.to_s.empty?

      tokens = name.to_s.scan(/[A-Za-z0-9]+/)
      normalized = if tokens.length == 1
        tokens.first.sub(/\A[a-z]/, &:upcase)
      else
        tokens.map(&:capitalize).join
      end
      return nil if normalized.empty?

      normalized += "Able" unless normalized.match?(/(?:able|ible|ifiable|izable)\z/i)
      normalized
    end

    private

    def register_method(method)
      groups = method.capabilities
        .select { |capability| capability.receiver.is_a?(TypeVariable) }
        .group_by(&:receiver)

      groups.each do |receiver, capabilities|
        shape = build_shape(receiver, capabilities)
        name = "Capability_#{Digest::SHA256.hexdigest(shape.fetch(:definition))[0, 10]}"
        definition = @definitions[name] ||= {
          id: name,
          name: name,
          parameters: shape.fetch(:parameter_names),
          definition: shape.fetch(:definition),
          template: shape.fetch(:template),
          slots: shape.fetch(:slots),
          uses: 0
        }
        definition[:uses] += 1
        @occurrences[[method.object_id, receiver]] = {
          arguments: shape.fetch(:parameter_types),
          definition: definition
        }
      end
    end

    # Final compression: definitions sharing the same method structure (same
    # messages, arities, and keyword names) merge into one type. Slots that
    # agree stay fixed, concrete slots that differ become unions, and slots
    # involving generics become shared parameters bound per occurrence.
    def consolidate!
      # Occurrences by their current definition id; merging moves them.
      occurrences_by_id = Hash.new { |hash, key| hash[key] = [] }
      @occurrences.each_value { |occurrence| occurrences_by_id[occurrence.fetch(:definition).fetch(:id)] << occurrence }
      @definitions.values.group_by { |definition| definition.fetch(:template) }.each_value do |members|
        next if members.length == 1

        members = members.sort_by { |member| member.fetch(:id) }
        slot_count = members.first.fetch(:slots).length
        roles = (0...slot_count).map do |index|
          values = members.map { |member| member.fetch(:slots)[index] }
          if values.any? { |value| value.match?(/\bT\d+\b/) }
            :parameter
          elsif values.uniq.length == 1
            values.first
          else
            values.flat_map { |value| value.split(" | ") }.uniq.join(" | ")
          end
        end
        parameter_slots = roles.each_index.select { |index| roles[index] == :parameter }
        merged_text = members.first.fetch(:template).gsub(/%(\d+)%/) do
          index = Regexp.last_match(1).to_i
          roles[index] == :parameter ? "T#{parameter_slots.index(index) + 1}" : roles[index]
        end
        merged_id = "Capability_#{Digest::SHA256.hexdigest(merged_text)[0, 10]}"
        merged = {
          id: merged_id,
          name: merged_id,
          parameters: parameter_slots.each_index.map { |index| "T#{index + 1}" },
          definition: merged_text,
          template: merged_text,
          slots: [],
          uses: members.sum { |member| member.fetch(:uses) }
        }

        moved = members.map { |member| member.fetch(:id) }.uniq.flat_map { |id| occurrences_by_id.delete(id) || [] }
        moved.each do |occurrence|
          definition = occurrence.fetch(:definition)
          occurrence[:arguments] = parameter_slots.map do |index|
            TemplateArgument.new(
              template: definition.fetch(:slots)[index],
              arguments: occurrence.fetch(:arguments)
            )
          end
          occurrence[:definition] = merged
        end
        occurrences_by_id[merged_id].concat(moved)
        members.each { |member| @definitions.delete(member.fetch(:id)) }
        @definitions[merged_id] = merged
      end
    end

    # The template marks each slot with a %index% placeholder, and the
    # definition is the template with the placeholders spelled out; both are
    # written in one walk. A name containing a percent sign could read as a
    # placeholder, so then the definition is substituted into the template.
    Shape = Struct.new(:receiver, :parameter_types, :parameter_indexes, :slots, :template, :definition, :percent)

    def build_shape(receiver, capabilities)
      shape = Shape.new(receiver, [], {}, [], +"{ ", +"{ ", false)
      sorted = capabilities.length == 1 ? capabilities : capabilities.sort_by { |capability| capability_sort_key(capability) }
      sorted.each_with_index do |capability, position|
        append_shape(shape, "; ") if position.positive?
        append_shape_name(shape, capability.message.to_s)
        append_shape(shape, "(")
        capability.arguments.each_with_index do |argument, index|
          append_shape(shape, ", ") if index.positive?
          slotify(shape, argument)
        end
        unless capability.keywords.empty?
          separate = !capability.arguments.empty?
          capability.keywords.sort.each do |name, value|
            append_shape(shape, ", ") if separate
            separate = true
            append_shape_name(shape, name.to_s)
            append_shape(shape, ": ")
            slotify(shape, value)
          end
        end
        append_shape(shape, ") -> ")
        slotify(shape, capability.result)
      end
      append_shape(shape, " }")
      parameter_types = shape.parameter_types
      slots = shape.slots
      template = shape.template

      {
        parameter_types: parameter_types,
        parameter_names: parameter_types.each_index.map { |index| "T#{index + 1}" },
        template: template,
        slots: slots,
        definition: shape.percent ? template.gsub(/%(\d+)%/) { slots[Regexp.last_match(1).to_i] } : shape.definition
      }
    end

    def append_shape(shape, text)
      shape.template << text
      shape.definition << text
    end

    def append_shape_name(shape, name)
      shape.percent = true if name.include?("%")
      append_shape(shape, name)
    end

    # Functions are structure (block arity), everything else is a type slot.
    def slotify(shape, type)
      if type.is_a?(Function)
        append_shape(shape, "(")
        type.parameters.each_with_index do |parameter, index|
          append_shape(shape, ", ") if index.positive?
          slotify(shape, parameter)
        end
        append_shape(shape, ") -> ")
        slotify(shape, type.result)
      else
        slot = normalize_slot(shape, type)
        slots = shape.slots
        shape.template << "%" << slots.length.to_s << "%"
        shape.definition << slot
        slots << slot
      end
    end

    def normalize_slot(shape, type)
      case type
      when TypeVariable
        return "Self" if type == shape.receiver

        index = shape.parameter_indexes[type] ||= begin
          shape.parameter_types << type
          shape.parameter_types.length
        end
        "T#{index}"
      when Named
        type.name
      when Generic
        "#{type.name}[#{type.arguments.map { |argument| normalize_slot(shape, argument) }.join(", ")}]"
      when Union
        format_union_slots(type.members.map { |member| normalize_slot(shape, member) }.uniq)
      when Function
        params = type.parameters.map { |parameter| normalize_slot(shape, parameter) }.join(", ")
        "(#{params}) -> #{normalize_slot(shape, type.result)}"
      else
        "Object"
      end
    end

    def capability_sort_key(capability)
      [
        capability.message.to_s,
        capability.arguments.length,
        capability.keywords.keys.map(&:to_s).sort.join(","),
        capability.line
      ]
    end

    def format_union_slots(members)
      members = members.uniq
      has_nil = members.include?("nil")
      members = members.reject { |member| member == "nil" || member == "Nullable[]" }

      nullable_inners = []
      others = []
      members.each do |member|
        if (match = member.match(/\ANullable\[(.*)\]\z/))
          nullable_inners << match[1]
        else
          others << member
        end
      end

      if has_nil || nullable_inners.any?
        inner_parts = (others + nullable_inners).uniq.sort
        inner = inner_parts.length == 1 ? inner_parts.first : inner_parts.join(" | ")
        return "Nullable[#{inner}]"
      end

      others.sort!
      others.length == 1 ? others.first : others.join(" | ")
    end
  end

  class Renderer
    NULLABLE = "Nullable"
    CORE_KEY_TYPES = %w[String Symbol Integer Float Rational Complex bool nil Object].freeze

    attr_reader :helper_registry

    # Type simplification and string polishing are pure and repeat heavily
    # across methods, so renderers of one analysis share these memos.
    def self.memo
      {
        polished: {}, simplified: {}.compare_by_identity, simplified_trees: {}, joined: {},
        argument_texts: {}.compare_by_identity, solved_texts: {}.compare_by_identity,
        result_variables: {}.compare_by_identity,
        subtree_results: {}.compare_by_identity, subtree_reaches: {}.compare_by_identity
      }
    end

    def initialize(method, helper_registry: UniversalHelperRegistry.new([method]), analyzed_method: method, memo: Renderer.memo)
      @method = method
      @analyzed_method = analyzed_method
      @helper_registry = helper_registry
      @polished = memo.fetch(:polished)
      @simplified = memo.fetch(:simplified)
      @simplified_trees = memo.fetch(:simplified_trees)
      @subtree_results = memo[:subtree_results] ||= {}.compare_by_identity
      @subtree_reaches = memo[:subtree_reaches] ||= {}.compare_by_identity
      @tree_reach = nil
      @argument_texts = memo.fetch(:argument_texts)
      @solved_texts = memo.fetch(:solved_texts)
      @joined = memo.fetch(:joined) { {} }
      @result_variables = memo[:result_variables] ||= {}.compare_by_identity
      register_result_variables
      @structural_texts = {}.compare_by_identity
      @consulted_variable = false
      @references = {}.compare_by_identity
      @rendering = Set.new
      @names = {}
      @helpers = analyzed_method.capabilities
        .map(&:receiver)
        .uniq
        .filter_map do |receiver|
          occurrence = helper_registry.occurrence(analyzed_method, receiver)
          [receiver, occurrence] if occurrence
        end
        .to_h
    end

    def text
      helpers = helper_definitions.map do |helper|
        parameters = helper.fetch(:parameters)
        generic = parameters.empty? ? "" : "<#{parameters.join(", ")}>"
        definition = polish_type_string(helper.fetch(:definition))
        "  type #{helper.fetch(:name)}#{generic} = #{definition}"
      end
      constraints = ungrouped_capabilities.zip(rendered_constraints).map do |capability, rendered|
        "  L#{capability.line}: #{rendered}"
      end
      sections = [signature]
      sections << "helpers:\n#{helpers.join("\n")}" unless helpers.empty?
      sections << "constraints:\n#{constraints.join("\n")}" unless constraints.empty?
      sections.join("\n")
    end

    def as_json
      {
        name: @method.name,
        line: @method.line,
        end_line: @method.end_line,
        signature: signature.lines.first.chomp,
        helpers: helper_definitions,
        constraints: rendered_constraints,
        send_constraint_count: @method.capabilities.length,
        locals: rendered_bindings
      }
    end

    private

    # Rendering is pure, so the pieces shared by text and as_json render once.
    def signature
      @signature ||= begin
        params = @method.parameters.map { |parameter| render_parameter(parameter) }.join(", ")
        "#{@method.name} : (#{params}) -> #{render(@method.result, grounded_only: true)}"
      end
    end

    def rendered_constraints
      @rendered_constraints ||= ungrouped_capabilities.map { |capability| render_capability(capability) }
    end

    # Local variables, parameters, and ivars with their rendered types, for
    # editor hover support.
    def rendered_bindings
      bindings = {}
      @method.locals.each { |name, type| bindings[name.to_s] = render(type, grounded_only: true, skip_helpers: true) }
      @method.ivars.each { |name, type| bindings[name.to_s] = render(type, grounded_only: true, skip_helpers: true) }
      bindings
    end

    def render_parameter(parameter)
      return "... #{render(parameter.type)}" if parameter.kind == :forwarding

      prefix = case parameter.kind
      when :rest then "*"
      when :keyword_rest then "**"
      when :block then "&"
      else ""
      end
      suffix = %i[keyword optional_keyword].include?(parameter.kind) ? ":" : ""
      optional = %i[optional optional_keyword].include?(parameter.kind) ? "?" : ""
      type_text = render_parameter_type(parameter)
      "#{prefix}#{parameter.name}#{suffix}#{optional} #{type_text}"
    end

    def render_parameter_type(parameter)
      concrete = render(parameter.type, skip_helpers: true)
      return concrete if concrete_parameter_type?(concrete)

      analyzed = @analyzed_method.parameters.find { |candidate| candidate.name == parameter.name }
      analyzed_variable = analyzed&.type
      analyzed_variable = nil unless analyzed_variable.is_a?(TypeVariable)

      if analyzed_variable
        record = render_record_type(analyzed_variable)
        return record if record

        return render_helper_reference(@helpers.fetch(analyzed_variable)) if @helpers.key?(analyzed_variable)
      end

      render(parameter.type, structural: true)
    end

    def concrete_parameter_type?(text)
      return false if text == "Object"
      return false if text.start_with?("{ ")
      return false if text.match?(/\ACapability_[a-f0-9]+/)

      true
    end

    def render_record_type(variable)
      capabilities = solved_capabilities_for(variable).select { |capability| capability.message == :[] }
      fields = Hash.new { |hash, key| hash[key] = [] }
      capabilities.each do |capability|
        field = field_name_from_index_key(capability.arguments.first)
        next unless field

        fields[field] << capability.result
      end
      return nil if fields.empty?

      body = fields.sort.map do |name, types|
        rendered = join_union(types.map { |type| render(type, grounded_only: true, skip_helpers: true) }.uniq)
        "#{name}: #{rendered}"
      end.join(", ")
      "{ #{body} }"
    end

    def solved_capabilities_for(analyzed_variable)
      analyzed_by_receiver.fetch(analyzed_variable, EMPTY).map do |analyzed_capability|
        solved_at(analyzed_capability).find do |solved_capability|
          index_key_eq?(solved_capability.arguments, analyzed_capability.arguments)
        end || analyzed_capability
      end
    end

    EMPTY = [].freeze

    # Capability lookups by identity-hashed variables or by source position,
    # in list order, so each finds what a scan of the list would.
    def solved_by_receiver = @solved_by_receiver ||= @method.capabilities.group_by(&:receiver)
    def analyzed_by_receiver = @analyzed_by_receiver ||= @analyzed_method.capabilities.group_by(&:receiver)

    def solved_at(capability)
      @solved_by_position ||= @method.capabilities.group_by { |solved| [solved.line, solved.message] }
      @solved_by_position.fetch([capability.line, capability.message], EMPTY)
    end

    def analyzed_by_result
      @analyzed_by_result ||= @analyzed_method.capabilities.each_with_object({}) do |capability, index|
        index[capability.result] = capability unless index.key?(capability.result)
      end
    end

    # A variable that is no renderer's capability result renders as Object in
    # every renderer, so texts reaching only such variables are shared. Texts
    # shared before a renderer adds new result variables may not hold for it.
    def register_result_variables
      added = false
      @analyzed_method.capabilities.each do |capability|
        result = capability.result
        next if !result.is_a?(TypeVariable) || @result_variables.key?(result)

        @result_variables[result] = true
        added = true
      end
      return unless added

      @argument_texts.clear
      @solved_texts.clear
    end

    def index_key_eq?(left_args, right_args)
      left_args.zip(right_args).all? do |left, right|
        resolve_index_key(left) == resolve_index_key(right)
      end
    end

    def resolve_index_key(key)
      case key
      when Named then key.name
      else render(key, skip_helpers: true)
      end
    end

    def field_name_from_index_key(key)
      case key
      when Named
        return key.name unless CORE_KEY_TYPES.include?(key.name)
      end
      nil
    end

    def record_parameter?(variable)
      analyzed_by_receiver.fetch(variable, EMPTY).any? do |capability|
        capability.message == :[] && field_name_from_index_key(capability.arguments.first)
      end
    end

    def record_field_slot?(capability)
      return false unless capability.message == :[]

      receiver = capability.receiver
      return false unless receiver.is_a?(TypeVariable) && record_parameter?(receiver)

      field_name_from_index_key(capability.arguments.first)
    end

    def render(type, structural: false, grounded_only: false, skip_helpers: false, depth: 0)
      return "Object" if depth > 48

      type = simplify(type)
      rendered = case type
      when TypeVariable
        if @helpers.key?(type) && !skip_helpers
          render_helper_reference(@helpers.fetch(type))
        else
          render_structural_variable(type, depth: depth + 1)
        end
      when Named
        type.name
      when Generic
        if type.name == NULLABLE && type.arguments.length == 1
          "Nullable[#{render(type.arguments.first, grounded_only:, skip_helpers:, depth: depth + 1)}]"
        else
          "#{type.name}[#{type.arguments.map { |argument| render(argument, grounded_only:, skip_helpers:, depth: depth + 1) }.join(", ")}]"
        end
      when Union
        join_union(type.members.map { |member| render(member, grounded_only:, skip_helpers:, depth: depth + 1) })
      when Function
        parameters = type.parameters.map { |parameter| render(parameter, grounded_only:, skip_helpers:, depth: depth + 1) }.join(", ")
        "(#{parameters}) -> #{render(type.result, grounded_only:, skip_helpers:, depth: depth + 1)}"
      else
        "Object"
      end
      polish_type_string(rendered)
    end

    # Variables and named types come back as they are, wherever they sit.
    def simplify(type, seen = nil, depth = 0)
      return type unless type.is_a?(Union) || type.is_a?(Generic) || type.is_a?(Function)
      if seen
        return @tree_reach ? simplify_subtree(type, seen, depth) : simplify_uncached(type, seen, depth)
      end

      @simplified.fetch(type) do
        @simplified[type] =
          if (result = @subtree_results[type])
            result
          elsif tree_shaped?(type)
            @simplified_trees.fetch(type) { @simplified_trees[type] = simplify_tree(type) }
          else
            simplify_uncached(type, nil, 0)
          end
      end
    end

    MAX_SIMPLIFY_DEPTH = 48

    # Walking a tree meets no node twice, and the results it simplifies
    # again are built fresh during the walk, so the seen set never answers
    # and is skipped. A subtree then simplifies the same wherever it sits
    # unless the depth cutoff truncates it: each result records how far
    # below its node the work went, and is reused wherever that stays
    # within the cutoff, so trees sharing subtrees share their results.
    #
    # Every node in a result comes from the subtree of one input node, and
    # sibling subtrees of a tree are disjoint, so results are trees too and
    # every key here is one. A node that simplifies to an equal term stands
    # for its own result, which lets rendering, as it simplifies each part
    # of a result again, find those parts already done.
    def simplify_tree(type)
      @tree_reach = 0
      simplify_subtree(type, true, 0)
    ensure
      @tree_reach = nil
    end

    def simplify_subtree(type, seen, depth)
      if (result = @subtree_results[type])
        reach = depth + @subtree_reaches[type]
        if reach <= MAX_SIMPLIFY_DEPTH
          @tree_reach = reach if reach > @tree_reach
          return result
        end
      end

      outer = @tree_reach
      @tree_reach = depth
      result = simplify_uncached(type, seen, depth)
      result = type if result.eql?(type)
      reach = @tree_reach
      if reach <= MAX_SIMPLIFY_DEPTH
        @subtree_results[type] = result
        @subtree_reaches[type] = reach - depth
      end
      @tree_reach = outer if outer > reach
      result
    end

    # Simplifying returns a node it has already visited untouched, so its
    # result follows the type's structure alone only when no composite node
    # occurs twice; such types share results across structurally equal
    # copies.
    def tree_shaped?(type)
      visited = {}.compare_by_identity
      stack = [type]
      until stack.empty?
        node = stack.pop
        case node
        when Union
          return false if visited.key?(node)

          visited[node] = true
          stack.concat(node.members)
        when Generic
          return false if visited.key?(node)

          visited[node] = true
          stack.concat(node.arguments)
        when Function
          return false if visited.key?(node)

          visited[node] = true
          stack.concat(node.parameters) << node.result
        end
      end
      true
    end

    def simplify_uncached(type, seen, depth)
      if @tree_reach
        @tree_reach = depth if depth > @tree_reach
        return type if depth > MAX_SIMPLIFY_DEPTH
      else
        return type if depth > MAX_SIMPLIFY_DEPTH

        seen ||= {}.compare_by_identity
        return type if seen.key?(type)

        seen[type] = true
      end
      case type
      when Union
        members = []
        type.members.each do |member|
          if member.is_a?(Union)
            member.members.each { |inner| members << simplify(inner, seen, depth + 1) }
          else
            members << simplify(member, seen, depth + 1)
          end
        end
        members = dedupe_types(members)
        return members.first if members.length == 1

        if members.any? { |member| nil_type?(member) }
          rest = members.reject { |member| nil_type?(member) }
          # A union built here is new, so no result can be stored for it.
          inner = rest.length == 1 ? simplify(rest.first, seen, depth + 1) : simplify_uncached(Union.new(rest), seen, depth + 1)
          return Generic.new(NULLABLE, [inner]) unless nil_type?(inner)

          return inner
        end

        Union.new(members)
      when Generic
        arguments = type.arguments.map { |argument| simplify(argument, seen, depth + 1) }
        if type.name == NULLABLE && arguments.length == 1
          inner = unwrap_nullable(arguments.first)
          return Generic.new(NULLABLE, [inner.is_a?(Generic) && inner.name == NULLABLE ? inner.arguments.first : inner])
        end

        Generic.new(type.name, arguments)
      when Function
        Function.new(
          type.parameters.map { |parameter| simplify(parameter, seen, depth + 1) },
          simplify(type.result, seen, depth + 1)
        )
      else
        type
      end
    end

    def nil_type?(type)
      type.is_a?(Named) && type.name == "nil"
    end

    def unwrap_nullable(type)
      while type.is_a?(Generic) && type.name == NULLABLE && type.arguments.length == 1
        type = type.arguments.first
      end
      type
    end

    def nullable_type(inner)
      inner = unwrap_nullable(inner)
      return inner if nil_type?(inner)

      Generic.new(NULLABLE, [inner])
    end

    def flatten_nullable_type(type)
      return type unless type.is_a?(Generic) && type.name == NULLABLE && type.arguments.length == 1

      Generic.new(NULLABLE, [unwrap_nullable(type.arguments.first)])
    end

    def dedupe_types(types)
      types.uniq
    end

    # Nullable[T] when nil is present; otherwise a sorted, deduped union. Never
    # drop members — an incomplete inference is shown as Object, not elided.
    def join_union(rendered)
      @joined.fetch(rendered) { @joined[rendered.frozen? ? rendered : rendered.dup.freeze] = join_union_uncached(rendered).freeze }
    end

    def join_union_uncached(rendered)
      parts = []
      has_nil = false
      rendered.uniq.each do |member|
        case member
        when "nil"
          has_nil = true
        when "Nullable[]"
          next
        else
          if (match = member.match(/\ANullable\[(.*)\]\z/m))
            has_nil = true
            parts.concat(split_top_level_union(match[1]))
          else
            parts.concat(split_top_level_union(member))
          end
        end
      end

      parts = parts.reject { |part| part == "nil" || part.empty? }.uniq.sort
      if has_nil
        inner = parts.length == 1 ? parts.first : parts.join(" | ")
        inner = inner.match(/\ANullable\[(.*)\]\z/m)&.then { |match| match[1] } || inner
        return "Nullable[#{inner}]"
      end

      parts.length == 1 ? parts.first : parts.join(" | ")
    end

    # Rewrite nil-union slots inside helper definition text and similar
    # pre-rendered type strings from the registry.
    # Every rewrite below needs "nil" or "Nullable[" in the text.
    def polish_type_string(text)
      return text unless text.is_a?(String)
      return text unless text.include?("nil") || text.include?("Nullable[")

      @polished[text] ||= polish_uncached(text).freeze
    end

    # The patterns need these literals, and scanning for a literal is far
    # cheaper than a regex backtracking through every position of a long text.
    def polish_uncached(text)
      text = flatten_nullable_text(text)
      8.times do
        previous = text
        if text.include?(" | nil") || text.include?("nil | ")
          text = text.gsub(/([A-Za-z0-9_:|\[\], ]+ \|\ nil|nil \|\ [A-Za-z0-9_:|\[\], ]+)/) do |match|
            join_union(split_top_level_union(match))
          end
        end
        if text.include?("Nullable[")
          text = text.gsub(/Nullable\[([^\]]+)\]/) do |_match|
            inner = join_union(split_top_level_union(Regexp.last_match(1)))
            inner.start_with?("Nullable[") ? inner : "Nullable[#{inner}]"
          end
        end
        text = flatten_nullable_text(text)
        break if text == previous
      end
      text
    end

    def flatten_nullable_text(text)
      8.times do
        previous = text
        text = text.gsub("Nullable[Nullable[", "Nullable[")
        break if text == previous
      end
      text
    end

    OPEN_BRACKET = "[".ord
    CLOSE_BRACKET = "]".ord
    SPACE = " ".ord
    PIPE = "|".ord

    # Scans bytes so no per-character strings are allocated; the separators
    # are ASCII, which never occurs inside a multibyte UTF-8 sequence.
    def split_top_level_union(text)
      parts = []
      depth = 0
      start = 0
      index = 0
      length = text.bytesize
      while index < length
        byte = text.getbyte(index)
        if byte == OPEN_BRACKET
          depth += 1
        elsif byte == CLOSE_BRACKET
          depth -= 1
        elsif depth.zero? && byte == SPACE && text.getbyte(index + 1) == PIPE && text.getbyte(index + 2) == SPACE
          parts << text.byteslice(start, index - start).strip
          index += 3
          start = index
          next
        end
        index += 1
      end
      parts << text.byteslice(start, length - start).strip
      parts.reject(&:empty?)
    end

    # Only reached from render, never while a helper argument is being
    # rendered, so the text depends on the variable and depth alone.
    def render_structural_variable(variable, depth: 0)
      return "Object" if depth > 16 || !solved_by_receiver.key?(variable)

      memo = @structural_texts[variable] ||= {}
      memo.fetch(depth) { memo[depth] = render_structural_variable_uncached(variable, depth).freeze }
    end

    def render_structural_variable_uncached(variable, depth)
      capabilities = solved_by_receiver.fetch(variable, EMPTY)
      return "Object" if capabilities.empty?

      body = capabilities.first(24).map { |capability| render_send(capability, depth: depth + 1) }.uniq.join("; ")
      "{ #{body} }"
    end

    def render_capability(capability)
      "#{render(capability.receiver)} responds to #{render_send(capability)}"
    end

    def render_send(capability, depth: 0)
      return "..." if depth > 16

      arguments = capability.arguments.map { |argument| render(argument, depth: depth + 1) }
      arguments.concat(capability.keywords.map { |name, value| "#{name}: #{render(value, depth: depth + 1)}" })
      "#{capability.message}(#{arguments.join(", ")}) -> #{render(capability.result, depth: depth + 1)}"
    end

    def helper_definitions
      @helper_definitions ||= @helpers.values.uniq.map do |occurrence|
        definition = occurrence.fetch(:definition)
        {
          name: definition.fetch(:name),
          reference: render_helper_reference(occurrence),
          parameters: definition.fetch(:parameters),
          definition: polish_type_string(definition.fetch(:definition))
        }
      end.uniq { |helper| [helper.fetch(:name), helper.fetch(:definition)] }
    end

    def ungrouped_capabilities
      @ungrouped_capabilities ||= begin
        grouped_lines = @analyzed_method.capabilities
          .select { |capability| capability.receiver.is_a?(TypeVariable) && @helpers.key?(capability.receiver) }
          .map(&:line)
          .to_set
        @method.capabilities.reject { |capability| grouped_lines.include?(capability.line) }
      end
    end

    # Never reached while a variable is being rendered, so the text depends
    # only on the occurrence.
    def render_helper_reference(occurrence)
      @references[occurrence] ||= begin
        arguments = occurrence.fetch(:arguments).map { |argument| render_helper_argument(argument) }
        name = occurrence.fetch(:definition).fetch(:name)
        reference = arguments.empty? ? name : "#{name}[#{arguments.join(", ")}]"
        polish_type_string(reference)
      end
    end

    # Text for a type reached without consulting a variable is the same in
    # every renderer, so renderers share it.
    def render_helper_argument(type)
      type = simplify(type) if type.is_a?(Union) || type.is_a?(Generic)
      cached = @argument_texts[type]
      return cached if cached

      outer = @consulted_variable
      @consulted_variable = false
      text = render_helper_argument_uncached(type)
      @argument_texts[type] = text unless @consulted_variable
      @consulted_variable ||= outer
      text
    end

    def render_helper_argument_uncached(type)
      case type
      when TemplateArgument
        substituted = type.template.gsub(/\bT(\d+)\b/) do
          render_helper_argument(type.arguments[Regexp.last_match(1).to_i - 1])
        end
        polish_type_string(substituted)
      when TypeVariable
        return "Object" unless @result_variables.key?(type)

        @consulted_variable = true
        # solved_type_for_variable matches sends by line and message, so a
        # variable can map to a sibling send whose type contains it again.
        return "Object" if @rendering.include?(type)

        @rendering << type
        begin
          render_solved(solved_type_for_variable(type))
        ensure
          @rendering.delete(type)
        end
      when Named
        type.name
      when Generic
        "#{type.name}[#{type.arguments.map { |argument| render_helper_argument(argument) }.join(", ")}]"
      when Union
        join_union(type.members.map { |member| render_helper_argument(member) })
      when Function
        parameters = type.parameters.map { |parameter| render_helper_argument(parameter) }.join(", ")
        "(#{parameters}) -> #{render_helper_argument(type.result)}"
      else
        "Object"
      end
    end

    # A solved type renders unsimplified at the top, unlike an argument.
    def render_solved(solved)
      cached = @solved_texts[solved]
      return cached if cached

      outer = @consulted_variable
      @consulted_variable = false
      text = render_solved_uncached(solved)
      @solved_texts[solved] = text unless @consulted_variable
      @consulted_variable ||= outer
      text
    end

    def render_solved_uncached(solved)
      case solved
      when Named then solved.name
      when Generic
        if solved.name == NULLABLE && solved.arguments.length == 1
          return "Nullable[#{render_helper_argument(solved.arguments.first)}]"
        end

        "#{solved.name}[#{solved.arguments.map { |argument| render_helper_argument(argument) }.join(", ")}]"
      when Union
        join_union(solved.members.map { |member| render_helper_argument(member) })
      when Function
        parameters = solved.parameters.map { |parameter| render_helper_argument(parameter) }.join(", ")
        "(#{parameters}) -> #{render_helper_argument(solved.result)}"
      else
        "Object"
      end
    end

    def solved_type_for_variable(analyzed_variable)
      analyzed_capability = analyzed_by_result[analyzed_variable]
      return nil unless analyzed_capability

      solved_at(analyzed_capability).first&.result
    end
  end

  class HtmlDocument
    def initialize(reports, analyzed_files: reports.map(&:first).uniq, parse_errors: {})
      @reports = reports
      @grouped = reports.group_by(&:first)
      @analyzed_files = analyzed_files
      @parse_errors = parse_errors
      @helper_registry = reports.first&.last&.helper_registry
    end

    def render
      method_count = @reports.length
      constraint_count = @reports.sum { |_, renderer| renderer.as_json.fetch(:send_constraint_count) }
      generated_at = Time.now.utc.strftime("%Y-%m-%d %H:%M UTC")

      <<~HTML
        <!doctype html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>Autotype inferred types</title>
          <style>
            :root {
              color-scheme: light dark;
              --bg: #111318;
              --panel: #181b22;
              --panel-2: #20242d;
              --text: #e8eaf0;
              --muted: #9ba3b4;
              --line: #343a46;
              --accent: #78a9ff;
              --capability: #b6e3a8;
              --code: #f1d18a;
            }
            * { box-sizing: border-box; }
            html { scroll-behavior: smooth; }
            body {
              margin: 0;
              background: var(--bg);
              color: var(--text);
              font: 14px/1.5 ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            }
            a { color: var(--accent); text-decoration: none; }
            a:hover { text-decoration: underline; }
            code {
              font: 13px/1.55 ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
              overflow-wrap: anywhere;
            }
            .layout { display: grid; grid-template-columns: 280px minmax(0, 1fr); min-height: 100vh; }
            aside {
              position: sticky;
              top: 0;
              height: 100vh;
              overflow: auto;
              border-right: 1px solid var(--line);
              background: var(--panel);
              padding: 20px 16px;
            }
            main { width: min(1100px, 100%); padding: 32px 42px 80px; }
            h1 { margin: 0 0 6px; font-size: 24px; }
            h2 { margin: 42px 0 12px; font-size: 18px; scroll-margin-top: 20px; }
            h3 { margin: 0; font-size: 14px; font-weight: 600; }
            .muted { color: var(--muted); }
            .summary { display: flex; gap: 24px; margin: 18px 0 28px; }
            .summary strong { display: block; font-size: 20px; }
            .summary span { color: var(--muted); font-size: 12px; }
            #search {
              width: 100%;
              margin: 18px 0;
              padding: 9px 10px;
              border: 1px solid var(--line);
              border-radius: 6px;
              background: var(--panel-2);
              color: var(--text);
            }
            nav ul { margin: 0; padding: 0; list-style: none; }
            nav li { margin: 5px 0; }
            nav a { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
            .method {
              margin: 10px 0;
              border: 1px solid var(--line);
              border-radius: 7px;
              background: var(--panel);
              overflow: hidden;
            }
            .method header { padding: 12px 15px; border-bottom: 1px solid var(--line); }
            .line { color: var(--muted); font-size: 12px; }
            .signature {
              display: block;
              padding: 13px 15px;
              color: var(--code);
              background: var(--panel-2);
              white-space: pre-wrap;
              overflow-wrap: anywhere;
            }
            .helpers { padding: 11px 15px 4px; border-top: 1px solid var(--line); }
            .helpers h4 { margin: 0 0 7px; color: var(--muted); font-size: 11px; letter-spacing: .08em; text-transform: uppercase; }
            .helper { display: block; padding: 5px 0 8px; }
            .helper-name { display: block; color: var(--accent); font-weight: 700; overflow-wrap: anywhere; }
            .helper-definition { display: block; padding-top: 2px; color: var(--capability); overflow-wrap: anywhere; }
            .universal-types { margin: 32px 0 44px; }
            .universal-type { padding: 10px 0; border-bottom: 1px solid var(--line); scroll-margin-top: 20px; }
            .universal-type code { display: block; }
            .uses { color: var(--muted); font-size: 12px; }
            .constraints { margin: 0; padding: 10px 15px 13px 34px; }
            .constraints li { padding: 2px 0; color: var(--capability); }
            .empty { padding: 10px 15px; color: var(--muted); }
            .warnings { margin: 24px 0; padding: 14px 16px; border: 1px solid var(--line); border-radius: 7px; }
            .warnings h2 { margin: 0 0 8px; font-size: 15px; }
            .warnings ul { margin: 0; padding-left: 20px; }
            .hidden { display: none; }
            @media (prefers-color-scheme: light) {
              :root {
                --bg: #f7f8fa;
                --panel: #fff;
                --panel-2: #f1f3f6;
                --text: #20242d;
                --muted: #677084;
                --line: #d9dde5;
                --accent: #245fb5;
                --capability: #276738;
                --code: #754f00;
              }
            }
            @media (max-width: 760px) {
              .layout { display: block; }
              aside { position: static; height: auto; border-right: 0; border-bottom: 1px solid var(--line); }
              main { padding: 24px 18px 60px; }
            }
          </style>
        </head>
        <body>
          <div class="layout">
            <aside>
              <h1>Inferred types</h1>
              <div class="muted">Autotype · #{escape(generated_at)}</div>
              <input id="search" type="search" placeholder="Filter methods or types…" aria-label="Filter methods or types">
              <nav aria-label="Source files">
                <ul>#{navigation}</ul>
              </nav>
            </aside>
            <main>
              <h1>Syntax-less Ruby typedoc</h1>
              <p class="muted">Intraprocedural structural inference from Ruby message sends. Signatures are generalized at each method boundary.</p>
              <div class="summary">
                <div><strong>#{@analyzed_files.length}</strong><span>files analyzed</span></div>
                <div><strong>#{@grouped.length}</strong><span>files with methods</span></div>
                <div><strong>#{method_count}</strong><span>methods</span></div>
                <div><strong>#{constraint_count}</strong><span>send constraints</span></div>
                <div><strong>#{universal_definitions.length}</strong><span>universal types</span></div>
              </div>
              #{parse_failure_section}
              #{universal_type_section}
              #{sections}
            </main>
          </div>
          <script>
            const search = document.querySelector("#search");
            search.addEventListener("input", () => {
              const query = search.value.trim().toLowerCase();
              document.querySelectorAll(".method").forEach((element) => {
                element.classList.toggle("hidden", query && !element.dataset.search.includes(query));
              });
              document.querySelectorAll(".file-section").forEach((section) => {
                const visible = section.querySelector(".method:not(.hidden)");
                section.classList.toggle("hidden", query && !visible);
              });
            });
          </script>
        </body>
        </html>
      HTML
    end

    private

    def navigation
      files = @grouped.keys.sort.each_with_index.map do |path, index|
        %(<li><a href="#file-#{index}" title="#{escape(path)}">#{escape(path)}</a></li>)
      end
      ([%(<li><a href="#universal-types">Universal capability types</a></li>)] + files).join
    end

    def parse_failure_section
      return "" if @parse_errors.empty?

      items = @parse_errors.sort.map do |path, errors|
        "<li><code>#{escape(path)}</code>: #{escape(errors.join("; "))}</li>"
      end.join
      <<~HTML
        <section class="warnings">
          <h2>Parse failures (#{@parse_errors.length})</h2>
          <ul>#{items}</ul>
        </section>
      HTML
    end

    def sections
      @grouped.sort_by(&:first).each_with_index.map do |(path, entries), index|
        methods = entries.map { |_, renderer| method_card(renderer) }.join
        <<~HTML
          <section class="file-section" id="file-#{index}">
            <h2>#{escape(path)}</h2>
            #{methods}
          </section>
        HTML
      end.join
    end

    def universal_type_section
      definitions = universal_definitions.map do |definition|
        parameters = definition.fetch(:parameters)
        generic = parameters.empty? ? "" : "&lt;#{escape(parameters.join(", "))}&gt;"
        <<~HTML
          <div class="universal-type" id="type-#{escape(definition.fetch(:name))}">
            <code><span class="helper-name">type #{escape(definition.fetch(:name))}#{generic}</span> = <span class="helper-definition">#{escape(definition.fetch(:definition))}</span></code>
            <span class="uses">Used by #{definition.fetch(:uses)} inferred receiver#{definition.fetch(:uses) == 1 ? "" : "s"}</span>
          </div>
        HTML
      end.join

      <<~HTML
        <section class="universal-types" id="universal-types">
          <h2>Universal capability types</h2>
          <p class="muted">Canonical structural shapes shared by every analyzed file. Free types are represented as generic parameters.</p>
          #{definitions}
        </section>
      HTML
    end

    def universal_definitions
      @helper_registry&.definitions || []
    end

    def method_card(renderer)
      report = renderer.as_json
      helpers = report.fetch(:helpers)
      constraints = report.fetch(:constraints)
      helper_html = if helpers.empty?
        ""
      else
        rows = helpers.map do |helper|
          <<~HTML
            <div class="helper">
              <a class="helper-name" href="#type-#{escape(helper.fetch(:name))}">#{escape(helper.fetch(:name))}</a>
              <code class="helper-definition">#{escape(helper.fetch(:reference))}</code>
            </div>
          HTML
        end.join
        %(<section class="helpers"><h4>Uses universal types</h4>#{rows}</section>)
      end
      constraint_html = if constraints.empty?
        helpers.empty? ? %(<div class="empty">No structural send constraints</div>) : ""
      else
        items = constraints.map { |constraint| "<li><code>#{escape(constraint)}</code></li>" }.join
        %(<ol class="constraints">#{items}</ol>)
      end
      helper_text = helpers.flat_map { |helper| helper.values }
      searchable = ([report.fetch(:name), report.fetch(:signature)] + helper_text + constraints).join(" ").downcase

      <<~HTML
        <article class="method" data-search="#{escape(searchable)}">
          <header>
            <h3>#{escape(report.fetch(:name))} <span class="line">line #{report.fetch(:line)}</span></h3>
          </header>
          <code class="signature">#{escape(report.fetch(:signature))}</code>
          #{helper_html}
          #{constraint_html}
        </article>
      HTML
    end

    def escape(value)
      CGI.escapeHTML(value.to_s)
    end
  end

  # Deterministic, LLM-free naming. Names are derived from the capability
  # shape itself: a Ruby-vocabulary table for common messages, snake_case
  # morphology for the rest, and a detail-escalation ladder that resolves
  # collisions by folding in more of the shape (all sends, then result types,
  # then argument types, then a full injective mangle of the definition).
  class HeuristicCapabilityNamer
    MAX_LEVEL = 5
    GREEK_WORDS = /(?:Alpha|Beta|Gamma|Delta|Epsilon|Zeta|Eta|Theta|Iota|Kappa|Lambda|Mu|Nu|Xi|Omicron|Pi|Rho|Sigma|Tau|Upsilon|Phi|Chi|Psi|Omega)(?=[A-Z]|$)/
    KNOWN = {
      "to_s" => "Stringifiable", "to_str" => "Stringifiable", "inspect" => "Inspectable",
      "to_i" => "IntegerConvertible", "to_int" => "IntegerConvertible", "to_f" => "FloatConvertible",
      "to_h" => "HashConvertible", "to_a" => "ArrayConvertible", "to_sym" => "Symbolizable",
      "to_json" => "JsonSerializable", "to_set" => "SetConvertible", "to_proc" => "ProcConvertible",
      "each" => "Enumerable", "each_with_index" => "IndexEnumerable", "each_with_object" => "ObjectEnumerable",
      "each_pair" => "PairEnumerable", "each_key" => "KeyEnumerable", "each_value" => "ValueEnumerable",
      "map" => "Mappable", "collect" => "Mappable", "flat_map" => "FlatMappable", "filter_map" => "FilterMappable",
      "select" => "Selectable", "filter" => "Filterable", "reject" => "Rejectable",
      "reduce" => "Reducible", "inject" => "Reducible", "sum" => "Summable",
      "find" => "Findable", "detect" => "Findable", "include?" => "MembershipTestable",
      "size" => "Sizable", "length" => "Measurable", "count" => "Countable",
      "call" => "Callable", "new" => "Instantiable", "create" => "Creatable", "build" => "Buildable",
      "[]" => "Indexable", "[]=" => "IndexWritable", "<<" => "Appendable", "push" => "Pushable",
      "+" => "Addable", "-" => "Subtractable", "*" => "Multipliable", "/" => "Divisible",
      "%" => "Modulable", "**" => "Exponentiable",
      "==" => "Equatable", "!=" => "Equatable", "eql?" => "Equatable", "equal?" => "Equatable",
      "<=>" => "Comparable", "<" => "Comparable", ">" => "Comparable", "<=" => "Comparable", ">=" => "Comparable",
      "=~" => "Matchable", "match" => "Matchable", "match?" => "Matchable",
      "!" => "Negatable", "&" => "Conjoinable", "|" => "Disjoinable", "^" => "ExclusiveDisjoinable",
      "nil?" => "NilTestable", "empty?" => "EmptinessTestable", "any?" => "AnyTestable", "all?" => "AllTestable",
      "present?" => "PresenceTestable", "blank?" => "BlankTestable", "presence" => "PresenceReadable",
      "dup" => "Duplicable", "clone" => "Clonable", "freeze" => "Freezable", "frozen?" => "FrozenTestable",
      "tap" => "Tappable", "then" => "Chainable", "yield_self" => "Chainable", "itself" => "IdentityReadable",
      "fetch" => "Fetchable", "dig" => "Diggable", "key?" => "KeyTestable", "has_key?" => "KeyTestable",
      "keys" => "KeysReadable", "values" => "ValuesReadable", "merge" => "Mergeable", "merge!" => "Mergeable",
      "join" => "Joinable", "split" => "Splittable", "strip" => "Strippable", "chomp" => "Chompable",
      "gsub" => "GlobalSubstitutable", "sub" => "Substitutable",
      "downcase" => "Downcaseable", "upcase" => "Upcaseable", "capitalize" => "Capitalizable",
      "start_with?" => "PrefixTestable", "end_with?" => "SuffixTestable",
      "first" => "FirstReadable", "last" => "LastReadable", "min" => "MinReadable", "max" => "MaxReadable",
      "compact" => "Compactable", "flatten" => "Flattenable", "uniq" => "Uniquable", "sort" => "Sortable",
      "sort_by" => "KeySortable", "group_by" => "Groupable", "reverse" => "Reversible", "raise" => "Raisable",
      "emit" => "Emittable", "respond_to?" => "RespondTestable",
      "send" => "MessageSendable", "public_send" => "MessageSendable"
    }.freeze

    def initialize(registry)
      @registry = registry
    end

    def name!
      # Every round renames each definition at its current level, which only
      # rises; a definition's name at a level never changes within a run.
      @names = {}.compare_by_identity
      @parsed_sends = {}
      levels = Hash.new(1)
      names = {}
      # Nothing is renamed until the rounds end, so the definitions keep
      # their order, and a name normalizes the same in every round.
      definitions = @registry.definitions
      normalized = {}
      (MAX_LEVEL * 4).times do
        names = definitions.to_h do |definition|
          [definition.fetch(:id), name_for(definition, levels[definition.fetch(:id)])]
        end
        clusters = definitions
          .group_by do |definition|
            name = names[definition.fetch(:id)]
            normalized.fetch(name) { normalized[name] = @registry.normalize_semantic_name(name) }
          end
          .select { |_, members| members.length > 1 }
        break if clusters.empty?

        progressed = false
        clusters.each_value do |members|
          members.sort_by { |definition| [-definition.fetch(:uses), definition.fetch(:id)] }.drop(1).each do |definition|
            id = definition.fetch(:id)
            next unless levels[id] < MAX_LEVEL

            levels[id] += 1
            progressed = true
          end
        end
        break unless progressed
      end
      names = de_greek_names!(names)
      @registry.apply_names!(names)
      names
    end

    private

    # Replace any leftover Alpha/Beta/… fragments with words derived from
    # the helper's concrete slot types, or drop generic slots entirely.
    def de_greek_names!(names)
      @registry.definitions.each_with_object(names.dup) do |definition, result|
        id = definition.fetch(:id)
        name = result[id]
        next unless greek?(name)

        replacement = non_greek_name(definition)
        result[id] = replacement if replacement && !replacement.empty?
      end
    end

    def greek?(name)
      name.match?(GREEK_WORDS)
    end

    def non_greek_name(definition)
      MAX_LEVEL.downto(1) do |level|
        candidate = name_for(definition, level)
        return candidate unless greek?(candidate)
      end

      sends = parse_sends(definition.fetch(:definition))
      compose(sends)
    end

    def name_for(definition, level)
      memo = (@names ||= {}.compare_by_identity)[definition] ||= {}
      memo.fetch(level) { memo[level] = name_for_uncached(definition, level) }
    end

    def name_for_uncached(definition, level)
      sends = parse_sends(definition.fetch(:definition))
      slots = definition.fetch(:slots)
      case level
      when 1 then compose(sends.first(2))
      when 2 then compose(sends)
      when 3 then "#{type_words(sends.map { |send| send.fetch(:result) }, slots: slots)}#{compose(sends)}"
      when 4
        argument_words = type_words(sends.flat_map { |send| send.fetch(:arguments) }, slots: slots)
        result_words = type_words(sends.map { |send| send.fetch(:result) }, slots: slots)
        "#{argument_words}#{result_words}#{compose(sends)}"
      else
        "#{mangle(definition.fetch(:definition), slots: slots)}Able"
      end
    end

    def compose(sends)
      final = single_name(sends.last)
      stems = sends[0...-1].map { |send| stem(send.fetch(:message)) }.uniq
      stems.reject! { |candidate| final.start_with?(candidate) }
      "#{stems.join}#{final}"
    end

    def single_name(send)
      message = send.fetch(:message)
      return KNOWN.fetch(message) if KNOWN.key?(message)
      return "#{stem(message)}Testable" if message.end_with?("?")
      return "#{stem(message)}Writable" if message.end_with?("=")

      tokens = message.delete_suffix("!").split("_")
      if send.fetch(:arguments).any? || message.end_with?("!")
        objects = tokens.drop(1).map(&:capitalize).join
        "#{objects}#{verbify(tokens.first).capitalize}"
      else
        "#{stem(message)}Readable"
      end
    end

    def stem(message)
      unless message.match?(/[a-z0-9]/i)
        known = KNOWN[message]
        return known ? known.sub(/(?:t?able|ible)\z/, "") : "Op"
      end

      message.delete_suffix("?").delete_suffix("!").delete_suffix("=").split("_").map(&:capitalize).join
    end

    def verbify(word)
      if word.match?(/[^aeiouy]y\z/)
        "#{word[0..-2]}iable"
      elsif word.end_with?("e")
        "#{word[0..-2]}able"
      elsif word.match?(/[^aeiouy][aeiouy][bdgklmnprtv]\z/)
        "#{word}#{word[-1]}able"
      else
        "#{word}able"
      end
    end

    def type_words(types, slots: [])
      dedupe_adjacent(type_tokens(types.join(", "), slots: slots)).join
    end

    def dedupe_adjacent(words)
      words.each_with_object([]) { |word, acc| acc << word unless acc.last == word }
    end

    def type_tokens(type, slots: [], depth: 0, resolving: nil)
      return [] if depth > 12

      type.scan(/[A-Za-z0-9_]+|::|->|[|\[\],()]/).flat_map do |token|
        case token
        when "|" then ["Or"]
        when "[" then ["Of"]
        when "->" then ["To"]
        when "," then ["And"]
        when "]", "(", ")", "::" then []
        when "nil" then ["Nil"]
        when "noreturn" then ["Never"]
        when "Object" then ["Object"]
        when "bool" then ["Bool"]
        when /\AT(\d+)\z/
          index = Regexp.last_match(1).to_i
          next [] if resolving == index

          slot_type_words(index, slots: slots, depth: depth + 1)
        else
          [token.split("_").map(&:capitalize).join]
        end
      end
    end

    def slot_type_words(index, slots: [], depth: 0)
      return [] if depth > 12

      slot = slots[index - 1]
      return [] if slot.nil? || slot.empty?
      return [] if slot.match?(/\AT\d+\z/)
      return [] if slot.match?(/\bT\d+\b/) && !slot.match?(/[A-Za-z_]|::|\[/)

      type_tokens(slot, slots: slots, depth: depth + 1, resolving: index)
    end

    def mangle(definition, slots: [])
      type_tokens(definition, slots: slots).join
    end

    def parse_sends(definition)
      (@parsed_sends ||= {}).fetch(definition) do
        body = definition.delete_prefix("{ ").delete_suffix(" }")
        @parsed_sends[definition] = body.split("; ").map { |send| parse_send(send) }
      end
    end

    OPEN_PAREN = "(".ord
    CLOSE_PAREN = ")".ord
    OPEN_SQUARE = "[".ord
    CLOSE_SQUARE = "]".ord
    COMMA = ",".ord

    def parse_send(send)
      open = send.index("(")
      message = send[0...open]
      depth = 0
      close = open
      if open && send.ascii_only?
        index = open
        length = send.bytesize
        while index < length
          byte = send.getbyte(index)
          depth += 1 if byte == OPEN_PAREN
          depth -= 1 if byte == CLOSE_PAREN
          if depth.zero?
            close = index
            break
          end
          index += 1
        end
      else
        (open...send.length).each do |index|
          depth += 1 if send[index] == "("
          depth -= 1 if send[index] == ")"
          if depth.zero?
            close = index
            break
          end
        end
      end
      {
        message: message,
        arguments: split_top_level(send[(open + 1)...close]),
        result: send[(close + 5)..].to_s
      }
    end

    def split_top_level(text)
      return [] if text.empty?
      return split_top_level_ascii(text) if text.ascii_only?

      parts = []
      depth = 0
      current = +""
      text.each_char do |char|
        depth += 1 if "([".include?(char)
        depth -= 1 if ")]".include?(char)
        if depth.zero? && char == "," && !current.empty?
          parts << current.strip
          current = +""
        else
          current << char
        end
      end
      parts << current.strip unless current.strip.empty?
      parts
    end

    # split_top_level over bytes: a comma that would start an empty part
    # stays in the part, as it does above.
    def split_top_level_ascii(text)
      parts = []
      depth = 0
      start = 0
      index = 0
      length = text.bytesize
      while index < length
        byte = text.getbyte(index)
        if byte == OPEN_PAREN || byte == OPEN_SQUARE
          depth += 1
        elsif byte == CLOSE_PAREN || byte == CLOSE_SQUARE
          depth -= 1
        elsif byte == COMMA && depth.zero? && index > start
          parts << text.byteslice(start, index - start).strip
          start = index + 1
        end
        index += 1
      end
      last = text.byteslice(start, length - start).strip
      parts << last unless last.empty?
      parts
    end
  end

  class OpenAiCapabilityNamer
    DEFAULT_MODEL = "gpt-5.6-luna"
    DEFAULT_BATCH_SIZE = 100
    DEFAULT_CONCURRENCY = 16
    SYSTEM_PROMPT = <<~PROMPT.freeze
      Name every anonymous structural Ruby capability below.

      Return one concise PascalCase interface name per id using the "-able"
      framework. Describe what values can do, not their implementation or a
      nominal class.

      Examples: Stringifiable, Enumerable, KeyFetchable, EventEmittable,
      CurrentQuestionReadable, CacheClearable, ScoreRankable.

      Rules:
      - Return every input id exactly once.
      - Use one to four semantic words.
      - End with Able, Ible, Ifiable, or Izable.
      - Prefer established Ruby vocabulary when precise.
      - Name the combined ability when multiple methods are present.
      - Never include hashes, ids, generic parameter names, or "Capability".
      - Return only a JSON object mapping each id to its name.
    PROMPT

    def initialize(registry, cache_path:, model: DEFAULT_MODEL, batch_size: DEFAULT_BATCH_SIZE,
      concurrency: DEFAULT_CONCURRENCY, runner: nil)
      @registry = registry
      @cache_path = cache_path
      @model = model
      @batch_size = batch_size
      @concurrency = concurrency
      @runner = runner || method(:run_openai)
    end

    MAX_COLLISION_ROUNDS = 5
    CLUSTER_PROMPT = <<~PROMPT.freeze
      These distinct structural Ruby capability types were all given the name
      "%<shared_name>s". Rename them so every id gets a unique PascalCase name.

      Rules:
      - Return every input id exactly once, each with a different name.
      - Distinguish members using their methods, argument types, and result types.
      - The most general member may stay close to "%<shared_name>s"; the others
        must be more specific.
      - Never use numbers, hashes, or the words "Variant" or "Capability".
      - Use one to five semantic words ending with Able, Ible, Ifiable, or Izable.
      - Return only a JSON object mapping each id to its name.
    PROMPT

    def name!
      names = load_cache
      missing = @registry.definitions.reject { |definition| names.key?(definition.fetch(:id)) }
      batches = missing.each_slice(@batch_size).to_a
      puts "Naming #{missing.length} capabilities in #{batches.length} parallel batches with #{@model}..." if batches.any?
      parallel_map(batches) { |batch| name_batch(batch) }.each { |batch_names| names.merge!(batch_names) }
      File.write(@cache_path, JSON.pretty_generate(names.sort.to_h)) if batches.any?

      resolve_collisions!(names)
      @registry.apply_names!(names)
      names
    end

    private

    def resolve_collisions!(names)
      MAX_COLLISION_ROUNDS.times do
        clusters = @registry.collisions(names)
        break if clusters.empty?

        puts "Renaming #{clusters.sum { |_, definitions| definitions.length }} capabilities across " \
          "#{clusters.length} collision clusters in parallel with #{@model}..."
        renames = parallel_map(clusters.to_a) do |shared_name, definitions|
          rename_cluster(shared_name, definitions)
        end
        renames.each { |cluster_names| names.merge!(cluster_names) }
        File.write(@cache_path, JSON.pretty_generate(names.sort.to_h))
      end

      leftovers = @registry.collisions(names)
      return if leftovers.empty?

      warn "Naming model left #{leftovers.length} name collisions after #{MAX_COLLISION_ROUNDS} rounds"
    end

    # Fiber-based fan-out (this repo never uses threads). Failed calls return
    # an empty result: unresolved names simply stay missing or colliding and
    # the next round retries them.
    def parallel_map(items)
      return [] if items.empty?

      Sync do |parent|
        semaphore = Async::Semaphore.new(@concurrency, parent: parent)
        items.map do |item|
          semaphore.async do
            yield item
          rescue StandardError => error
            warn "Naming call failed: #{error.message}"
            {}
          end
        end.map(&:wait)
      end
    end

    def rename_cluster(shared_name, definitions)
      payload = definitions.map do |definition|
        { id: definition.fetch(:id), capability: definition.fetch(:definition) }
      end
      prompt = "#{format(CLUSTER_PROMPT, shared_name: shared_name)}\n\n#{JSON.generate(payload)}"
      parsed = parse_json_object(@runner.call(prompt, @model))
      parsed.slice(*definitions.map { |definition| definition.fetch(:id) })
    end

    def load_cache
      return {} unless File.exist?(@cache_path)

      JSON.parse(File.read(@cache_path))
    end

    def name_batch(definitions, retry_count: 0)
      payload = definitions.map do |definition|
        { id: definition.fetch(:id), capability: definition.fetch(:definition) }
      end
      output = @runner.call("#{SYSTEM_PROMPT}\n\n#{JSON.generate(payload)}", @model)
      parsed = parse_json_object(output)
      expected_ids = definitions.map { |definition| definition.fetch(:id) }
      missing_ids = expected_ids - parsed.keys
      extra_ids = parsed.keys - expected_ids
      puts "Ignoring #{extra_ids.length} unknown capability ids..." unless extra_ids.empty?
      parsed = parsed.slice(*expected_ids)
      unless missing_ids.empty?
        raise "Naming model repeatedly omitted #{missing_ids.length} capabilities" if retry_count >= 2

        puts "Retrying #{missing_ids.length} omitted capabilities..."
        missing_definitions = definitions.select { |definition| missing_ids.include?(definition.fetch(:id)) }
        parsed.merge!(name_batch(missing_definitions, retry_count: retry_count + 1))
      end

      parsed
    end

    def run_openai(prompt, model)
      connection = Faraday.new(url: ENV.fetch("OPENAI_URI_BASE", "https://api.openai.com"))
      response = connection.post("/v1/responses") do |request|
        request.headers["Authorization"] = "Bearer #{ENV.fetch("OPENAI_ACCESS_TOKEN")}"
        request.headers["Content-Type"] = "application/json"
        request.options.timeout = 180
        request.body = {
          model: model,
          input: prompt,
          max_output_tokens: 16_384,
          reasoning: { effort: "low" },
          text: { verbosity: "low" },
          store: false
        }.to_json
      end
      unless response.success?
        error = JSON.parse(response.body).dig("error", "message")
        raise "OpenAI Responses API failed (#{response.status}): #{error}"
      end

      body = JSON.parse(response.body)
      output_text = body.fetch("output").filter_map do |item|
        next unless item["type"] == "message"

        item.fetch("content").filter_map do |content|
          content["text"] if content["type"] == "output_text"
        end
      end.join
      raise "OpenAI response contained no output text" if output_text.empty?

      output_text
    end

    def parse_json_object(output)
      JSON.parse(output)
    rescue JSON::ParserError
      object = output[/\{.*\}/m]
      raise "Naming model did not return a JSON object" unless object

      JSON.parse(object)
    end
  end

  class CLI
    def self.skipped_files
      Autotype.configuration.skipped_files
    end

    def self.default_profile
      Autotype.profile
    end

    def self.expand_referenced_type_files(files, profile: default_profile)
      Pipeline.expand_referenced_type_files(files, profile: profile)
    end

    def self.build_metadata(collectors, profile: default_profile)
      Pipeline.build_metadata(collectors, profile: profile)
    end

    def self.run(argv)
      json = false
      html_path = nil
      config_path = ENV["AUTOTYPE_CONFIG"]
      capability_names_path = nil
      naming_cache_path = nil
      naming_model = OpenAiCapabilityNamer::DEFAULT_MODEL
      naming_batch_size = OpenAiCapabilityNamer::DEFAULT_BATCH_SIZE
      dump_capabilities_path = nil
      parser = OptionParser.new do |options|
        options.banner = "Usage: autotype [OPTIONS] FILE..."
        options.on("--config PATH", "Path to autotype.yml (default: discover from cwd)") do |path|
          config_path = path
        end
        options.on("--json", "Emit machine-readable JSON") { json = true }
        options.on("--html PATH", "Write a self-contained HTML typedoc") { |path| html_path = path }
        options.on("--capability-names PATH", "Load semantic names from a JSON file or directory") do |path|
          capability_names_path = path
        end
        options.on("--name-capabilities PATH", "Call OpenAI Responses API and cache semantic names") do |path|
          naming_cache_path = path
        end
        options.on("--capability-model MODEL", "OpenAI model used for naming (default: gpt-5.6-luna)") do |model|
          naming_model = model
        end
        options.on("--capability-batch-size N", Integer, "Capabilities per model call (default: 100)") do |size|
          naming_batch_size = size
        end
        options.on("--dump-capabilities PATH", "Write universal definitions as JSON Lines") do |path|
          dump_capabilities_path = path
        end
      end
      files = parser.parse(argv)
      abort parser.to_s if files.empty?
      abort "--json and --html are mutually exclusive" if json && html_path

      Autotype.configuration.config_path = config_path if config_path
      Autotype.configuration.reload_profile!

      pipeline = Pipeline.new(Autotype.expand_paths(files), profile: default_profile).solve
      warn_diagnostics(pipeline.diagnostics)
      unless json
        status = pipeline.converged? ? "converged" : "reached its iteration limit"
        puts "Type inference #{status} after #{pipeline.iterations} iteration(s)"
      end
      helper_registry = pipeline.helper_registry
      # The OpenAI flags below override the pipeline's heuristic names.
      if naming_cache_path
        OpenAiCapabilityNamer.new(
          helper_registry,
          cache_path: naming_cache_path,
          model: naming_model,
          batch_size: naming_batch_size
        ).name!
      end
      if dump_capabilities_path
        lines = helper_registry.definitions.map do |definition|
          JSON.generate(id: definition.fetch(:id), capability: definition.fetch(:definition))
        end
        File.write(dump_capabilities_path, "#{lines.join("\n")}\n")
        if html_path.nil? && !json
          puts "Wrote #{dump_capabilities_path} (#{lines.length} universal capability types)"
          return
        end
      end
      capability_names = load_capability_names(capability_names_path) if capability_names_path
      analysis = pipeline.analysis(capability_names: capability_names)
      reports = pipeline.renderers

      if html_path
        parse_errors = pipeline.diagnostics.select { |diagnostic| diagnostic.kind == :parse }
          .group_by(&:path)
          .transform_values { |entries| entries.map { |diagnostic| "L#{diagnostic.line}: #{diagnostic.message}" } }
        document = HtmlDocument.new(reports, analyzed_files: pipeline.files, parse_errors: parse_errors)
        File.write(html_path, document.render)
        puts "Wrote #{html_path} (#{reports.length} methods across #{reports.map(&:first).uniq.length} files)"
      elsif json
        puts JSON.pretty_generate(analysis.to_h)
      else
        reports.group_by(&:first).each do |path, entries|
          puts path
          puts "=" * path.length
          entries.each do |_, renderer|
            puts renderer.text
            puts
          end
        end
      end
    end

    def self.warn_diagnostics(diagnostics)
      diagnostics.group_by(&:path).each do |path, entries|
        parse_errors, failures = entries.partition { |diagnostic| diagnostic.kind == :parse }
        unless parse_errors.empty?
          warn "#{path}: parse failed"
          parse_errors.each { |diagnostic| warn "  #{"L#{diagnostic.line}: " if diagnostic.line}#{diagnostic.message}" }
        end
        failures.each do |diagnostic|
          location = [path, diagnostic.line].compact.join(":")
          warn "#{location}: skipped #{diagnostic.name || "rest of file"} (#{diagnostic.message})"
        end
      end
    end

    def self.load_capability_names(path)
      paths = File.directory?(path) ? Dir[File.join(path, "*.json")].sort : [path]
      paths.each_with_object({}) { |file, names| names.merge!(JSON.parse(File.read(file))) }
    end
  end
end
