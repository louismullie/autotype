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
  Named = Data.define(:name)
  Generic = Data.define(:name, :arguments)
  Union = Data.define(:members)
  Function = Data.define(:parameters, :result)
  Capability = Data.define(:receiver, :message, :arguments, :keywords, :result, :line)
  Parameter = Data.define(:name, :type, :kind)
  # A helper-type argument for consolidated definitions: a normalized slot
  # string whose T-references are filled from the occurrence's own arguments.
  TemplateArgument = Data.define(:template, :arguments)
  MethodResult = Data.define(
    :name, :owner, :kind, :method_name, :superclass, :line, :end_line,
    :parameters, :result, :capabilities, :self_type, :ivars, :locals, :port_assignments,
    :case_narrowings
  )

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

    def merge_bootstrap_member_types!
      Autotype.bootstrap_member_types.each do |owner, fields|
        @member_types[owner] ||= {}
        fields.each { |member, type| @member_types[owner][member] = type }
      end
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
    distance: "Float",
    line: "Integer",
    end_line: "Integer",
    argument_index: "Integer",
    handler_method: "Symbol",
    dispatch_param: "Symbol",
    dispatch_param_type: "String",
    entity_param: "Symbol",
    port_keyword: "Symbol",
    init_param: "Symbol",
    reader_method: "Symbol",
    ivar: "Symbol",
    method_name: "Symbol",
    owner: "String",
    template: "String"
  }.freeze

  TYPE_NODE = "Function | Generic | Named | TypeVariable | Union"
  NULLABLE_TYPE_NODE = "Nullable[#{TYPE_NODE}]"

  # Ground types for Data.define classes declared in this file. Without these,
  # accessor synthesis leaves member readers as Object and poisons inference.
  BOOTSTRAP_MEMBER_TYPE_STRINGS = {
    "Autotype::Named" => { name: "String" },
    "Autotype::Generic" => { name: "String", arguments: "Array[#{TYPE_NODE}]" },
    "Autotype::Union" => { members: "Array[#{TYPE_NODE}]" },
    "Autotype::Function" => { parameters: "Array[Autotype::Parameter]", result: TYPE_NODE },
    "Autotype::Capability" => {
      receiver: NULLABLE_TYPE_NODE,
      message: "Symbol",
      arguments: "Array[#{TYPE_NODE}]",
      keywords: "Hash[Symbol, Object]",
      result: NULLABLE_TYPE_NODE,
      line: "Integer"
    },
    "Autotype::Parameter" => { name: "Symbol", type: TYPE_NODE, kind: "Symbol" },
    "Autotype::TemplateArgument" => { template: "String", arguments: "Array[#{TYPE_NODE}]" },
    "Autotype::MethodResult" => {
      name: "String",
      owner: "String",
      kind: "Symbol",
      method_name: "Symbol",
      superclass: "Nullable[String]",
      line: "Integer",
      end_line: "Integer",
      parameters: "Array[Autotype::Parameter]",
      result: TYPE_NODE,
      capabilities: "Array[Autotype::Capability]",
      self_type: TYPE_NODE,
      ivars: "Hash[Symbol, #{TYPE_NODE}]",
      locals: "Hash[Symbol, #{TYPE_NODE}]",
      port_assignments: "Array[Object]",
      case_narrowings: "Hash[Symbol, Array[#{TYPE_NODE}]]"
    },
    "Autotype::InferenceMetadata::PortWiring" => {
      handler_method: "Symbol",
      dispatch_param: "Symbol",
      dispatch_param_type: "String",
      entity_param: "Symbol"
    },
    "Autotype::InferenceMetadata::OutputEmitWiring" => {
      message: "Symbol",
      port_keyword: "Symbol",
      argument_index: "Integer"
    },
    "Autotype::InferenceMetadata::ConfigHashWiring" => {
      init_param: "Symbol",
      reader_method: "Symbol",
      ivar: "Symbol"
    },
    "Autotype::TypeVariable" => { id: "Integer", hint: "Nullable[Symbol]" },
    "Autotype::InferenceMetadata" => {
      member_types: "Hash[String, Hash[Symbol, Object]]",
      ports: "Hash[String, Hash[Symbol, Hash[Symbol, Object]]]",
      config_options: "Hash[String, Hash[Symbol, Object]]",
      structured_owners: "Set",
      referenced_types: "Set",
      member_type_hints: "Hash[Symbol, String]",
      option_type_hints: "Hash[Symbol, String]",
      side_effect_methods: "Set",
      structured_type_prefixes: "Array[String]",
      port_wiring: "Nullable[Autotype::InferenceMetadata::PortWiring]",
      output_emit: "Nullable[Autotype::InferenceMetadata::OutputEmitWiring]",
      config_hash: "Nullable[Autotype::InferenceMetadata::ConfigHashWiring]",
      framework_self_fallbacks: "Hash[Symbol, Object]",
      type_locators: "Array[Object]"
    }
  }.freeze

  def self.bootstrap_member_types
    @bootstrap_member_types ||= BOOTSTRAP_MEMBER_TYPE_STRINGS.transform_values do |fields|
      fields.transform_values { |type_string| TypeString.parse(type_string) }
    end
  end

  def self.bootstrap_member_type(owner, member)
    bootstrap_member_types.dig(owner, member)
  end

  # Kernel module functions invoked without an explicit receiver (`Array(x)`).
  KERNEL_CLASS_CALLS = %i[Array Integer Float String Symbol Hash].freeze

  # Type names that must not be treated as literal hash key strings.
  RESERVED_TYPE_NAMES = %w[String Symbol Integer Float Rational Complex bool nil Object].freeze

  class TypeVariable
    attr_reader :scope, :id, :hint

    def initialize(scope, id, hint = nil)
      @scope = scope
      @id = id
      @hint = hint
    end

    def eql?(other) = other.is_a?(TypeVariable) && scope.equal?(other.scope) && id == other.id
    def hash = [scope.object_id, id].hash
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

      MethodResult.new(
        name: qualified_name,
        owner: owner,
        kind: kind,
        method_name: node.name,
        superclass: superclass,
        line: node.location.start_line,
        end_line: node.location.end_line,
        parameters: parameters,
        result: result,
        capabilities: capabilities,
        self_type: @self_type,
        ivars: @ivars.dup,
        # A name bound both at method level and inside blocks (e.g.
        # `x = nil` reassigned within an each) carries both types.
        locals: @block_locals.merge(@environment) { |_name, inner, outer| union(inner, outer) },
        port_assignments: @port_assignments.dup,
        case_narrowings: @case_narrowings.transform_values { |types| types.uniq }
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
      required.each { |node| parameters << bind_parameter(node.name, :required) }
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
            if element.is_a?(Prism::AssocNode)
              key = element.key.respond_to?(:value) ? element.key.value : element.key.slice
              keywords[key.to_sym] = infer_keyword_argument(element.value)
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
        arguments: positional,
        keywords: keywords,
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
          arguments: [],
          keywords: {},
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
      parameter_types = []

      if node.parameters&.parameters
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

    def infer_lambda(node)
      saved_environment = @environment.dup
      parameters = bind_parameters(node.parameters&.parameters)
      result = infer(node.body)
      capture_block_locals(saved_environment)
      @environment = saved_environment
      Function.new(parameters.map(&:type), result)
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
                :declared_member_types, :structured_owners, :referenced_types

    def initialize(path, profile: nil)
      @path = path
      @profile = profile
      @namespace = []
      @singleton = false
      @methods = []
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
      within_namespace(node.constant_path.slice) { super }
    end

    def visit_class_node(node)
      name = node.constant_path.slice
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
      analyzer = Analyzer.new
      methods << analyzer.analyze(
        node,
        "#{owner}#{separator}#{node.name}",
        owner: owner,
        kind: singleton ? :singleton : :instance,
        superclass: @superclasses[owner]
      )
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

    def member_type_hint(owner, member)
      Autotype.bootstrap_member_type(owner, member) ||
        @profile&.member_type_hints&.fetch(member, nil) ||
        core_member_type_hint(member)
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
          hint = member_type_hint(current_owner, member)
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
      type = literal_constant_type(value)
      @constants[qualified_owner(name)] = type if type
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

    def literal_call_type(node)
      if %i[freeze dup].include?(node.name) && node.receiver
        literal_constant_type(node.receiver)
      elsif %i[new create_many].include?(node.name) && %w[Fast::Regexp Regexp].include?(node.receiver&.slice)
        Named.new("Regexp")
      elsif node.name == :to_set && node.receiver
        inner = literal_constant_type(node.receiver)
        Generic.new("Set", inner.arguments) if inner.is_a?(Generic) && inner.name == "Array"
      end
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
        hint = member_type_hint(current_owner, name)
        declared_member_types[current_owner][name] = hint if hint
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

  class FixedPointInferencer
    MAX_ITERATIONS = 30
    PREDICATES = %i[
      == != < <= > >= all? any? blank? connected? empty? eql? include?
      is_a? key? member? nil? present? respond_to? start_with? end_with? zero?
    ].to_set.freeze
    INTEGER_RESULTS = %i[count length size bytesize hash object_id].to_set.freeze
    STRING_RESULTS = %i[
      strip lstrip rstrip chomp chop squeeze tr downcase upcase capitalize
      swapcase gsub sub join to_json encode truncate squish
      strip! chomp! gsub! sub! downcase! upcase! squish!
    ].to_set.freeze
    STRING_LIST_RESULTS = %i[split lines chars].to_set.freeze
    NORETURN = Named.new("noreturn")

    attr_reader :iterations

    def initialize(methods, constants: {}, includes: {}, metadata: InferenceMetadata.empty)
      # `initialize` is only reachable through `new`, which returns the
      # instance, so its meaningful type is the owner class.
      @methods = methods.map do |method|
        next method unless method.kind == :instance && method.method_name == :initialize

        method.with(result: Named.new(method.owner))
      end
      @index = @methods.to_h { |method| [[method.owner, method.kind, method.method_name], method] }
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
      @substitutions = {}
      @call_mappings = {}
      @stable_variables = {}
      @fresh_scope = Object.new
      @fresh_id = 0
      @iterations = 0
      @converged = false
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
          next if @metadata.member_types.dig(accessor.owner, member)

          unify(accessor.result, type)
          accessor.ivars.each_value { |ivar| unify(ivar, type) }
        end
      end
    end

    def apply_initialize_param_bindings!
      @methods.each do |method|
        next unless method.kind == :instance && method.method_name == :initialize

        send_results = method.capabilities.map(&:result)
        method.parameters.each do |parameter|
          ivar = method.ivars[:"@#{parameter.name}"]
          next unless ivar
          # `@x = transform(x)` stores a derived value, not the parameter.
          # Unifying the parameter with a send result creates a cycle that
          # collapses both to Object (e.g. `@collections = Array(collections)`).
          next if send_results.any? { |result| result.equal?(ivar) }

          unify(parameter.type, ivar)
        end
      end
    end

    def apply_declared_member_types!
      @metadata.member_types.each do |owner, fields|
        fields.each do |member, type|
          accessor = @index[[owner, :instance, member]]
          if accessor
            unify(accessor.result, type)
            accessor.ivars.each_value { |ivar| unify(ivar, type) }
          end

          initializer = @index[[owner, :instance, :initialize]]
          next unless initializer

          parameter = initializer.parameters.find { |candidate| candidate.name == member }
          unify(parameter.type, type) if parameter
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

          merged = types.reduce { |left, right| merge_union(left, right) }
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
      @metadata.ports.each do |owner, ports|
        outputs = ports[:outputs]
        next if outputs.empty?

        @methods.select { |method| method.owner == owner }.each do |method|
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

    def structured_owner?(owner)
      return true if @metadata.structured_type?(owner)

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

      value_type = fields.values.reduce { |left, right| merge_union(left, right) }
      Generic.new("Hash", [Named.new("String"), value_type])
    end

    private

    def native_solver_enabled?
      return @native_solver_enabled if defined?(@native_solver_enabled)

      @native_solver_enabled = begin
        require_relative "native_bridge"
        NativeBridge.enabled?
      rescue LoadError, StandardError
        false
      end
    end

    def solve_to_fixed_point
      if native_solver_enabled?
        NativeBridge.prime!(self)
      end

      MAX_ITERATIONS.times do |iteration|
        @changed = false
        @duck_cache = {}
        @methods.each do |method|
          method.capabilities.each do |capability|
            apply_builtin(method, capability)
            # Anchor before resolving the target so a delegating `new`
            # override cannot flood the call site with unresolved variables.
            apply_constructor(method, capability)
            target = resolve_target(method, capability)
            if target
              apply_method_call(method, capability, target)
            elsif apply_union_member_dispatch(method, capability)
              next
            else
              apply_duck_dispatch(method, capability)
              apply_fallback(method, capability)
            end
          end
        end
        @iterations = iteration + 1
        unless @changed
          @converged = true
          break
        end
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
        merged = observed.reduce { |left, right| merge_union(left, right) }
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
        end
      end

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
      when :fetch_chat
        unify(result, Named.new("Dox::AI::Provider::Response"))
      when :content
        unify(result, Named.new("String")) if llm_response_type?(receiver)
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
          unify(result, hash_types.reduce { |left, right| merge_union(left, right) }) if hash_types.any?
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
        when :read, :basename, :dirname, :extname, :join, :expand_path, :absolute_path, :realpath
          unify(result, Named.new("String"))
        when :readlines then unify(result, Generic.new("Array", [Named.new("String")]))
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

    def constant_literal(name, lexical_owner)
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
    DUCK_CORE_RECEIVERS = %w[String Integer Float Symbol bool Time Regexp MatchData noreturn].freeze

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
        next unless @metadata.structured_type?(terminal.name)

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
      returns = callees.map do |callee|
        key = [caller.object_id, capability.object_id, callee.object_id]
        mapping = @call_mappings[key] ||= {}
        instantiated_parameters = callee.parameters.map do |parameter|
          Parameter.new(
            name: parameter.name,
            type: instantiate(resolve(parameter.type), mapping),
            kind: parameter.kind
          )
        end
        bind_arguments(instantiated_parameters, capability)
        instantiate(resolve(callee.result), mapping)
      end
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
      @duck_cache.fetch(message) do
        ground = @duck_index[message]
          .map { |candidate| resolve(candidate.result) }
          .select { |type| ground?(type) }
          .uniq
        @duck_cache[message] =
          if ground.empty? || ground.length > DUCK_UNION_LIMIT
            nil
          else
            ground.length == 1 ? ground.first : Union.new(ground)
          end
      end
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
        return true if @metadata.structured_type?(receiver.name)
        !DUCK_CORE_RECEIVERS.include?(receiver.name) && !receiver.name.start_with?("Class[")
      else
        false
      end
    end

    # Fallbacks for sends that resolve to no repository method. Ruby's `?`
    # suffix convention is reliable enough for a typedoc, and a bare
    # `new`/`create` inside a singleton method constructs the owner class.
    def apply_fallback(method, capability)
      unify(capability.result, Named.new("bool")) if capability.message.to_s.end_with?("?")
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

    def unwrap_nilable(type)
      return type unless type.is_a?(Union)

      members = type.members.reject { |member| [Named.new("nil"), NORETURN].include?(member) }
      members.length == 1 ? members.first : type
    end

    def strip_nil(type)
      return type unless type.is_a?(Union)

      members = type.members.reject { |member| member == Named.new("nil") }
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
        values.reduce { |left, right| merge_union(left, right) }
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

    def resolve_target(method, capability)
      if capability.receiver == method.self_type
        resolve_in_hierarchy(method.owner, method.kind, capability.message)
      else
        receiver = resolve(capability.receiver)
        if (class_name = class_name_from(receiver))
          resolve_named_owner(class_name, method.owner, :singleton, capability.message)
        elsif receiver.is_a?(Named)
          resolve_named_owner(receiver.name, method.owner, :instance, capability.message)
        end
      end
    end

    def resolve_in_hierarchy(owner, kind, method_name)
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
      @index.keys.any? { |(owner, _, _)| owner == name }
    end

    def resolve_superclass(owner, superclass)
      return nil unless superclass

      superclass = superclass.delete_prefix("::")
      return superclass if @methods.any? { |method| method.owner == superclass }

      namespace = owner.split("::")[0...-1]
      namespace.length.downto(0) do |length|
        candidate = (namespace.first(length) + [superclass]).join("::")
        return candidate if @methods.any? { |method| method.owner == candidate }
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
      mapping = @call_mappings[key] ||= {}
      instantiated_parameters = callee.parameters.map do |parameter|
        Parameter.new(
          name: parameter.name,
          type: instantiate(resolve(parameter.type), mapping),
          kind: parameter.kind
        )
      end
      bind_arguments(instantiated_parameters, capability)
      unify(capability.result, instantiate(resolve(callee.result), mapping))
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

    def instantiate(type, mapping)
      case type
      when TypeVariable
        mapping[type] ||= fresh(type.hint)
      when Generic
        Generic.new(type.name, type.arguments.map { |argument| instantiate(argument, mapping) })
      when Union
        Union.new(type.members.map { |member| instantiate(member, mapping) }.uniq)
      when Function
        Function.new(
          type.parameters.map { |parameter| instantiate(parameter, mapping) },
          instantiate(type.result, mapping)
        )
      else
        type
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

      @substitutions[variable] = type
      # Variable-to-variable links are alpha-moves carrying no new concrete
      # information. Counting them as progress lets recursive call cycles
      # mint fresh-variable chains that never converge.
      @changed = true unless type.is_a?(TypeVariable)
    end

    def occurs?(variable, type)
      type = dereference(type)
      case type
      when TypeVariable
        type == variable
      when Generic
        type.arguments.any? { |argument| occurs?(variable, argument) }
      when Union
        type.members.any? { |member| occurs?(variable, member) }
      when Function
        type.parameters.any? { |parameter| occurs?(variable, parameter) } || occurs?(variable, type.result)
      else
        false
      end
    end

    def dereference(type)
      seen = Set.new
      while type.is_a?(TypeVariable) && @substitutions.key?(type) && !seen.include?(type)
        seen << type
        type = @substitutions.fetch(type)
      end
      type
    end

    def resolve(type)
      type = dereference(type)
      case type
      when Generic
        Generic.new(type.name, type.arguments.map { |argument| resolve(argument) })
      when Union
        members = type.members.flat_map do |member|
          resolved = resolve(member)
          resolved.is_a?(Union) ? resolved.members : resolved
        end.uniq
        # Raising branches contribute no value, so noreturn disappears from
        # unions unless the method can only raise.
        live = members.reject { |member| member == NORETURN }
        members = live unless live.empty?
        members.length == 1 ? members.first : Union.new(members)
      when Function
        Function.new(type.parameters.map { |parameter| resolve(parameter) }, resolve(type.result))
      else
        type
      end
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
        if array_normalizer_return?(method.method_name)
          anchor_array_normalizer_return!(method)
          next
        end

        default = convention_default(method.method_name.to_s)
        next unless default

        parameter_terminals = method.parameters.map { |parameter| dereference(parameter.type) }
        residual = residual_return_variables(method) - parameter_terminals
        residual.each { |variable| unify(variable, default) }
      end
    end

    ARRAY_NORMALIZER_METHODS = %w[
      normalize_array normalize_json_array normalize_locations normalize_phases phase_keys
    ].freeze

    def array_normalizer_return?(name)
      ARRAY_NORMALIZER_METHODS.include?(name.to_s)
    end

    def anchor_array_normalizer_return!(method)
      array_type = Generic.new("Array", [Named.new("Object")])
      force_return!(method, array_type)

      parameter_terminals = method.parameters.map { |parameter| dereference(parameter.type) }
      residual_return_variables(method).each do |variable|
        next if parameter_terminals.include?(variable)

        unify(variable, array_type)
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

    def resolve_chained_source_type(method, capability, visited = nil)
      visited ||= Set.new.compare_by_identity
      return nil if visited.include?(capability.object_id)

      visited.add(capability.object_id)
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
    def reflow_callee_returns!
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

      @substitutions[method.result] = type
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
    def narrow_residual_returns!
      NARROWING_ROUNDS.times do
        break unless narrowing_round
      end
    end

    def skip_residual_narrowing?(method)
      array_normalizer_return?(method.method_name)
    end

    # One narrowing round; returns true when new evidence was attached so a
    # follow-up round can propagate it through forwarding methods.
    def narrowing_round
      observations = Hash.new { |hash, key| hash[key] = [] }
      @methods.each do |caller|
        caller.capabilities.each do |capability|
          target = call_target(caller, capability)
          observations[target] << [caller, capability.result] if target
        end
      end

      changed = false
      observations.each do |callee, calls|
        next if skip_residual_narrowing?(callee)

        parameter_variables = callee.parameters.map { |parameter| dereference(parameter.type) }
        residual = residual_return_variables(callee) - parameter_variables
        next if residual.empty?

        sends = collect_result_observations(calls)
        next if sends.empty?

        residual.each do |variable|
          existing = callee.capabilities.select { |capability| dereference(capability.receiver) == variable }
          seen = existing.map { |capability| [capability.message, capability.arguments.length] }.to_set
          budget = MAX_NARROWING_SENDS - seen.size
          break if budget <= 0

          sends.each do |send|
            key = [send.fetch(:message), send.fetch(:arguments).length]
            next if seen.include?(key)

            callee.capabilities << Capability.new(
              receiver: variable,
              message: send.fetch(:message),
              arguments: send.fetch(:arguments),
              keywords: send.fetch(:keywords),
              result: send.fetch(:result),
              line: callee.line
            )
            seen << key
            changed = true
            break if seen.size >= MAX_NARROWING_SENDS
          end
        end
      end
      changed
    end

    def residual_return_variables(method)
      resolved = resolve(method.result)
      case resolved
      when TypeVariable then [resolved]
      when Union then resolved.members.grep(TypeVariable)
      else []
      end
    end

    def collect_result_observations(calls)
      groups = {}
      calls.each do |caller, result|
        terminal = dereference(result)
        next unless terminal.is_a?(TypeVariable)

        caller.capabilities.each do |capability|
          next unless dereference(capability.receiver) == terminal

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

    def side_effect_return_type(method)
      return Named.new("nil") if @metadata.side_effect_methods.include?(method.method_name)

      resolve(method.result)
    end

    def llm_response_type?(receiver)
      return false unless receiver.is_a?(Named)

      receiver.name == "Dox::AI::Provider::Response" || receiver.name.end_with?("::Provider::Response")
    end

    def merge_union(left, right)
      return left if left == right

      members = (left.is_a?(Union) ? left.members : [left]) +
        (right.is_a?(Union) ? right.members : [right])
      Union.new(members.uniq)
    end

    def resolved_method(method)
      MethodResult.new(
        name: method.name,
        owner: method.owner,
        kind: method.kind,
        method_name: method.method_name,
        superclass: method.superclass,
        line: method.line,
        end_line: method.end_line,
        parameters: method.parameters.map do |parameter|
          Parameter.new(name: parameter.name, type: resolve(parameter.type), kind: parameter.kind)
        end,
        result: side_effect_return_type(method),
        capabilities: method.capabilities.map do |capability|
          Capability.new(
            receiver: resolve(capability.receiver),
            message: capability.message,
            arguments: capability.arguments.map { |argument| resolve(argument) },
            keywords: capability.keywords.transform_values { |value| resolve(value) },
            result: resolve(capability.result),
            line: capability.line
          )
        end,
        self_type: resolve(method.self_type),
        ivars: method.ivars.transform_values { |type| resolve(type) },
        locals: method.locals.transform_values { |type| resolve(type) },
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

      match = type.name.match(/\AClass\[(.+)\]\z/)
      match && match[1].delete_prefix("::")
    end

    def array_element(type)
      case type
      when Generic
        type.arguments.first if type.name == "Array"
      when Union
        elements = type.members.filter_map { |member| array_element(member) }
        elements.reduce { |left, right| merge_union(left, right) }
      end
    end

    def enumerable_element(type)
      case type
      when Generic
        return type.arguments.first if %w[Array Enumerator Set].include?(type.name)
      when Union
        elements = type.members.filter_map { |member| enumerable_element(member) }
        return elements.reduce { |left, right| merge_union(left, right) } unless elements.empty?
      end

      nil
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

        member_ids = members.to_set { |member| member.fetch(:id) }
        @occurrences.each_value do |occurrence|
          definition = occurrence.fetch(:definition)
          next unless member_ids.include?(definition.fetch(:id))

          occurrence[:arguments] = parameter_slots.map do |index|
            TemplateArgument.new(
              template: definition.fetch(:slots)[index],
              arguments: occurrence.fetch(:arguments)
            )
          end
          occurrence[:definition] = merged
        end
        members.each { |member| @definitions.delete(member.fetch(:id)) }
        @definitions[merged_id] = merged
      end
    end

    def build_shape(receiver, capabilities)
      parameter_types = []
      parameter_indexes = {}
      slots = []
      normalize = lambda do |type|
        case type
        when TypeVariable
          return "Self" if type == receiver

          index = parameter_indexes[type] ||= begin
            parameter_types << type
            parameter_types.length
          end
          "T#{index}"
        when Named
          type.name
        when Generic
          "#{type.name}[#{type.arguments.map { |argument| normalize.call(argument) }.join(", ")}]"
        when Union
          format_union_slots(type.members.map { |member| normalize.call(member) }.uniq)
        when Function
          params = type.parameters.map { |parameter| normalize.call(parameter) }.join(", ")
          "(#{params}) -> #{normalize.call(type.result)}"
        else
          "Object"
        end
      end
      # Functions are structure (block arity), everything else is a type slot.
      slotify = lambda do |type|
        if type.is_a?(Function)
          params = type.parameters.map { |parameter| slotify.call(parameter) }.join(", ")
          "(#{params}) -> #{slotify.call(type.result)}"
        else
          slots << normalize.call(type)
          "%#{slots.length - 1}%"
        end
      end

      sends = capabilities.sort_by { |capability| capability_sort_key(capability) }.map do |capability|
        arguments = capability.arguments.map { |argument| slotify.call(argument) }
        arguments.concat(
          capability.keywords.sort.map { |name, value| "#{name}: #{slotify.call(value)}" }
        )
        "#{capability.message}(#{arguments.join(", ")}) -> #{slotify.call(capability.result)}"
      end
      template = "{ #{sends.join("; ")} }"

      {
        parameter_types: parameter_types,
        parameter_names: parameter_types.each_index.map { |index| "T#{index + 1}" },
        template: template,
        slots: slots,
        definition: template.gsub(/%(\d+)%/) { slots[Regexp.last_match(1).to_i] }
      }
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

    def initialize(method, helper_registry: UniversalHelperRegistry.new([method]), analyzed_method: method)
      @method = method
      @analyzed_method = analyzed_method
      @helper_registry = helper_registry
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
      params = @method.parameters.map { |parameter| render_parameter(parameter) }.join(", ")
      signature = "#{@method.name} : (#{params}) -> #{render_return_type(@method.result)}"
      helpers = helper_definitions.map do |helper|
        parameters = helper.fetch(:parameters)
        generic = parameters.empty? ? "" : "<#{parameters.join(", ")}>"
        definition = polish_type_string(helper.fetch(:definition))
        "  type #{helper.fetch(:name)}#{generic} = #{definition}"
      end
      constraints = ungrouped_capabilities.map do |capability|
        "  L#{capability.line}: #{render_capability(capability)}"
      end
      sections = [signature]
      sections << "helpers:\n#{helpers.join("\n")}" unless helpers.empty?
      sections << "constraints:\n#{constraints.join("\n")}" unless constraints.empty?
      sections.join("\n")
    end

    def as_json
      payload = {
        name: @method.name,
        line: @method.line,
        end_line: @method.end_line,
        signature: text.lines.first.chomp,
        helpers: helper_definitions,
        constraints: ungrouped_capabilities.map { |capability| render_capability(capability) },
        send_constraint_count: @method.capabilities.length,
        locals: rendered_bindings
      }
      payload[:anomalies] = AnomalyDetector.detect(payload)
      payload
    end

    private

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
      analyzed = @analyzed_method.capabilities.select { |capability| capability.receiver == analyzed_variable }
      analyzed.map do |analyzed_capability|
        @method.capabilities.find do |solved_capability|
          solved_capability.line == analyzed_capability.line &&
            solved_capability.message == analyzed_capability.message &&
            index_key_eq?(solved_capability.arguments, analyzed_capability.arguments)
        end || analyzed_capability
      end
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
      @analyzed_method.capabilities.any? do |capability|
        capability.receiver == variable &&
          capability.message == :[] &&
          field_name_from_index_key(capability.arguments.first)
      end
    end

    def record_field_slot?(capability)
      return false unless capability.message == :[]

      receiver = capability.receiver
      return false unless receiver.is_a?(TypeVariable) && record_parameter?(receiver)

      field_name_from_index_key(capability.arguments.first)
    end

    def render_return_type(type)
      rendered = render(type, grounded_only: true)
      return rendered unless toxic_display_type?(rendered)

      render(type, grounded_only: true, skip_helpers: true)
    end

    def toxic_display_type?(text)
      text.length > 96 || text.match?(/(?:OrArrayOf|ArrayOfArrayOf|OrAndSymbol){2,}/i)
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

    def simplify(type, seen = nil, depth = 0)
      return type if depth > 48
      seen ||= Set.new
      return type if seen.include?(type.object_id)

      seen.add(type.object_id)
      case type
      when Union
        members = type.members.flat_map { |member| member.is_a?(Union) ? member.members : [member] }
        members = members.map { |member| simplify(member, seen, depth + 1) }
        members = dedupe_types(members)
        return members.first if members.length == 1

        nil_members, rest = members.partition { |member| nil_type?(member) }
        if nil_members.any?
          inner = rest.length == 1 ? rest.first : Union.new(rest)
          inner = simplify(inner, seen, depth + 1)
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
    def polish_type_string(text)
      return text unless text.is_a?(String)

      text = flatten_nullable_text(text)
      8.times do
        previous = text
        text = text.gsub(/([A-Za-z0-9_:|\[\], ]+ \|\ nil|nil \|\ [A-Za-z0-9_:|\[\], ]+)/) do |match|
          join_union(split_top_level_union(match))
        end
        text = text.gsub(/Nullable\[([^\]]+)\]/) do |_match|
          inner = join_union(split_top_level_union(Regexp.last_match(1)))
          inner.start_with?("Nullable[") ? inner : "Nullable[#{inner}]"
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

    def split_top_level_union(text)
      parts = []
      depth = 0
      start = 0
      i = 0
      while i < text.length
        char = text[i]
        depth += 1 if char == "["
        depth -= 1 if char == "]"
        if depth.zero? && text[i, 3] == " | "
          parts << text[start...i].strip
          i += 3
          start = i
          next
        end
        i += 1
      end
      parts << text[start..].strip
      parts.reject(&:empty?)
    end

    def render_structural_variable(variable, depth: 0)
      return "Object" if depth > 16

      capabilities = @method.capabilities.select { |capability| capability.receiver == variable }
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
      @helpers.values.uniq.map do |occurrence|
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
      grouped_lines = @analyzed_method.capabilities
        .select { |capability| capability.receiver.is_a?(TypeVariable) && @helpers.key?(capability.receiver) }
        .map(&:line)
        .to_set
      @method.capabilities.reject { |capability| grouped_lines.include?(capability.line) }
    end

    def render_helper_reference(occurrence)
      arguments = occurrence.fetch(:arguments).map { |argument| render_helper_argument(argument) }
      name = occurrence.fetch(:definition).fetch(:name)
      reference = arguments.empty? ? name : "#{name}[#{arguments.join(", ")}]"
      polish_type_string(reference)
    end

    def render_helper_argument(type)
      type = simplify(type) if type.is_a?(Union) || type.is_a?(Generic)
      case type
      when TemplateArgument
        substituted = type.template.gsub(/\bT(\d+)\b/) do
          render_helper_argument(type.arguments[Regexp.last_match(1).to_i - 1])
        end
        polish_type_string(substituted)
      when TypeVariable
        solved = solved_type_for_variable(type)
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

    def solved_type_for_variable(analyzed_variable)
      analyzed_capability = @analyzed_method.capabilities.find { |capability| capability.result == analyzed_variable }
      return nil unless analyzed_capability

      @method.capabilities.find do |capability|
        capability.line == analyzed_capability.line && capability.message == analyzed_capability.message
      end&.result
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
    MAX_NAME_LENGTH = 56
    MAX_TYPE_WORD_LENGTH = 24
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
      levels = Hash.new(1)
      names = {}
      (MAX_LEVEL * 4).times do
        names = @registry.definitions.to_h do |definition|
          [definition.fetch(:id), name_for(definition, levels[definition.fetch(:id)])]
        end
        clusters = @registry.definitions
          .group_by { |definition| @registry.normalize_semantic_name(names[definition.fetch(:id)]) }
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
      truncate_name("#{stems.join}#{final}")
    end

    def truncate_name(name)
      return name if name.length <= MAX_NAME_LENGTH

      suffix = name[/(?:able|ible|ifiable|izable|able)\z/i] || "Able"
      stem = name.sub(/(?:able|ible|ifiable|izable|able)\z/i, "")
      max_stem = [MAX_NAME_LENGTH - suffix.length, 1].max
      "#{stem[0, max_stem]}#{suffix}"
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
      words = dedupe_adjacent(type_tokens(types.join(", "), slots: slots)).join
      words.length > MAX_TYPE_WORD_LENGTH ? "Mixed" : words
    end

    def dedupe_adjacent(words)
      words.each_with_object([]) { |word, acc| acc << word unless acc.last == word }
    end

    def type_tokens(type, slots: [], depth: 0, resolving: nil)
      return [] if depth > 6

      resolving ||= Set.new
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
          next [] if resolving.include?(index)

          slot_type_words(index, slots: slots, depth: depth + 1, resolving: resolving)
        else
          [token.split("_").map(&:capitalize).join]
        end
      end
    end

    def slot_type_words(index, slots: [], depth: 0, resolving: nil)
      resolving ||= Set.new
      return [] if depth > 6
      return [] if resolving.include?(index)

      slot = slots[index - 1]
      return [] if slot.nil? || slot.empty?
      return [] if slot.match?(/\AT\d+\z/)

      type_tokens(slot, slots: slots, depth: depth + 1, resolving: resolving.dup.add(index))
    end

    def mangle(definition, slots: [])
      type_tokens(definition, slots: slots).join
    end

    def parse_sends(definition)
      body = definition.delete_prefix("{ ").delete_suffix(" }")
      body.split("; ").map { |send| parse_send(send) }
    end

    def parse_send(send)
      open = send.index("(")
      message = send[0...open]
      depth = 0
      close = open
      (open...send.length).each do |index|
        depth += 1 if send[index] == "("
        depth -= 1 if send[index] == ")"
        if depth.zero?
          close = index
          break
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
      expanded = files.dup
      referenced = Set.new
      files.each do |path|
        next unless File.file?(path)

        result = Prism.parse_file(path)
        next unless result.success?

        collector = Collector.new(path, profile: profile)
        result.value.accept(collector)
        collector.referenced_types.each do |type_name|
          type_path = profile.locate_type_file(type_name)
          referenced << normalize_scan_path(type_path) if type_path
        end
      end
      (expanded.map { |path| normalize_scan_path(path) } + referenced.to_a).uniq
    end

    # Referenced entity files resolve to absolute paths; the input list is
    # usually relative. Normalize to cwd-relative so the same file never
    # appears under two keys in the JSON output (which duplicates editor
    # diagnostics).
    def self.normalize_scan_path(path)
      cwd = "#{Dir.pwd}/"
      expanded = File.expand_path(path)
      expanded.start_with?(cwd) ? expanded.delete_prefix(cwd) : path
    end

    def self.build_metadata(collectors, profile: default_profile)
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
      metadata.merge_bootstrap_member_types!
      metadata
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

      files.reject! { |path| skipped_files.include?(path.delete_prefix("./")) }
      profile = default_profile
      profile.prepare_search!(files) if profile.respond_to?(:prepare_search!)
      files = expand_referenced_type_files(files, profile: profile)

      parse_errors = {}
      constants = {}
      includes = Hash.new { |hash, key| hash[key] = [] }
      collectors = []
      method_reports = files.flat_map do |path|
        result = Prism.parse_file(path)
        unless result.success?
          warn "#{path}: parse failed"
          result.errors.each { |error| warn "  L#{error.location.start_line}: #{error.message}" }
          parse_errors[path] = result.errors.map { |error| "L#{error.location.start_line}: #{error.message}" }
          next []
        end

        collector = Collector.new(path, profile: profile)
        result.value.accept(collector)
        collectors << collector
        constants.merge!(collector.constants)
        collector.includes.each { |owner, mods| includes[owner].concat(mods) }
        collector.methods.map { |method| [path, method] }
      end
      includes.transform_values! { |mods| mods.uniq }
      metadata = build_metadata(collectors, profile: profile)
      inferencer = FixedPointInferencer.new(
        method_reports.map(&:last),
        constants: constants,
        includes: includes,
        metadata: metadata
      )
      analyzed_methods = method_reports.map(&:last)
      solved_methods = inferencer.run
      method_reports = method_reports.zip(solved_methods, analyzed_methods).map do |(path, _method), solved_method, analyzed_method|
        [path, solved_method, analyzed_method]
      end
      unless json
        status = inferencer.converged? ? "converged" : "reached its iteration limit"
        puts "Type inference #{status} after #{inferencer.iterations} iteration(s)"
      end
      helper_registry = UniversalHelperRegistry.new(analyzed_methods)
      # Deterministic LLM-free names first; the OpenAI flags below override.
      HeuristicCapabilityNamer.new(helper_registry).name!
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
      if capability_names_path
        helper_registry.apply_names!(load_capability_names(capability_names_path))
      end
      reports = method_reports.map do |path, method, analyzed_method|
        [path, Renderer.new(method, analyzed_method: analyzed_method, helper_registry: helper_registry)]
      end

      if html_path
        document = HtmlDocument.new(reports, analyzed_files: files, parse_errors: parse_errors)
        File.write(html_path, document.render)
        puts "Wrote #{html_path} (#{reports.length} methods across #{reports.map(&:first).uniq.length} files)"
      elsif json
        puts JSON.pretty_generate(
          reports.group_by(&:first).transform_values { |entries| entries.map { |_, renderer| renderer.as_json } }
        )
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

    def self.load_capability_names(path)
      paths = File.directory?(path) ? Dir[File.join(path, "*.json")].sort : [path]
      paths.each_with_object({}) { |file, names| names.merge!(JSON.parse(File.read(file))) }
    end
  end
end
