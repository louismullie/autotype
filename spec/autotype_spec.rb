# frozen_string_literal: true

require "spec_helper"

RSpec.describe Autotype do
  def collect(source, path = "example.rb")
    collector_for(source, path).methods
  end

  def collector_for(source, path = "example.rb", profile: nil)
    result = Prism.parse(source)
    expect(result).to be_success

    collector = described_class::Collector.new(path, profile: profile)
    result.value.accept(collector)
    collector
  end

  def infer(source)
    methods = collect(source)
    registry = described_class::UniversalHelperRegistry.new(methods)
    methods.to_h do |method|
      [method.name, described_class::Renderer.new(method, helper_registry: registry)]
    end
  end

  def solve(source, profile: Autotype.profile)
    collector = collector_for(source, profile: profile)
    analyzed_methods = collector.methods
    metadata =
      if profile
        described_class::CLI.build_metadata([collector], profile: profile)
      else
        described_class::InferenceMetadata.empty
      end
    methods = described_class::FixedPointInferencer.new(
      analyzed_methods,
      constants: collector.constants,
      includes: collector.includes,
      metadata: metadata
    ).run
    registry = described_class::UniversalHelperRegistry.new(analyzed_methods)
    analyzed_methods.zip(methods).to_h do |analyzed_method, solved_method|
      [
        solved_method.name,
        described_class::Renderer.new(
          solved_method,
          analyzed_method: analyzed_method,
          helper_registry: registry
        )
      ]
    end
  end

  it "infers plain Ruby without a project profile" do
    methods = solve(<<~RUBY, profile: nil)
      class Counter
        def initialize
          @count = 0
        end

        def increment
          @count + 1
        end
      end
    RUBY

    expect(methods.fetch("Counter#increment").text.lines.first).to include("-> Integer")
  end

  it "folds single-send string interpolation constraints into a helper type" do
    methods = infer(<<~RUBY)
      def greet(name)
        "Hello, \#{name}!"
      end
    RUBY
    text = methods.fetch("example#greet").text

    expect(text).to match(/example#greet : \(name Capability_[a-f0-9]{10}\) -> String/)
    expect(text).to match(/type Capability_[a-f0-9]{10} = \{ to_s\(\) -> String \}/)
    expect(text).not_to include("responds to")
  end

  it "generalizes structural operator constraints into a helper type" do
    methods = infer(<<~RUBY)
      def add(a, b)
        a + b
      end
    RUBY
    text = methods.fetch("example#add").text

    expect(text).to match(/example#add : \(a Capability_[a-f0-9]{10}\[Object, Object\], b Object\) -> Object/)
    expect(text).to match(/type Capability_[a-f0-9]{10}<T1, T2> = \{ \+\(T1\) -> T2 \}/)
  end

  it "propagates return types through repository method calls to a fixed point" do
    methods = solve(<<~RUBY)
      class Example
        def leaf = "done"
        def middle = leaf
        def root = middle
      end
    RUBY

    expect(methods.fetch("Example#root").text).to start_with("Example#root : () -> String")
  end

  it "resolves inherited methods and cross-method instance variable types" do
    methods = solve(<<~RUBY)
      class Base
        def emit(value) = value
      end

      class Child < Base
        def initialize
          @items = []
        end

        def finish
          emit(@items.size)
        end
      end
    RUBY

    expect(methods.fetch("Child#finish").text).to start_with("Child#finish : () -> Integer")
  end

  it "flows instance variable types through synthesized attr_reader methods" do
    methods = solve(<<~RUBY)
      class Config
        attr_reader :timeout

        def initialize
          @timeout = 30
        end
      end

      class Client
        def wait
          Config.new.timeout
        end
      end
    RUBY

    expect(methods.fetch("Config#timeout").text).to start_with("Config#timeout : () -> Integer")
    expect(methods.fetch("Client#wait").text).to start_with("Client#wait : () -> Integer")
  end

  it "unions nil initialization with later ivar assignments for accessors" do
    methods = solve(<<~RUBY)
      class Tracker
        def reset
          @elapsed = nil
        end

        def finalize
          @elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - @started_at
        end

        def elapsed
          @elapsed
        end
      end
    RUBY

    expect(methods.fetch("Tracker#elapsed").text).to start_with("Tracker#elapsed : () -> Nullable[Float]")
  end

  it "drops raising branches from return unions" do
    methods = solve(<<~RUBY)
      def checked(flag)
        raise ArgumentError, "nope" if flag
        "ok"
      end
    RUBY

    expect(methods.fetch("example#checked").text.lines.first).to include("-> String")
    expect(methods.fetch("example#checked").text.lines.first).not_to include("noreturn")
  end

  it "constructs the owner class from bare new in singleton methods" do
    methods = solve(<<~RUBY)
      class Widget
        def self.build
          new
        end
      end
    RUBY

    expect(methods.fetch("Widget.build").text).to start_with("Widget.build : () -> Widget")
  end

  it "models common stdlib methods and question-mark predicates" do
    methods = solve(<<~RUBY)
      class Sample
        def label(parts)
          parts.join(", ").strip
        end

        def ready
          engine.ready?
        end
      end
    RUBY

    expect(methods.fetch("Sample#label").text.lines.first).to include("-> String")
    expect(methods.fetch("Sample#ready").text.lines.first).to include("-> bool")
  end

  it "namespaces methods defined inside block-based constant definitions" do
    methods = solve(<<~RUBY)
      module Entities
        Hit = App::Entity.define(:title) do
          def self.from_h(hash)
            new
          end
        end
      end
    RUBY

    expect(methods.fetch("Entities::Hit.from_h").text.lines.first).to include("-> Entities::Hit")
  end

  it "anchors entity factory constructors to nominal return types" do
    methods = solve(<<~RUBY)
      class Builder
        def build
          Entities::Hit.create(title: "Example")
        end
      end
    RUBY

    expect(methods.fetch("Builder#build").text).to start_with(
      "Builder#build : () -> Entities::Hit"
    )
  end

  it "handles forwarding and destructured block parameters" do
    methods = infer(<<~RUBY)
      def forward(...)
        pairs.each { |(key, value)| target(key, value, ...) }
      end
    RUBY

    expect(methods.fetch("example#forward").text).to include("example#forward : (... Object) -> Object")
  end

  it "renders unresolved outputs as Object instead of fake generics" do
    methods = infer(<<~RUBY)
      def perform
        helper_call
      end

      def tagged(value)
        value.tag
      end
    RUBY

    expect(methods.fetch("example#perform").text).to start_with("example#perform : () -> Object")
    expect(methods.fetch("example#tagged").text).to match(
      /example#tagged : \(value Capability_[a-f0-9]{10}\[Object\]\) -> Object/
    )
  end

  it "grounds constructor-assigned accessors from call-site arguments" do
    methods = solve(<<~RUBY)
      class Client
        attr_reader :url

        def initialize(url:)
          @url = url
        end
      end

      class Caller
        def build
          Client.new(url: "https://example.com")
        end
      end
    RUBY

    expect(methods.fetch("Client#url").text.lines.first).to include("-> String")
  end

  it "defaults residual returns from naming conventions" do
    methods = solve(<<~RUBY)
      class Judge
        def relevant?
          opaque_call
        end

        def to_tool_hash
          opaque_call
        end
      end
    RUBY

    expect(methods.fetch("Judge#relevant?").text.lines.first).to include("-> bool")
    expect(methods.fetch("Judge#to_tool_hash").text.lines.first).to include("-> Hash[")
  end

  it "keeps all union members visible instead of eliding unresolved branches" do
    methods = solve(<<~RUBY)
      class Picker
        def pick(flag)
          flag ? "yes" : mystery
        end
      end
    RUBY

    signature = methods.fetch("Picker#pick").text.lines.first
    expect(signature).to include("-> Object | String")
    expect(signature).not_to include("?")
  end

  it "exports local variable types including block-scoped assignments" do
    methods = solve(<<~RUBY)
      class Demo
        def run(items)
          found = nil
          items.each do |item|
            found = item.to_s
          end
          found
        end
      end
    RUBY

    locals = methods.fetch("Demo#run").as_json.fetch(:locals)
    expect(locals.fetch("found")).to eq("Nullable[String]")
    expect(locals).to have_key("item")
  end

  it "flows a caller block's return type through yield" do
    methods = solve(<<~RUBY)
      class Gate
        def decide
          yield
        end

        def run
          decide { 42 }
        end
      end
    RUBY

    expect(methods.fetch("Gate#run").text.lines.first).to include("-> Integer")
    expect(methods.fetch("Gate#decide").text.lines.first).to include("&block")
  end

  it "narrows index helper slots from caller argument contexts" do
    methods = solve(<<~RUBY)
      module TargetFilter
        def filter_targets(raw_targets)
          Array(raw_targets).reject { |target| vague_status?(target) }
        end

        def vague_status?(target)
          concept_type = target["concept_type"] || target[:concept_type]
          phrase = target["core_phrase"] || target[:core_phrase]
          concept_type.to_s == "status" && phrase.to_s.include?("post")
        end
      end

      class Parser
        include TargetFilter

        def run
          filter_targets([{ concept_type: "status", core_phrase: "post op" }])
        end
      end
    RUBY

    signature = methods.fetch("TargetFilter#vague_status?").text.lines.first
    expect(signature).to include("concept_type")
    expect(signature).to include("core_phrase")
    expect(signature).not_to match(/<B, C, D, E>/)
  end

  it "narrows unresolved returns from caller usage" do
    methods = solve(<<~RUBY)
      class Service
        def payload
          remote_fetch
        end
      end

      class Consumer
        def run
          data = Service.new.payload
          data.status_code
        end
      end
    RUBY

    expect(methods.fetch("Service#payload").text).to include("status_code")
    expect(methods.fetch("Service#payload").text.lines.first).not_to eq("Service#payload : () -> Object\n")
  end

  it "types initialize as returning the owner instance" do
    methods = solve(<<~RUBY)
      class Widget
        def initialize(name)
          @name = name
        end
      end
    RUBY

    expect(methods.fetch("Widget#initialize").text.lines.first).to include("-> Widget")
  end

  it "infers optional parameter types from default values" do
    methods = solve(<<~RUBY)
      class Service
        def call(retries = 3, label: "default")
          retries + label.length
        end
      end
    RUBY

    signature = methods.fetch("Service#call").text.lines.first
    expect(signature).to include("retries? Integer")
    expect(signature).to include("label:? String")
    expect(signature).to include("-> Integer")
  end

  it "widens nil-default keyword parameters to Nullable" do
    methods = solve(<<~RUBY)
      class Service
        def call(token: nil)
          token
        end
      end
    RUBY

    signature = methods.fetch("Service#call").text.lines.first
    expect(signature).to include("token:? Nullable[Object]")
  end

  it "prefers explicit Data block initialize over synthesized member constructor" do
    methods = solve(<<~RUBY)
      Widget = Data.define(:id, :score) do
        def initialize(id:, score: nil)
          super
        end
      end
    RUBY

    inits = methods.values.select { |renderer| renderer.as_json.fetch(:name).end_with?("#initialize") }
    expect(inits.length).to eq(1)
    signature = inits.first.text.lines.first
    expect(signature).to include("id: String")
    expect(signature).not_to include("id:?")
    expect(signature).to include("score:? Nullable[Object]")
  end

  it "flattens nested Nullable wrappers in rendered output" do
    methods = solve(<<~RUBY)
      class Demo
        def run(items)
          items.filter_map { |item| item.to_i if item }
        end
      end
    RUBY

    text = methods.fetch("Demo#run").text
    expect(text).not_to include("Nullable[Nullable[")
    expect(text).not_to match(/Nullable\[[^\]]*(\|\ nil|nil \|\ )/)
  end

  it "grounds actor process parameters from input port declarations" do
    methods = solve(<<~RUBY)
      module Actors
        class DemoActor < App::Actor
          input :prompts, type: App::Entities::Prompt

          def process(prompt, from:)
            prompt.query
          end
        end
      end
    RUBY

    signature = methods.fetch("Actors::DemoActor#process").text.lines.first
    expect(signature).to include("prompt App::Entities::Prompt")
    expect(signature).to include("from: Symbol")
  end

  it "narrows entity and ivar types from case from port branches" do
    methods = solve(<<~RUBY)
      module Actors
        class DemoActor < App::Actor
          input :prompts, type: App::Entities::Prompt
          input :queries, type: App::Entities::Query

          def process(entity, from:)
            case from
            when :prompts
              @prompt = entity
            when :queries
              @query = entity
            end
          end
        end
      end
    RUBY

    json = methods.fetch("Actors::DemoActor#process").as_json
    expect(json.fetch(:locals).fetch("entity")).to include("App::Entities::")
    expect(json.fetch(:locals).fetch("@prompt")).to include("App::Entities::Prompt")
    expect(json.fetch(:locals).fetch("@query")).to include("App::Entities::Query")
  end

  it "types actor options reads from option declarations" do
    methods = solve(<<~RUBY)
      module Actors
        class DemoActor < App::Actor
          option :base_url
          option :timeout

          def endpoint
            options[:base_url]
          end
        end
      end
    RUBY

    expect(methods.fetch("Actors::DemoActor#endpoint").text.lines.first).to include("-> String")
  end

  it "expands entity files referenced by actor ports" do
    actor_path = File.expand_path("fixtures/pipeline/actors/demo_actor.rb", __dir__)
    profile = Autotype::DiscoveryProfile.new(root: File.expand_path("fixtures", __dir__))
    profile.prepare_search!([actor_path])
    paths = described_class::CLI.expand_referenced_type_files([actor_path], profile: profile)

    # Paths under the working directory are normalized to relative form so the
    # JSON output never lists the same file under two keys.
    expect(paths).to include(
      "spec/fixtures/entities/tool_call.rb",
      "spec/fixtures/entities/tool_result.rb"
    )
  end

  it "types Hash.new block defaults and element appends" do
    methods = solve(<<~RUBY)
      class Buffer
        def reset!
          @items = Hash.new { |hash, key| hash[key] = [] }
        end

        def push(item)
          @items[1] << item
        end
      end
    RUBY

    expect(methods.fetch("Buffer#reset!").text.lines.first).to include("-> nil")
    ivar_type = methods.fetch("Buffer#push").as_json.fetch(:locals).fetch("@items")
    expect(ivar_type).to include("Hash[Integer, Array[")
  end

  it "grounds emit arguments from declared output ports" do
    methods = solve(<<~RUBY)
      module Actors
        class DemoActor < App::Actor
          output :chunks, type: App::Entities::StreamChunk

          def send_chunk(entity)
            emit(entity, to: :chunks)
          end
        end
      end
    RUBY

    signature = methods.fetch("Actors::DemoActor#send_chunk").text.lines.first
    expect(signature).to include("entity App::Entities::StreamChunk")
  end

  it "resolves entity member reads on union-typed pipeline inputs" do
    methods = solve(<<~RUBY)
      ToolCall = App::Entity.define(:step) do
      end

      ToolResult = App::Entity.define(:step) do
      end

      module Actors
        class DemoActor < App::Actor
          input :tool_calls, type: ToolCall
          input :tool_results, type: ToolResult

          def process(entity, from:)
            entity.step
          end
        end
      end
    RUBY

    expect(methods.fetch("Actors::DemoActor#process").text.lines.first).to include("-> Integer")
  end

  it "types normalize_array as Array without runaway helper names" do
    methods = solve(<<~RUBY)
      module Normalization
        module_function

        def parse_json(value)
          nil
        end

        def normalize_array(value)
          parsed = parse_json(value)
          value = parsed if parsed

          case value
          when nil
            []
          when Array
            value
          when String
            value.split(/[;,]/).map(&:strip)
          else
            [value]
          end.reject { |item| item.to_s.blank? }
        end
      end
    RUBY

    signature = methods.fetch("Normalization#normalize_array").text.lines.first
    expect(signature).to include("Array[")
    expect(signature).not_to match(/OrArrayOf/i)
    expect(signature.length).to be < 200
  end

  it "types entity to_h as a string-keyed hash" do
    methods = solve(<<~RUBY)
      DemoEntity = App::Entity.define(:id) do
        def payload
          to_h
        end
      end
    RUBY

    expect(methods.fetch("DemoEntity#payload").text.lines.first).to include("-> Hash[String, String]")
  end

  it "applies core member-name conventions to synthesized readers" do
    methods = solve(<<~RUBY, profile: nil)
      Record = Data.define(:name, :step) do
      end

      class Demo
        def run(record)
          record.name
          record.step
        end
      end
    RUBY

    expect(methods.fetch("Record#name").text.lines.first).to include("-> String")
    expect(methods.fetch("Record#step").text.lines.first).to include("-> Integer")
  end

  it "narrows hash dig chains with literal string keys" do
    methods = solve(<<~RUBY, profile: nil)
      class Demo
        def read
          data = { "detail" => { "locations" => [] } }
          data.dig("detail", "locations")
        end
      end
    RUBY

    expect(methods.fetch("Demo#read").text.lines.first).to include("-> Nullable[Array[")
  end

  it "narrows array elements from appended parameters" do
    methods = solve(<<~RUBY, profile: nil)
      Widget = Data.define(:id)

      class Demo
        def buffer
          items = []
          items << Widget.new(id: "a")
        end
      end
    RUBY

    expect(methods.fetch("Demo#buffer").text.lines.first).to include("Array[Widget")
  end

  it "narrows dynamic symbol hash access after to_sym" do
    methods = solve(<<~RUBY, profile: nil)
      class Demo
        def push(bucket, kind, item)
          bucket[kind.to_sym] << item
        end
      end
    RUBY

    signature = methods.fetch("Demo#push").text.lines.first
    expect(signature).to include("item Object")
    expect(signature).not_to include("Appendable[Object, Object]")
  end

  it "narrows nested hash index append chains from method parameters" do
    methods = solve(<<~RUBY, profile: nil)
      Item = Data.define(:id)

      class Demo
        def buffer(step, kind)
          item = Item.new(id: "a")
          @buckets = Hash.new { |hash, key| hash[key] = { slots: [] } }
          @buckets[step][kind.to_sym] << item
        end
      end
    RUBY

    signature = methods.fetch("Demo#buffer").text.lines.first
    expect(signature).to include("Array[Item")
    expect(signature).not_to include("Array[Object]")
  end

  it "narrows append targets when literal hashes expose multiple array slots" do
    methods = solve(<<~RUBY, profile: nil)
      Entity = Data.define(:step)

      class Demo
        def buffer(step, kind)
          entity = Entity.new(step: 1)
          @pending = Hash.new { |hash, key| hash[key] = { tool_calls: [], tool_results: [] } }
          @pending[step][kind.to_sym] << entity
        end
      end
    RUBY

    signature = methods.fetch("Demo#buffer").text.lines.first
    expect(signature).to include("Array[Entity")
    expect(signature).not_to include("Array[Object]")
  end

  it "flows each block parameters into callee arguments" do
    methods = solve(<<~RUBY, profile: nil)
      class Demo
        def run
          @counts = { 1 => "a", 2 => "b" }
          @counts.keys.sort.each { |step| consume(step) }
        end

        def consume(step)
          step
        end
      end
    RUBY

    expect(methods.fetch("Demo#consume").text.lines.first).to include("(step Integer)")
  end

  it "types kernel Array() coercion without an explicit receiver" do
    methods = solve(<<~RUBY, profile: nil)
      class Demo
        def wrap
          Array([1, 2, 3])
        end
      end
    RUBY

    expect(methods.fetch("Demo#wrap").text.lines.first).to include("Array[Integer")
  end

  it "narrows case/when branches on Hash and Array" do
    methods = solve(<<~RUBY, profile: nil)
      class Demo
        def walk(payload)
          case payload
          when Hash
            payload.each_value { |value| value }
          when Array
            payload.each { |item| item }
          end
        end
      end
    RUBY

    signature = methods.fetch("Demo#walk").text.lines.first
    expect(signature).to include("Hash[String | Symbol, Object]")
    expect(signature).to include("Array[Object]")
    expect(signature).not_to include("(payload Object")
  end

  it "infers hash literal key names from core member conventions" do
    methods = solve(<<~RUBY, profile: nil)
      class Demo
        def read(target)
          target["concept_type"]
        end
      end
    RUBY

    expect(methods.fetch("Demo#read").text.lines.first).to include("-> String")
  end

  it "binds entity factory keyword params to declared member types" do
    methods = solve(<<~RUBY)
      Widget = App::Entity.define(:id, :name) do
        field :id, required: true
        field :name, required: true

        def self.create(id:, name:)
          new(id: id, name: name)
        end
      end
    RUBY

    signature = methods.fetch("Widget.create").text.lines.first
    expect(signature).to include("name: String")
    expect(signature).not_to include("name: Object")
  end

  it "reflows callee return types after callees converge" do
    methods = solve(<<~RUBY)
      class Demo
        def process
          buffer
        end

        def buffer
          items = []
          items << 1
        end
      end
    RUBY

    signature = methods.fetch("Demo#process").text.lines.first
    expect(signature).to include("Array[Integer")
    expect(signature).not_to include("Object")
  end

  it "types entity to_h from declared member fields" do
    methods = solve(<<~RUBY)
      DemoEntity = App::Entity.define(:id, :name) do
        def payload
          to_h
        end
      end
    RUBY

    signature = methods.fetch("DemoEntity#payload").text.lines.first
    expect(signature).to include("-> Hash[String,")
    expect(signature).to include("String")
  end

  it "types mutator methods ending in bang as nil returns" do
    methods = solve(<<~RUBY, profile: nil)
      class Demo
        def remap!(payload)
          payload["name"] = "x"
        end
      end
    RUBY

    expect(methods.fetch("Demo#remap!").text.lines.first).to include("-> nil")
  end

  it "uses stable JSON.parse value types" do
    methods = solve(<<~RUBY, profile: nil)
      class Demo
        def read
          JSON.parse("{}")
        end
      end
    RUBY

    signature = methods.fetch("Demo#read").text.lines.first
    expect(signature).to include("Hash[String,")
    expect(signature).not_to match(/Hash\[String, Hash\[String, Hash/)
  end

  it "names capability types without greek letter fragments" do
    methods = [
      *collect("def a(x); x[1]; x[2]; end", "a.rb"),
      *collect("def b(y); y[:key]; y.dig(:a, :b); end", "b.rb"),
      *collect("def c(z); z.map(&:to_s); end", "c.rb")
    ]
    registry = described_class::UniversalHelperRegistry.new(methods)
    described_class::HeuristicCapabilityNamer.new(registry).name!
    names = registry.definitions.map { |definition| definition.fetch(:name) }.join(" ")

    expect(names).not_to match(/Alpha|Beta|Gamma|Delta|Epsilon|Zeta|Eta|Theta|Iota|Kappa|Lambda|Mu|Nu|Xi|Omicron|Pi|Rho|Sigma|Tau|Upsilon|Phi|Chi|Psi|Omega/)
  end

  it "collapses repeated receiver constraints into helper types" do
    methods = infer(<<~RUBY)
      def context(prompt)
        prompt.current_question
        prompt.thread_context
      end
    RUBY
    text = methods.fetch("example#context").text

    expect(text).to match(
      /example#context : \(prompt Capability_[a-f0-9]{10}\[Object, Object\]\) -> Object/
    )
    expect(text).to match(
      /type Capability_[a-f0-9]{10}<T1, T2> = \{ current_question\(\) -> T1; thread_context\(\) -> T2 \}/
    )
    expect(text).not_to include("A responds to")
  end

  it "reuses canonical helper types across files" do
    methods = [
      *collect("def first(input); input.left; input.right; end", "one.rb"),
      *collect("def second(value); value.left; value.right; end", "two.rb")
    ]
    registry = described_class::UniversalHelperRegistry.new(methods)
    helper_names = methods.flat_map do |method|
      described_class::Renderer.new(method, helper_registry: registry).as_json.fetch(:helpers).map { _1[:name] }
    end

    expect(helper_names.uniq.length).to eq(1)
    expect(registry.definitions.first.fetch(:uses)).to eq(2)
  end

  it "applies semantic -able names to universal capability types" do
    method = collect("def read(input); input.current_question; input.thread_context; end").first
    registry = described_class::UniversalHelperRegistry.new([method])
    id = registry.definitions.first.fetch(:id)
    registry.apply_names!(id => "Context Readable")
    text = described_class::Renderer.new(method, helper_registry: registry).text

    expect(text).to include(
      "ContextReadable[",
      "type ContextReadable<T1, T2>"
    )
  end

  it "consolidates same-structure helper shapes using union typed slots" do
    methods = [
      *collect("def first(a); a.fetch(1); end", "one.rb"),
      *collect("def second(b); b.fetch(\"key\"); end", "two.rb")
    ]
    registry = described_class::UniversalHelperRegistry.new(methods)

    expect(registry.definitions.length).to eq(1)
    definition = registry.definitions.first
    expect(definition.fetch(:definition)).to eq("{ fetch(Integer | String) -> T1 }")
    expect(definition.fetch(:uses)).to eq(2)

    renderer = described_class::Renderer.new(methods.first, helper_registry: registry)
    expect(renderer.text).to match(/one#first : \(a Capability_[a-f0-9]{10}\[Object\]\) -> Object/)
  end

  it "derives deterministic -able names without an LLM" do
    methods = [
      *collect("def greet(name); \"hi \#{name}\"; end", "a.rb"),
      *collect("def read(input); input.current_question; input.thread_context; end", "b.rb"),
      *collect("def clean(doc); doc.strip_attachment_stubs(1); end", "c.rb")
    ]
    registry = described_class::UniversalHelperRegistry.new(methods)
    described_class::HeuristicCapabilityNamer.new(registry).name!
    names = registry.definitions.map { |definition| definition.fetch(:name) }

    expect(names).to include(
      "Stringifiable",
      "CurrentQuestionThreadContextReadable",
      "AttachmentStubsStrippable"
    )
  end

  it "escalates colliding heuristic names deterministically without variants" do
    methods = [
      *collect("def a(x); x.fetch(1); end", "a.rb"),
      *collect("def b(y); y.fetch(1, 2); end", "b.rb")
    ]
    registry = described_class::UniversalHelperRegistry.new(methods)
    described_class::HeuristicCapabilityNamer.new(registry).name!
    names = registry.definitions.map { |definition| definition.fetch(:name) }

    expect(names.uniq.length).to eq(2)
    expect(names).to include("Fetchable")
    expect(names.join).not_to include("Variant")
    expect(names.join).not_to match(/Capability_/)
  end

  it "resolves name collisions cluster by cluster instead of Variant-prefixing" do
    methods = [
      *collect("def first(a); a.title; end", "one.rb"),
      *collect("def second(b); b.title(1); end", "two.rb")
    ]
    registry = described_class::UniversalHelperRegistry.new(methods)
    ids = registry.definitions.map { |definition| definition.fetch(:id) }
    expect(ids.length).to eq(2)

    Tempfile.create("capability-names") do |cache|
      path = cache.path
      cache.close
      File.delete(path)
      calls = 0
      runner = lambda do |prompt, _model|
        calls += 1
        case calls
        when 1
          JSON.generate(ids[0] => "TitleReadable", ids[1] => "TitleReadable")
        else
          expect(prompt).to include("TitleReadable", ids[0], ids[1])
          JSON.generate(ids[0] => "TitleReadable", ids[1] => "IndexedTitleReadable")
        end
      end

      described_class::OpenAiCapabilityNamer.new(registry, cache_path: path, runner: runner).name!

      names = registry.definitions.map { |definition| definition.fetch(:name) }
      expect(names).to contain_exactly("TitleReadable", "IndexedTitleReadable")
      expect(names.join).not_to include("Variant")
      expect(calls).to eq(2)
    end
  end

  it "runs and caches batched OpenAI capability naming inside the script" do
    method = collect("def read(input); input.current_question; input.thread_context; end").first
    registry = described_class::UniversalHelperRegistry.new([method])
    id = registry.definitions.first.fetch(:id)

    Tempfile.create("capability-names") do |cache|
      path = cache.path
      cache.close
      File.delete(path)
      runner = lambda do |prompt, model|
        expect(model).to eq("gpt-5.6-luna")
        expect(prompt).to include(id, "current_question")
        JSON.generate(id => "ContextReadable")
      end

      described_class::OpenAiCapabilityNamer.new(
        registry,
        cache_path: path,
        batch_size: 1,
        runner: runner
      ).name!

      expect(JSON.parse(File.read(path))).to eq(id => "ContextReadable")
      expect(registry.definitions.first.fetch(:name)).to eq("ContextReadable")
    end
  end

  it "renders a searchable, escaped HTML report with coverage details" do
    renderer = infer("def identity(value) = value").fetch("example#identity")
    html = described_class::HtmlDocument.new(
      [["example.rb", renderer]],
      analyzed_files: ["example.rb", "fragment.rb"],
      parse_errors: { "fragment.rb" => ["L1: expected <end>"] }
    ).render

    expect(html).to include(
      "<strong>2</strong><span>files analyzed</span>",
      "Parse failures (1)",
      "expected &lt;end&gt;",
      "data-search=",
      ".helper-name { display: block;"
    )
  end
end
