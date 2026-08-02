# frozen_string_literal: true

require "spec_helper"

RSpec.describe AutotypeNative do
  it "loads the C extension and exposes solve_graph" do
    expect(described_class.available?).to be(true)
    expect(described_class).to respond_to(:solve_graph)
  end

  it "unifies array append capabilities via the native solver" do
    described_class.load_extension!

    graph = {
      "capabilities" => [
        {
          "message" => "<<",
          "receiver" => {
            "k" => "generic",
            "name" => "Array",
            "args" => [{ "k" => "var", "id" => 100, "hint" => "element" }]
          },
          "result" => 200,
          "args" => [{ "k" => "named", "name" => "String" }],
          "line" => 1
        }
      ],
      "bindings" => {}
    }

    result = described_class.solve_graph(graph)
    bindings = result.fetch(:bindings).transform_keys(&:to_i).transform_values { _1.transform_keys(&:to_s) }

    expect(result.fetch(:converged)).to be(true)
    expect(bindings.fetch(100)).to eq("k" => "named", "name" => "String")
    result_type = bindings.fetch(200)
    expect(result_type.fetch("k")).to eq("generic")
    expect(result_type.fetch("name")).to eq("Array")
  end

  it "round-trips through NativeBridge on a small inferencer graph" do
    skip "NativeBridge unavailable" unless Autotype::NativeBridge.native_available?

    source = <<~RUBY
      class Demo
        def push(item)
          buffer = []
          buffer << item
          buffer
        end
      end
    RUBY

    result = Prism.parse(source)
    collector = Autotype::Collector.new("demo.rb")
    result.value.accept(collector)
    inferencer = Autotype::FixedPointInferencer.new(
      collector.methods,
      constants: collector.constants,
      includes: collector.includes,
      metadata: Autotype::InferenceMetadata.empty
    )
    inferencer.apply_declared_annotations!
    inferencer.send(:anchor_constructor_definitions)

    Autotype::NativeBridge.prime!(inferencer)

    renderer = Autotype::Renderer.new(inferencer.send(:resolved_method, collector.methods.first))
    expect(renderer.text.lines.first).to include("-> Array[")
  end
end
