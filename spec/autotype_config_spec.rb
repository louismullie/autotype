# frozen_string_literal: true

require "spec_helper"
require "fileutils"

RSpec.describe Autotype::TypeString do
  it "parses named types" do
    expect(described_class.parse("String")).to eq(Autotype::Named.new("String"))
  end

  it "parses generic types" do
    type = described_class.parse("Array[String]")
    expect(type).to eq(Autotype::Generic.new("Array", [Autotype::Named.new("String")]))
  end

  it "parses nested generics" do
    type = described_class.parse("Hash[Symbol, Object]")
    expect(type.name).to eq("Hash")
    expect(type.arguments.map(&:name)).to eq(%w[Symbol Object])
  end

  it "parses unions" do
    type = described_class.parse("String | nil")
    expect(type).to be_a(Autotype::Union)
    expect(type.members.map(&:name)).to eq(%w[String nil])
  end
end

RSpec.describe Autotype::DiscoveryProfile do
  let(:fixture_root) { File.expand_path("fixtures", __dir__) }

  it "infers actor port wiring from handler methods" do
    source = <<~RUBY
      class DemoActor < Actor
        input :prompts, type: Entities::Prompt

        def process(prompt, from:)
          prompt
        end
      end
    RUBY

    collector = Autotype::Collector.new("demo_actor.rb", profile: described_class.new)
    Prism.parse(source).value.accept(collector)
    profile = described_class.new
    profile.finalize!([collector])

    wiring = profile.port_wiring
    expect(wiring.handler_method).to eq(:process)
    expect(wiring.dispatch_param).to eq(:from)
  end

  it "locates entity files by constant name under the project tree" do
    profile = described_class.new(root: fixture_root)
    profile.prepare_search!([File.expand_path("fixtures/pipeline/actors/demo_actor.rb", __dir__)])

    expect(profile.locate_type_file("App::Entities::ToolCall")).to eq(
      File.expand_path("fixtures/entities/tool_call.rb", __dir__)
    )
  end

  it "lists the project tree once however many types it locates" do
    profile = described_class.new(root: fixture_root)
    allow(profile).to receive(:git_ruby_files).and_call_original
    allow(Dir).to receive(:glob).and_call_original

    expect(profile.locate_type_file("App::Entities::ToolCall")).to end_with("entities/tool_call.rb")
    expect(profile.locate_type_file("App::Entities::ToolResult")).to end_with("entities/tool_result.rb")
    expect(profile.locate_type_file("App::Entities::Missing")).to be_nil
    expect(profile).to have_received(:git_ruby_files).once
    expect(Dir).to have_received(:glob).at_most(:once)
  end

  it "skips files git ignores when locating types" do
    Dir.mktmpdir do |dir|
      system("git", "init", "-q", dir, exception: true)
      File.write(File.join(dir, ".gitignore"), "vendor/\n")
      { "vendor/gems/tool_call.rb" => "class ToolCall; end\n", "app/entities/tool_result.rb" => "class ToolResult; end\n" }.each do |path, source|
        FileUtils.mkdir_p(File.dirname(File.join(dir, path)))
        File.write(File.join(dir, path), source)
      end

      profile = described_class.new(root: dir)
      expect(profile.locate_type_file("ToolResult")).to eq(File.join(dir, "app/entities/tool_result.rb"))
      expect(profile.locate_type_file("ToolCall")).to be_nil
    end
  end

  it "loads optional overrides from autotype.yml" do
    Dir.mktmpdir do |dir|
      config_path = File.join(dir, "autotype.yml")
      File.write(config_path, <<~YAML)
        skip:
          - vendor/**
        types:
          members:
            query: App::Entities::Query
      YAML

      profile = described_class.load_overrides(config_path)
      expect(profile.skipped_files).to include("vendor/**")
      expect(profile.member_type_hints[:query]).to eq(Autotype::Named.new("App::Entities::Query"))
    end
  end

  it "discovers autotype.yml from nested directories" do
    Dir.mktmpdir do |dir|
      config_dir = File.join(dir, "project")
      FileUtils.mkdir_p(config_dir)
      File.write(File.join(config_dir, "autotype.yml"), "skip:\n  - vendor/**\n")

      nested = File.join(config_dir, "app", "actors")
      FileUtils.mkdir_p(nested)

      expect(described_class.find(nested)).to eq(File.join(config_dir, "autotype.yml"))
    end
  end
end
