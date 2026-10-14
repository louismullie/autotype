# frozen_string_literal: true

require "spec_helper"
require "tmpdir"

RSpec.describe Autotype, "analysis API" do
  def write(dir, name, source)
    File.join(dir, name).tap { |path| File.write(path, source) }
  end

  let(:greeter_source) do
    <<~RUBY
      class Greeter
        GREETING = "hello"

        def greet(name, greeting: GREETING) = greeting + name
      end
    RUBY
  end

  it "returns signatures and diagnostics as data without printing" do
    Dir.mktmpdir do |dir|
      greeter = write(dir, "greeter.rb", greeter_source)
      broken = write(dir, "broken.rb", "def broken(\n")
      analysis = nil

      expect { analysis = described_class.analyze(dir) }.not_to output.to_stdout
      expect(analysis.files).to contain_exactly(greeter, broken)
      expect(analysis).to be_converged
      expect(analysis.find("Greeter#greet")).to have_attributes(path: greeter, line: 4)
      expect(analysis.find("Greeter#greet").signature).to include("greeting:? String").and end_with("-> String")
      expect(analysis.diagnostics).not_to be_empty
      expect(analysis.diagnostics).to all(have_attributes(kind: :parse, path: broken, line: 1))
    end
  end

  it "produces the same document as autotype --json" do
    Dir.mktmpdir do |dir|
      greeter = write(dir, "greeter.rb", greeter_source)
      stdout = StringIO.new
      original = $stdout
      begin
        $stdout = stdout
        described_class.run([greeter, "--json"])
      ensure
        $stdout = original
      end

      expect(JSON.parse(described_class.analyze(greeter).to_json)).to eq(JSON.parse(stdout.string))
    end
  end

  it "analyzes unsaved source under the given path" do
    analysis = described_class.analyze_source("class Foo\n  def twice(n) = n * 2\nend\n", path: "foo.rb")

    expect(analysis.method_reports.map(&:name)).to eq(["Foo#twice"])
    expect(analysis.method_reports.first.path).to eq("foo.rb")
    expect(analysis.method_reports.first.text).to start_with("Foo#twice : ")
  end

  it "reports unreadable files instead of raising" do
    analysis = described_class.analyze(["does/not/exist.rb"])

    expect(analysis.method_reports).to be_empty
    expect(analysis.diagnostics).to contain_exactly(have_attributes(kind: :parse, path: "does/not/exist.rb"))
  end

  it "honors an explicit config without touching the global configuration" do
    Dir.mktmpdir do |dir|
      greeter = write(dir, "greeter.rb", greeter_source)
      skipped = write(dir, "skipped.rb", "class Skipped\n  def value = 1\nend\n")
      config = write(dir, "autotype.yml", { "skip" => [skipped] }.to_yaml)

      expect { described_class.analyze([greeter, skipped], config: config) }
        .not_to(change { described_class.configuration.config_path })
      expect(described_class.analyze([greeter, skipped], config: config).files).to eq([greeter])
    end
  end
end
