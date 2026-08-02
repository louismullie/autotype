# frozen_string_literal: true

require "spec_helper"

RSpec.describe Autotype::AnomalyDetector do
  def detect(signature, **overrides)
    method_json = {
      name: "Demo#run",
      line: 1,
      end_line: 3,
      signature: signature,
      send_constraint_count: 0,
      constraints: []
    }.merge(overrides)
    described_class.detect(method_json)
  end

  it "flags partially grounded Object unions in the return type" do
    anomalies = detect("Demo#run : () -> Prompt | Object")
    expect(anomalies.map { _1[:code] }).to include("AT001")
  end

  it "does not flag fully unresolved returns" do
    expect(detect("Demo#model : () -> Object")).to be_empty
    expect(detect("Demo#created : () -> Nullable[Object]")).to be_empty
  end

  it "does not flag weak returns on side-effect-named methods" do
    anomalies = detect(
      "Demo#record_pool_attempt : (name String) -> Nullable[Object | String]",
      name: "Demo#record_pool_attempt",
      send_constraint_count: 12
    )
    expect(anomalies.map { _1[:code] }).not_to include("AT001", "AT003", "AT008")
  end

  it "does not flag fully grounded structural returns" do
    anomalies = detect("Demo#reference_name : () -> { to_s() -> String }")
    expect(anomalies.map { _1[:code] }).not_to include("AT002")
  end

  it "does not double-flag nullable mixed unions already covered by AT001" do
    anomalies = detect("Demo#citation_id : () -> Nullable[Object | String]")
    codes = anomalies.map { _1[:code] }
    expect(codes).to include("AT001")
    expect(codes).not_to include("AT003")
  end

  it "treats generated helper names ending in able/ible as duck types" do
    anomalies = detect("Demo#gold? : (message SystemToolTestable[bool, bool, Object]) -> bool")
    expect(anomalies.map { _1[:code] }).not_to include("AT006")
  end

  it "does not flag weak returns on predicates and bang mutators" do
    predicate = detect(
      "Demo#healthy? : () -> Nullable[Object | bool]",
      name: "Demo#healthy?",
      send_constraint_count: 12
    )
    mutator = detect(
      "Demo#refresh_clients! : () -> Nullable[Object]",
      name: "Demo#refresh_clients!",
      send_constraint_count: 12
    )
    expect(predicate.map { _1[:code] }).not_to include("AT001", "AT008")
    expect(mutator.map { _1[:code] }).not_to include("AT001", "AT008")
  end

  it "does not flag weak returns on writer-style and exact effect names" do
    writer = detect(
      "Demo#write_ndjson_gz : (uuid String, records Object) -> Nullable[Object]",
      name: "Demo#write_ndjson_gz",
      send_constraint_count: 12
    )
    logger = detect(
      "Demo#log : () -> Object",
      name: "Demo#log",
      send_constraint_count: 12
    )
    expect(writer.map { _1[:code] }).not_to include("AT001", "AT008")
    expect(logger.map { _1[:code] }).not_to include("AT008")
  end

  it "flags structural returns" do
    anomalies = detect("Demo#run : () -> { content() -> Object }")
    expect(anomalies.map { _1[:code] }).to include("AT002")
  end

  it "allows entityish parameter names typed as grounded containers" do
    anomalies = detect("Demo#process_response : (prompt Hash[String, Object]) -> bool")
    expect(anomalies.map { _1[:code] }).not_to include("AT006")
  end

  it "allows entityish parameter names typed as bare nominal classes" do
    anomalies = detect("Demo#send_payload : (message ChatLogMessage) -> Object")
    expect(anomalies.map { _1[:code] }).not_to include("AT006")
  end

  it "allows constant-valued keyword defaults typed as Class refs" do
    anomalies = detect(
      "Demo.clarification : (prompt: Class[UNSUPPORTED_MESSAGE] | String) -> Demo"
    )
    expect(anomalies.map { _1[:code] }).not_to include("AT006")
  end

  it "splits params correctly when structural types embed commas" do
    anomalies = detect(
      "Demo#validate! : (response { code: String, message: String }) -> nil"
    )
    expect(anomalies.map { _1[:code] }).not_to include("AT006")
  end

  it "allows entityish parameter names when the type is an explicit primitive" do
    anomalies = detect("Demo#process_response : (prompt String) -> bool")
    expect(anomalies.map { _1[:code] }).not_to include("AT006")
  end

  it "ignores grounded stdlib constructor constraints" do
    anomalies = detect(
      "Demo#initialize : () -> Demo",
      constraints: ["Class[Set] responds to new() -> Set"]
    )
    expect(anomalies.map { _1[:code] }).not_to include("AT009")
  end

  it "ignores external class-level factory constraints" do
    anomalies = detect(
      "Demo#initialize : () -> Demo",
      constraints: ["Class[MilvusGrpc] responds to shared_client(endpoint: String) -> Object"]
    )
    expect(anomalies.map { _1[:code] }).not_to include("AT009")
  end

  it "allows the internal type-node union" do
    anomalies = detect("Demo#result : () -> Function | Generic | Named | TypeVariable | Union")
    expect(anomalies.map { _1[:code] }).not_to include("AT005")
  end

  it "allows intentional nullable optional fields" do
    anomalies = detect("Demo#superclass : () -> Nullable[String]")
    expect(anomalies.map { _1[:code] }).not_to include("AT003")
  end

  it "allows duck-type helper parameters named like entities" do
    anomalies = detect("Demo#stem : (message DeleteSuffixMatchable[Object, bool]) -> String")
    expect(anomalies.map { _1[:code] }).not_to include("AT006")
  end

  it "does not flag Object nested inside container types" do
    anomalies = detect("Demo#member_types : () -> Hash[String, Hash[Symbol, Object]]")
    expect(anomalies.map { _1[:code] }).not_to include("AT001")
  end

  it "skips inference implementation classes" do
    anomalies = detect(
      "Autotype::Analyzer#infer : (node Object) -> Object",
      name: "Autotype::Analyzer#infer"
    )
    expect(anomalies).to be_empty
  end

  it "flags toxic runaway signatures" do
    signature = "Demo#run : () -> ArrayOfArrayOfStringOrArrayOfArrayOfArrayOfStringOrArrayOfString"
    anomalies = detect(signature)
    expect(anomalies.map { _1[:code] }).to include("AT004")
  end

  it "allows long but grounded namespace-heavy signatures" do
    signature = "Orca::Actors::VelvetRopes::RagSearch#process : (entity Orca::Entities::Prompt, from: Symbol) -> nil"
    anomalies = detect(signature)
    expect(anomalies.map { _1[:code] }).not_to include("AT004")
  end

  it "reports no anomalies for grounded signatures" do
    anomalies = detect("Demo#run : (prompt Orca::Entities::Prompt) -> Array[Orca::Entities::Prompt]")
    expect(anomalies).to be_empty
  end
end
