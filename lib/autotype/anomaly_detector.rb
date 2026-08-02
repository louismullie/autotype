# frozen_string_literal: true

module Autotype
  # Flags suspicious inferred signatures for editor diagnostics and review.
  class AnomalyDetector
    ENTITYISH_PARAM_NAMES = %w[
      prompt request entity query message hit tool_call tool_result chunk completion
    ].freeze
    TOXIC_SIGNATURE_PATTERN = /(?:OrArrayOf|ArrayOfArrayOf|OrAndSymbol){2,}/i
    TYPE_SYSTEM_UNION_MEMBERS = %w[Function Generic Named TypeVariable Union].freeze
    PRIMITIVE_PARAM_TYPES = %w[String Integer Float bool Symbol nil].freeze
    # Generated structural helper names (FitsTestable[...], IndexDuplicable[...],
    # DeleteSuffixMatchable[...]) are synthesized duck types, not weak inference.
    DUCK_TYPE_HELPER = /\b[A-Z][A-Za-z0-9]*(?:able|ible)\[/.freeze
    # Methods whose names declare they are called for effect; their return value
    # is not part of the contract, so weak return types are not anomalies.
    SIDE_EFFECT_NAME = /\A(?:record|log|track|emit|notify|publish|report|instrument|audit|broadcast|persist|warn|write|save|store|flush|append|push|send|dispatch|upload|backfill|delete|remove|clear|reset|cleanup)_/.freeze
    SIDE_EFFECT_EXACT_NAMES = %w[log warn flush reset clear].freeze

    # The inference engine intentionally manipulates weak type nodes. Lint rules
    # meant for application code do not apply to these implementation classes.
    INFERENCE_IMPLEMENTATION_OWNERS = %w[
      Autotype::Analyzer
      Autotype::Collector
      Autotype::FixedPointInferencer
      Autotype::Renderer
      Autotype::UniversalHelperRegistry
      Autotype::HtmlDocument
      Autotype::HeuristicCapabilityNamer
      Autotype::OpenAiCapabilityNamer
      Autotype::CLI
      Autotype::InferenceMetadata
      Autotype::TypeVariable
      Autotype::AnomalyDetector
    ].freeze

    def self.detect(method_json)
      new(method_json).detect
    end

    def initialize(method_json)
      @method = method_json
      @signature = method_json.fetch(:signature).to_s
      @method_name = method_json.fetch(:name).to_s
      @simple_name = @method_name.split(/[#.]/).last.to_s
      @return_type = extract_return_type(@signature)
      @params = extract_params(@signature)
    end

    def detect
      return [] if skip_anomaly_checks?

      [].tap do |anomalies|
        check_weak_object_return(anomalies)
        check_structural_return(anomalies)
        check_nullable_return(anomalies)
        check_toxic_signature(anomalies)
        check_wide_union(anomalies)
        check_param_name_mismatch(anomalies)
        check_high_constraint_weak_return(anomalies)
        check_unresolved_constraints(anomalies)
      end
    end

    private

    def skip_anomaly_checks?
      owner = owner_name
      return true if INFERENCE_IMPLEMENTATION_OWNERS.include?(owner)
      return true if owner == "Autotype" && @simple_name.start_with?("bootstrap_")

      false
    end

    def owner_name
      if @method_name.include?("#")
        @method_name.split("#").first
      else
        @method_name.split(".").first
      end
    end

    def extract_return_type(signature)
      signature.split("->", 2).last&.strip.to_s
    end

    def extract_params(signature)
      params_text = signature[/\((.*)\)\s*->/m, 1]
      return [] unless params_text

      split_params(params_text).filter_map do |chunk|
        name, type = chunk.strip.split(/\s+/, 2)
        next unless name && type

        { name: name.delete_prefix("*").delete_prefix("&").delete_suffix(":").delete_suffix("?"), type: type }
      end
    end

    def split_params(text)
      parts = []
      depth = 0
      current = +""
      text.each_char do |char|
        # Structural types embed commas inside braces: `{ code: String, ... }`.
        depth += 1 if char == "[" || char == "{"
        depth -= 1 if char == "]" || char == "}"
        if depth.zero? && char == ","
          parts << current
          current = +""
        else
          current << char
        end
      end
      parts << current unless current.empty?
      parts
    end

    def union_members(type)
      return [] if type.empty?

      depth = 0
      members = []
      start = 0
      type.each_char.with_index do |char, index|
        depth += 1 if char == "[" || char == "{"
        depth -= 1 if char == "]" || char == "}"
        next unless depth.zero? && type[index, 3] == " | "

        members << type[start...index].strip
        start = index + 3
      end
      members << type[start..].strip
      members.reject(&:empty?)
    end

    # Object nested inside Hash/Array type parameters is intentional in many
    # APIs (metadata maps, generic bags). Only flag bare Object at the top.
    def bare_object?(type)
      type = type.strip
      return true if type == "Object"

      # Split unions before the container shortcut, or "Array[X] | Object"
      # would match the Array[ prefix and hide the bare Object member.
      members = union_members(type)
      return members.any? { |member| bare_object?(member) } if members.length > 1

      return false if container_type?(type)

      if type.start_with?("Nullable[")
        inner = type[/\ANullable\[(.+)\]\z/m, 1]
        return inner ? bare_object?(inner) : false
      end

      structural_return?(type) && type.include?("Object")
    end

    # A return that carries zero information: inference had no evidence at all.
    # Absence of evidence is the default state for delegators and readers of
    # unannotated data, not an anomaly worth surfacing.
    def fully_unresolved?(type)
      type = type.strip
      type == "Object" || type == "Nullable[Object]"
    end

    # Called for effect: name convention, setter, or bang mutator. Weak return
    # types on these are by design; predicates get bool by convention so a
    # residual Object branch is an engine concern, not a user-facing anomaly.
    def effect_only_method?
      @simple_name.match?(SIDE_EFFECT_NAME) ||
        SIDE_EFFECT_EXACT_NAMES.include?(@simple_name) ||
        @simple_name.end_with?("=") ||
        @simple_name.end_with?("!") ||
        @simple_name.end_with?("?")
    end

    def container_type?(type)
      type.match?(/\A(?:Hash|Array|Set|Enumerator)\[/)
    end

    def nullable_object?(type)
      inner = type[/\ANullable\[(.+)\]\z/m, 1].to_s
      inner == "Object" || union_members(inner).include?("Object")
    end

    def weak_return?(type)
      bare_object?(type) || structural_return?(type)
    end

    def structural_return?(type)
      type.start_with?("{") && type.end_with?("}")
    end

    # AT001 fires only on *partially* grounded returns (Object mixed into a
    # union with real types) — evidence that inference diverged mid-method.
    # Fully unresolved returns carry no signal and are skipped.
    def check_weak_object_return(anomalies)
      return if effect_only_method?
      return if fully_unresolved?(@return_type)
      return unless bare_object?(@return_type)

      add(
        anomalies,
        code: "AT001",
        severity: "hint",
        message: "Return type mixes Object with grounded types",
        detail: "Some branches of this method resolved to concrete types but others did not."
      )
    end

    # Structural returns that are fully grounded ({ to_s() -> String }) are
    # informative duck types; only flag ones that still contain Object.
    def check_structural_return(anomalies)
      return if effect_only_method?
      return unless structural_return?(@return_type)
      return unless @return_type.include?("Object")

      add(
        anomalies,
        code: "AT002",
        severity: "hint",
        message: "Return type is structural with unresolved members",
        detail: "The method return is described only by message sends, and some are ungrounded."
      )
    end

    def check_nullable_return(anomalies)
      return if effect_only_method?
      return unless @return_type.start_with?("Nullable[")
      return if @simple_name.end_with?("?")
      return if fully_unresolved?(@return_type)
      # AT001 already covers mixed Object unions; avoid double-flagging.
      return if anomalies.any? { |anomaly| anomaly[:code] == "AT001" }

      inner = @return_type[/\ANullable\[(.+)\]\z/m, 1].to_s
      return unless bare_object?(inner) || inner.match?(/\|\s*Object\b/) || inner == "Object"

      add(
        anomalies,
        code: "AT003",
        severity: "hint",
        message: "Non-predicate method returns Nullable",
        detail: "Consider whether nil is intentional or a missing return path."
      )
    end

    def check_toxic_signature(anomalies)
      return unless @signature.match?(TOXIC_SIGNATURE_PATTERN)

      add(
        anomalies,
        code: "AT004",
        severity: "error",
        message: "Type signature failed sanity check",
        detail: "The inferred type string is excessively long or recursive."
      )
    end

    def check_wide_union(anomalies)
      members = union_members(@return_type)
      return unless members.length >= 4
      return if members.all? { |member| type_system_member?(member) }

      add(
        anomalies,
        code: "AT005",
        severity: "hint",
        message: "Return type is a wide union (#{members.length} members)",
        detail: members.join(" | ")
      )
    end

    def check_param_name_mismatch(anomalies)
      @params.each do |param|
        next unless ENTITYISH_PARAM_NAMES.include?(param[:name])
        next if param[:type].include?("::")
        next if primitive_param_type?(param[:type])
        next if duck_type_name?(param[:type])

        add(
          anomalies,
          code: "AT006",
          severity: "hint",
          message: "Parameter `#{param[:name]}` looks like an entity but is typed #{param[:type]}",
          detail: "Name conventions suggest a structured entity type."
        )
      end
    end

    def check_high_constraint_weak_return(anomalies)
      return if effect_only_method?

      count = @method.fetch(:send_constraint_count, 0)
      return unless count > 8
      return unless weak_return?(@return_type) || fully_unresolved?(@return_type)

      add(
        anomalies,
        code: "AT008",
        severity: "warning",
        message: "Many sends (#{count}) but weak return type",
        detail: "Heavy method body with an unresolved return."
      )
    end

    def check_unresolved_constraints(anomalies)
      constraints = Array(@method[:constraints]).reject { |constraint| grounded_constraint?(constraint) }
      return if constraints.empty?

      add(
        anomalies,
        code: "AT009",
        severity: "info",
        message: "#{constraints.length} unresolved send constraint(s)",
        detail: constraints.first(3).join("\n")
      )
    end

    def grounded_constraint?(constraint)
      text = constraint.to_s
      # Sends on Class[...] receivers describe external or class-level APIs
      # (client factories, stdlib constructors) the repo cannot resolve;
      # expected, not an inference failure inside this method.
      return true if text.start_with?("Class[")

      # When the receiver itself already contains Object, an unresolved return
      # is just the upstream unknown propagating — not a new failure here.
      receiver = text.split(" responds to ", 2).first.to_s.strip
      return true if bare_object?(receiver)

      return_type = text.split(" -> ", 2).last.to_s.strip
      return false if return_type.empty?
      return false if bare_object?(return_type)
      return false if structural_return?(return_type)

      true
    end

    def type_system_member?(member)
      TYPE_SYSTEM_UNION_MEMBERS.include?(member) ||
        member.start_with?("Autotype::") ||
        member.start_with?("Nullable[")
    end

    def duck_type_name?(type)
      type.match?(DUCK_TYPE_HELPER)
    end

    def primitive_param_type?(type)
      return true if PRIMITIVE_PARAM_TYPES.include?(type)
      return true if type == "Object"

      if (match = type.match(/\ANullable\[(.+)\]\z/))
        return primitive_param_type?(match[1])
      end

      members = union_members(type)
      return false if members.empty?

      members.all? { |member| primitive_or_noise_type?(member) }
    end

    def primitive_or_noise_type?(type)
      PRIMITIVE_PARAM_TYPES.include?(type) ||
        type == "Object" ||
        structural_return?(type) ||
        duck_type_name?(type) ||
        # Hash/Array bags are grounded containers, not misnamed entities.
        container_type?(type) ||
        # Class[SOME_CONST] members come from constant-valued keyword defaults.
        type.start_with?("Class[") ||
        # A bare nominal class name (ChatLogMessage) is a grounded type even
        # without a namespace qualifier.
        type.match?(/\A[A-Z][A-Za-z0-9_]*\z/)
    end

    def add(anomalies, code:, severity:, message:, detail: nil)
      anomalies << {
        code: code,
        severity: severity,
        message: message,
        detail: detail,
        signature: @signature
      }.compact
    end
  end
end
