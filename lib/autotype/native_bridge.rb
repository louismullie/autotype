# frozen_string_literal: true

module Autotype
  module NativeBridge
    module_function

    def enabled?
      ENV["AUTOTYPE_NATIVE"] == "1" && native_available?
    end

    def native_available?
      require_relative "native"
      AutotypeNative.available?
    rescue LoadError, StandardError
      false
    end

    def export_type(type)
      case type
      when Autotype::Named
        { "k" => "named", "name" => type.name }
      when Autotype::Generic
        { "k" => "generic", "name" => type.name, "args" => type.arguments.map { export_type(_1) } }
      when Autotype::Union
        { "k" => "union", "members" => type.members.map { export_type(_1) } }
      when Autotype::TypeVariable
        { "k" => "var", "id" => type.object_id, "hint" => type.hint.to_s }
      else
        { "k" => "named", "name" => "Object" }
      end
    end

    def import_type(hash)
      entry = hash.transform_keys(&:to_s)
      case entry["k"]
      when "named" then Autotype::Named.new(entry["name"])
      when "generic"
        Autotype::Generic.new(entry["name"], entry["args"].map { import_type(_1) })
      when "union"
        Autotype::Union.new(entry["members"].map { import_type(_1) })
      else
        Autotype::Named.new("Object")
      end
    end

    def export_graph(inferencer)
      resolve = inferencer.method(:resolve)
      var_objects = {}
      capabilities = []

      inferencer.instance_variable_get(:@methods).each do |method|
        method.capabilities.each do |capability|
          next if capability.arguments.any? { |argument| argument.is_a?(Autotype::Function) }

          args = capability.arguments.reject { |argument| argument.is_a?(Autotype::Function) }
          result = capability.result
          next unless result.is_a?(Autotype::TypeVariable)

          var_objects[result.object_id] = result
          receiver = capability.receiver
          var_objects[receiver.object_id] = receiver if receiver.is_a?(Autotype::TypeVariable)

          args.each do |argument|
            var_objects[argument.object_id] = argument if argument.is_a?(Autotype::TypeVariable)
          end

          capabilities << {
            "message" => capability.message.to_s,
            "receiver" => export_type(receiver),
            "result" => result.object_id,
            "args" => args.map { export_type(_1) },
            "line" => capability.line
          }
        end
      end

      bindings = inferencer.instance_variable_get(:@substitutions).each_with_object({}) do |(variable, type), hash|
        resolved = resolve.call(type)
        next if resolved.is_a?(Autotype::TypeVariable)

        hash[variable.object_id] = export_type(resolved)
      end

      {
        "capabilities" => capabilities,
        "bindings" => bindings,
        "var_count" => var_objects.size
      }
    end

    def apply_result!(inferencer, result)
      result = result.transform_keys(&:to_s) if result.is_a?(Hash)
      var_map = {}
      inferencer.instance_variable_get(:@methods).each do |method|
        method.capabilities.each do |capability|
          [capability.receiver, capability.result, *capability.arguments].each do |node|
            var_map[node.object_id] = node if node.is_a?(Autotype::TypeVariable)
          end
        end
        method.parameters.each { |parameter| var_map[parameter.type.object_id] = parameter.type if parameter.type.is_a?(Autotype::TypeVariable) }
        method.ivars.each_value { |type| var_map[type.object_id] = type if type.is_a?(Autotype::TypeVariable) }
      end

      subs = inferencer.instance_variable_get(:@substitutions)
      result.fetch("bindings").each do |object_id, type_hash|
        variable = var_map[object_id.to_i]
        next unless variable

        subs[variable] = import_type(type_hash)
      end
    end

    def prime!(inferencer)
      native_available?
      graph = export_graph(inferencer)
      result = AutotypeNative.solve_graph(graph)
      apply_result!(inferencer, result)
      result
    end
  end
end
