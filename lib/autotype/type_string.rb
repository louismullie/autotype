# frozen_string_literal: true

module Autotype
  module TypeString
    module_function

    def parse(string)
      string = string.to_s.strip
      raise ArgumentError, "type string cannot be empty" if string.empty?

      if string.include?("|")
        members = string.split("|").map { parse(_1.strip) }
        return members.first if members.length == 1

        return Union.new(members.uniq)
      end

      if (match = string.match(/\A([A-Za-z_][\w:]*)\[(.*)\]\z/m))
        name = match[1]
        args = split_args(match[2]).map { parse(_1) }
        return Generic.new(name, args)
      end

      Named.new(string)
    end

    def split_args(source)
      args = []
      depth = 0
      start = 0
      source.each_char.with_index do |char, index|
        case char
        when "["
          depth += 1
        when "]"
          depth -= 1
        when ","
          if depth.zero?
            args << source[start...index]
            start = index + 1
          end
        end
      end
      args << source[start..]
      args.map(&:strip).reject(&:empty?)
    end
  end
end
