# frozen_string_literal: true

module Actors
  class DemoActor < App::Actor
    input :tool_calls, type: App::Entities::ToolCall
    input :tool_results, type: App::Entities::ToolResult
  end
end
