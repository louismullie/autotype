# frozen_string_literal: true

require "bundler/gem_tasks"
require "rspec/core/rake_task"

RSpec::Core::RakeTask.new(:spec)

task default: :spec

namespace :native do
  desc "Build standalone C smoke test"
  task :test do
    sh "make -C native/autotype test"
  end

  desc "Build Ruby C extension"
  task :compile do
    sh "ruby ext/autotype/extconf.rb"
    sh "make -C ext/autotype"
  end
end
