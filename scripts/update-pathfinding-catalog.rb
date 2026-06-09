#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "yaml"

if ARGV.length != 2
  warn "usage: scripts/update-pathfinding-catalog.rb PATHFINDING_REPO OUT_JSON"
  exit 2
end

source_root = File.expand_path(ARGV[0])
out_path = File.expand_path(ARGV[1])
paths_root = File.join(source_root, "data", "paths")

unless Dir.exist?(paths_root)
  warn "pathfinding.cloud data/paths directory not found: #{paths_root}"
  exit 1
end

catalog = Dir[File.join(paths_root, "**", "*.yaml")].sort.map do |file|
  yaml = YAML.load_file(file)
  permissions = yaml.fetch("permissions", {})
  required = Array(permissions["required"]).map { |item| item["permission"] }.compact
  additional = Array(permissions["additional"]).map { |item| item["permission"] }.compact
  references = Array(yaml["references"]).map { |item| item["url"] }.compact

  {
    id: yaml.fetch("id"),
    name: yaml.fetch("name"),
    category: yaml.fetch("category"),
    services: Array(yaml["services"]),
    required_actions: required,
    additional_actions: additional,
    references: references,
    source_path: file.delete_prefix("#{source_root}/")
  }
end

File.write(out_path, "#{JSON.pretty_generate(catalog)}\n")
