package com.jojo.vuln.analyzer;

import io.avaje.jsonb.Json;

@Json
public record OsvQuery(@Json.Property("package") PackageInfo packageInfo) {

  public OsvQuery(String name, String ecosystem) {
    this(new PackageInfo(name, ecosystem));
  }

  public record PackageInfo(String name, String ecosystem) {}
}
