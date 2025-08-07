package com.jojo.vuln.analyzer;

import io.avaje.jsonb.Json;
import java.util.List;

@Json
public record OsvResponse(List<CVE> vulns) {

  public record CVE(String published, String summary) {}
}
