package com.jojo.vuln.analyzer;

import io.avaje.http.api.Client;
import io.avaje.http.api.Post;

@Client
public interface OSVClient {

  @Post("https://api.osv.dev/v1/query")
  OsvResponse call(OsvQuery body);
}
