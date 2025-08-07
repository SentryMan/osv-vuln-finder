package com.jojo.vuln.analyzer;

import io.avaje.http.client.HttpClient;
import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Year;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class ProjectCveFinder {
  private static final String INPUT_CSV = "input.csv";
  private static final String YEARLY_VULNERABILITY_SUMMARY_CSV = "yearly-vulnerability-summary.csv";
  private static final String VULNERABILITY_SUMMARY_CSV = "vulnerability-summary.csv";
  private static final String CACHED_CVE_LIST_CSV = "cached-cve-list.csv";

  private static final OSVClient CLIENT = HttpClient.builder().build().create(OSVClient.class);

  private List<Vulnerability> cveDetails = new ArrayList<>();

  public ProjectCveFinder() throws IOException {
    loadCveDetails();
  }

  private void loadCveDetails() throws IOException {
    if (Files.exists(Path.of(CACHED_CVE_LIST_CSV))) {

      Files.readAllLines(Path.of(CACHED_CVE_LIST_CSV)).stream()
          .skip(1)
          .filter(s -> s.contains(","))
          .map(s -> s.split(","))
          .map(Vulnerability::new)
          .forEach(cveDetails::add);

    } else {
      cveDetails = new ArrayList<>();
    }
  }

  public List<Vulnerability> findVulnerabilities(String packageName)
      throws IOException, InterruptedException {
    // Find cached vulnerabilities
    List<Vulnerability> packageVulnerabilities =
        cveDetails.stream().filter(v -> packageName.equals(v.packageName())).toList();

    // If not cached, fetch from API
    if (packageVulnerabilities.isEmpty()) {

      OsvResponse response = CLIENT.call(new OsvQuery(packageName, "Maven"));

      List<Vulnerability> newVulns = new ArrayList<>();
      if (response.vulns() != null && !response.vulns().isEmpty()) {
        System.out.println("%s has had %s vulns".formatted(packageName, response.vulns().size()));

        response.vulns().stream()
            .map(cve -> new Vulnerability(packageName, cve.published(), cve.summary()))
            .forEach(
                v -> {
                  cveDetails.add(v);
                  newVulns.add(v);
                });

      } else {
        System.out.println(packageName + ", 0");
        Vulnerability zeroVuln = new Vulnerability(packageName, "0", " ");
        cveDetails.add(zeroVuln);
        newVulns.add(zeroVuln);
      }

      saveCveDetails();
      Thread.sleep(100);
      packageVulnerabilities = newVulns;
    }

    return packageVulnerabilities.stream().filter(v -> !"0".equals(v.published())).toList();
  }

  private void saveCveDetails() throws IOException {
    try (FileWriter writer = new FileWriter(CACHED_CVE_LIST_CSV)) {
      writer.write("packageName, published, summary\n");
      for (Vulnerability vuln : cveDetails) {
        writer.write(vuln.toCsvRow());
      }
    }
  }

  private static void writeVulnerabilitySummaryToFile(List<Vulnerability> allVulnerabilities)
      throws IOException {
    // Group vulnerabilities by package name and count them
    Map<String, Long> summary =
        allVulnerabilities.stream()
            .collect(Collectors.groupingBy(Vulnerability::packageName, Collectors.counting()));

    try (var writer = new FileWriter(VULNERABILITY_SUMMARY_CSV)) {
      // Write the header
      writer.write("Dependency, Historical CVE Count\n");

      // Write each dependency's CVE count
      for (Map.Entry<String, Long> entry : summary.entrySet()) {
        writer.write("%s,%s\n".formatted(entry.getKey(), String.valueOf(entry.getValue())));
      }
    }
    System.out.println("Vulnerability summary written to " + VULNERABILITY_SUMMARY_CSV);
  }

  private static void writeYearlySummaryToFile(List<Vulnerability> allVulnerabilities)
      throws IOException {
    // Count vulnerabilities per year
    Map<String, Long> yearlyCounts =
        allVulnerabilities.stream()
            .filter(v -> v.published() != null && v.published().length() >= 4)
            .collect(
                Collectors.groupingBy(v -> v.published().substring(0, 4), Collectors.counting()));

    try (var writer = new FileWriter(YEARLY_VULNERABILITY_SUMMARY_CSV)) {
      // Write the header
      writer.write("Year, Vulnerability Count\n");

      // Write each year and its count
      for (var entry : yearlyCounts.entrySet().stream().sorted(Map.Entry.comparingByKey()).toList())
        writer.write("%s, %s\n".formatted(entry.getKey(), String.valueOf(entry.getValue())));
    }
    System.out.println(
        "Yearly vulnerability summary written to " + YEARLY_VULNERABILITY_SUMMARY_CSV);
  }

  // call maven to produce list of dependencies
  static void callMaven() throws IOException, InterruptedException {

    // Build the command
    String command = "mvn dependency:list -DoutputFile=input.csv";

    // Create ProcessBuilder
    ProcessBuilder processBuilder = new ProcessBuilder();

    // Set the command based on the operating system
    if (System.getProperty("os.name").toLowerCase().contains("windows")) {
      processBuilder.command("cmd", "/c", command);
    } else {
      processBuilder.command("bash", "-c", command);
    }

    System.out.println("Executing command: " + command);

    // Start the process
    Process process = processBuilder.start();

    // Read the output
    BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

    // Read error stream
    BufferedReader errorReader =
        new BufferedReader(new InputStreamReader(process.getErrorStream()));

    String line;
    System.out.println("--- Output ---");
    while ((line = reader.readLine()) != null) {
      System.out.println(line);
    }

    System.out.println("--- Errors (if any) ---");
    while ((line = errorReader.readLine()) != null) {
      System.err.println(line);
    }

    // Wait for the process to complete
    int exitCode = process.waitFor();
    System.out.println("Command executed with exit code: " + exitCode);

    if (exitCode == 0) {
      System.out.println("Maven dependency list generated successfully in input.csv");
    } else {
      System.err.println("Command failed with exit code: " + exitCode);
    }
  }

  public static void main(String[] args) throws IOException, InterruptedException {
    ProjectCveFinder finder = new ProjectCveFinder();
    List<Vulnerability> allVulnerabilities = new ArrayList<>();

    callMaven();

    var dependencies =
        Files.readAllLines(Path.of(INPUT_CSV)).stream()
            .filter(
                s ->
                    !s.isBlank()
                        && s.contains(":")
                        && (s.contains("compile") || s.contains("runtime")))
            .map(String::trim)
            .map(d -> d.split(":")[0] + ":" + d.split(":")[1])
            .toList();

    for (int i = 0; i < dependencies.size(); i++) {
      String dependency = dependencies.get(i);

      System.out.printf("%d of %d : %s%n", i, dependencies.size(), dependency);

      List<Vulnerability> packageVulns = finder.findVulnerabilities(dependency);
      if (!packageVulns.isEmpty()) {
        allVulnerabilities.addAll(packageVulns);
      }
    }

    System.out.println("------------------------------------------");
    System.out.println("Total Vulnerabilities by year:");
    for (int i = Year.now().getValue(); i > 2017; i--) {
      var year = i;
      var count =
          allVulnerabilities.stream()
              .filter(v -> v.published() != null && v.published().startsWith(String.valueOf(year)))
              .count();
      System.out.println(year + " - " + count);
    }
    writeVulnerabilitySummaryToFile(allVulnerabilities);
    writeYearlySummaryToFile(allVulnerabilities);
  }
}
