# Burp Suite Traversal Scanner Extension

This Burp Suite extension, `TraversalScanner.java`, actively scans for file path traversal vulnerabilities. It extracts URLs from HTTP responses, constructs payloads, and sends requests in parallel. Results are reported through Burp Suite's logging and alert systems.

## Features

* **URL Extraction:** Extracts URLs from HTML and CSS content within HTTP responses.
* **Parameter Parsing:** Parses URL parameters to identify potential injection points.
* **Parallel Requests:** Sends traversal requests in parallel using `sendRequests(List<HttpRequest> requests)` for improved performance.
* **Vulnerability Reporting:** Reports potential vulnerabilities through Burp Suite's logging and alerts.
* **Payload Encoding:** URL-encodes payloads to ensure proper handling by target applications.
* **Base URL and Parameter Handling:** Tests both base URLs and URLs with parameters for traversal vulnerabilities.

## Usage

1. **Compilation:**
    * Compile `TraversalScanner.java` into a JAR file using a Java compiler (e.g., `javac`).
    * Ensure the Burp Suite Extender API JAR file (`burp-extender-api.jar`) is included in the classpath during compilation.

    ```bash
    javac -cp burp-extender-api.jar TraversalScanner.java
    jar cvf TraversalScanner.jar TraversalScanner.class
    ```

2. **Loading in Burp Suite:**
    * Open Burp Suite.
    * Navigate to `Extender` > `Extensions`.
    * Click `Add`.
    * Select "Java" as the extension type.
    * Choose the generated `TraversalScanner.jar` file.
    * Click `Next`.
    * The extension will automatically begin processing HTTP responses.

3. **Operation:**
    * The extension will automatically process HTTP responses intercepted by Burp Suite.
    * It will extract URLs, construct traversal payloads, and send requests in parallel.
    * Potential vulnerabilities will be reported in Burp Suite's logging and alerts.

## Dependencies

* Burp Suite with Montoya API support.

## Important Notes

* **Ethical Use:** This extension is intended for ethical security testing purposes only. Use it responsibly and only on systems you have explicit permission to test.
* **Payload Customization:** Adjust the `payloads` array in the code as needed for specific target environments.
* **Burp Suite Configuration:** Ensure Burp Suite's proxy and other settings are configured correctly to intercept and process HTTP traffic.
* **Montoya API:** Requires Burp Suite with Montoya API support.

## Contributing

Contributions and improvements are welcome. If you find any bugs or have suggestions for new features, please feel free to submit a pull request or open an issue.

## License

This extension is provided as-is. Please use it responsibly and ethically. No warranties are provided.
