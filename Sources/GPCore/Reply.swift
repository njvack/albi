/// Errors from a GlobalProtect portal or gateway.
public enum GPError: Error, Equatable, Sendable {
    /// Wrong username, password or challenge answer (HTTP 512, or an error page).
    case badCredentials(String)
    /// The cookie is no longer valid. Retrying with it will not help.
    case cookieRejected(String)
    /// The server says it is not a portal (or not a gateway).
    case notFound(String)
    /// The server wants a client certificate (HTTP 513).
    case certificateRequired
    /// A GP error message not covered above.
    case server(String)
    /// An unexpected HTTP status.
    case http(Int)
    /// A response we could not make sense of.
    case malformed(String)
    /// The login flow was cancelled by the credential provider.
    case cancelled

    /// Whether retrying the same request later might succeed.
    public var isTransient: Bool {
        switch self {
        case .server, .http, .malformed: true
        default: false
        }
    }
}

/// What a portal or gateway response turned out to be.
public enum Reply: Equatable, Sendable {
    /// An XML document that is not an error or a challenge.
    case document(XMLElement)
    /// A second-factor challenge: show `prompt`, send the answer with `inputStr`.
    case challenge(prompt: String, inputStr: String)

    /// Classifies a response the way openconnect's `gpst_xml_or_error` does.
    /// Throws `GPError` for error responses.
    public static func classify(status: Int, body: String) throws(GPError) -> Reply {
        switch status {
        case 200..<300: break
        case 512: throw .badCredentials("Invalid username or password")
        case 513: throw .certificateRequired
        default: throw .http(status)
        }
        guard let root = XMLElement.parse(body) else {
            return try javascript(body)
        }
        switch root.name {
        case "response" where root.attributes["status"]?.lowercased() == "error":
            throw mapError(root.value("error") ?? root.trimmedText)
        case "prelogin-response":
            if let status = root.value("status"), status != "Success" {
                throw mapError(root.value("msg") ?? status)
            }
            return .document(root)
        case "challenge":
            return .challenge(prompt: root.value("respmsg") ?? "", inputStr: root.value("inputstr") ?? "")
        case "html":
            return try javascript(root.child("body")?.text ?? root.text)
        default:
            return .document(root)
        }
    }

    /// Like `classify`, but a challenge is an error.
    public static func document(status: Int, body: String) throws(GPError) -> XMLElement {
        switch try classify(status: status, body: body) {
        case .document(let d): return d
        case .challenge: throw .malformed("unexpected challenge")
        }
    }

    static func mapError(_ message: String) -> GPError {
        switch message {
        case "GlobalProtect gateway does not exist", "GlobalProtect portal does not exist":
            .notFound(message)
        case "Invalid authentication cookie", "Portal name not found",
             "Allow Automatic Restoration of SSL VPN is disabled":
            .cookieRejected(message)
        case "Valid client certificate is required":
            .certificateRequired
        default:
            .server(message)
        }
    }

    /// Parses the JavaScript form of a challenge or error:
    ///
    ///     var respStatus = "Challenge";
    ///     var respMsg = "Enter the code";
    ///     thisForm.inputStr.value = "abc123";
    static func javascript(_ body: String) throws(GPError) -> Reply {
        func quoted(after marker: String) -> String? {
            guard let r = body.firstRange(of: marker) else { return nil }
            var out = ""
            var escaped = false
            for c in body[r.upperBound...] {
                if escaped {
                    switch c {
                    case "n": out.append("\n")
                    case "t": out.append("\t")
                    default: out.append(c)
                    }
                    escaped = false
                } else if c == "\\" {
                    escaped = true
                } else if c == "\"" {
                    return out
                } else {
                    out.append(c)
                }
            }
            return nil
        }
        guard let status = quoted(after: "var respStatus = \"") else {
            throw .malformed("not XML or a JavaScript challenge")
        }
        let msg = quoted(after: "var respMsg = \"") ?? ""
        if status.hasPrefix("Challenge") {
            guard let input = quoted(after: "thisForm.inputStr.value = \"") else {
                throw .malformed("challenge without inputStr")
            }
            return .challenge(prompt: msg, inputStr: input)
        }
        if status.hasPrefix("Error") {
            throw .badCredentials(msg)
        }
        throw .malformed("unknown respStatus \(status)")
    }
}
