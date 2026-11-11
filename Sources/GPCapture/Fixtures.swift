import Foundation

/// Writes a capture as test fixtures: one request and one response file per
/// exchange, an index, the rest of openconnect's log and a summary, all
/// redacted.
public struct FixtureSet {
    public struct File: Equatable {
        public var name: String
        public var contents: String
    }

    public var files: [File] = []
    public var redactor: Redactor

    public init(log: CaptureLog, redactor: Redactor) {
        var r = redactor
        r.learn(log)
        var files: [File] = []
        var index = ["# n\tmethod\ttarget\tstatus\tlabel"]
        var logLines: [String] = []
        var eventIdx = 0
        func flushEvents(through exchange: Int?) {
            while eventIdx < log.events.count, log.events[eventIdx].after == exchange {
                let e = log.events[eventIdx]
                logLines.append((e.time.map { "[\($0)] " } ?? "") + r.redact(e.text))
                eventIdx += 1
            }
        }
        flushEvents(through: nil)
        for (i, x) in log.exchanges.enumerated() {
            let n = String(format: "%02d", i + 1)
            let base = "\(n)-\(x.label)"
            let target = r.redactTarget(x.target)
            index.append("\(n)\t\(x.method)\t\(target)\t\(x.status.map(String.init) ?? "-")\t\(x.label)")
            if !x.requestBody.isEmpty {
                let isForm = x.requestHeaders.contains { $0.name.lowercased() == "content-type" && $0.value.contains("form") }
                let body = isForm ? r.redactForm(x.requestBody) : r.redact(x.requestBody)
                files.append(File(name: base + (isForm ? ".request.form" : ".request.txt"), contents: body + "\n"))
            }
            if let body = x.responseBody {
                let ext = body.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("<") ? "xml" : "txt"
                files.append(File(name: base + ".response.\(ext)", contents: r.redact(body) + "\n"))
            }
            logLines.append((x.time.map { "[\($0)] " } ?? "") + "--- exchange \(n): \(x.method) \(target) -> \(x.statusLine ?? "no response logged")")
            flushEvents(through: i)
        }
        files.append(File(name: "index.tsv", contents: index.joined(separator: "\n") + "\n"))
        files.append(File(name: "openconnect.log", contents: logLines.joined(separator: "\n") + "\n"))
        files.append(File(name: "summary.txt", contents: r.redact(Summary(log).text)))
        self.files = files
        self.redactor = r
    }

    /// Learned values that survived redaction, by file.
    public var leaks: [(file: String, what: [String])] {
        files.compactMap { f in
            let l = redactor.leaks(in: f.contents)
            return l.isEmpty ? nil : (f.name, l)
        }
    }

    public func write(to dir: URL) throws {
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        for f in files {
            try f.contents.write(to: dir.appendingPathComponent(f.name), atomically: true, encoding: .utf8)
        }
    }
}
