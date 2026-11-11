// albi-diag: reads incident files written by diagnostics mode.
//
//   albi-diag summary FILE           the header and a short timeline
//   albi-diag check FILE [--scrub W] look for anything the redaction missed
//   albi-diag replay FILE            replay the session events into Session
//   albi-diag scenario FILE          draft a gp-fake-gateway scenario

import Foundation
import Diagnostics
import GPCore

let usage = """
usage: albi-diag summary FILE
       albi-diag check FILE [--scrub WORD]...
       albi-diag replay FILE
       albi-diag scenario FILE [--name NAME]
"""

func fail(_ s: String) -> Never {
    FileHandle.standardError.write(Data((s + "\n").utf8))
    exit(1)
}

var args = Array(CommandLine.arguments.dropFirst())
guard args.count >= 2 else { fail(usage) }
let command = args.removeFirst()
let path = args.removeFirst()
let data: Data
do { data = try Data(contentsOf: URL(fileURLWithPath: path)) } catch { fail("\(path): \(error)") }
let file: IncidentFile
do { file = try IncidentFile(data: data) } catch { fail("\(path): \(error)") }

switch command {
case "summary":
    let h = file.header
    print("incident \(h["id"] ?? "?") written \(h["written"] ?? "?")")
    print("reason:  \(h["reason"] ?? "?")")
    if let o = h["outcome"] { print("outcome: \(o)") }
    for (k, v) in file.info.sorted(by: { $0.key < $1.key }) where !k.hasPrefix("policy.") { print("\(k): \(v)") }
    if let r = h["redaction"] as? [String: Any] {
        print("redaction: \(r["learned"] ?? 0) values learned, \(r["withheld"] ?? 0) withheld")
    }
    print("")
    for e in file.events {
        let t = String(format: "%9.3f", e["t"] as? Double ?? 0)
        let pin = e["pinned"] as? Bool == true ? "pinned " : ""
        switch e["kind"] as? String {
        case "state": print("\(t) \(pin)state \(e["state"] ?? "")")
        case "event":
            var s = "\(t) \(pin)event \(e["event"] ?? "")"
            if let f = e["failure"] as? [String: Any], let m = f.values.first { s += ": \(m)" }
            print(s)
        case "http":
            let st = e["status"].map { "\($0)" } ?? (e["error"] as? String ?? "?")
            print("\(t) \(pin)http \(IncidentFile.requestKind(e["path"] as? String ?? "")) → \(st) (\(e["duration"] ?? 0) s)")
        case "incident": print("\(t) incident \(e["message"] ?? "")")
        default: break
        }
    }

case "check":
    var words: [String] = []
    var it = args.makeIterator()
    while let a = it.next() {
        guard a == "--scrub", let w = it.next() else { fail(usage) }
        words.append(w.lowercased())
    }
    let text = String(decoding: data, as: UTF8.self)
    var problems: [String] = []
    let lower = text.lowercased()
    for w in words where lower.contains(w) { problems.append("contains \"\(w)\"") }
    // Addresses the redactor would have moved: anything public outside the
    // documentation and benchmark ranges it maps to.
    let ipv4 = try! NSRegularExpression(pattern: #"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])"#)
    for m in ipv4.matches(in: text, range: NSRange(text.startIndex..., in: text)) {
        let o = (1...4).map { Int((text as NSString).substring(with: m.range(at: $0))) ?? 0 }
        guard o.allSatisfy({ $0 <= 255 }) else { continue }
        let ok = o[0] == 10 || o[0] == 127 || o[0] == 0 || o[0] == 255 || o[0] >= 224
            || (o[0] == 172 && (16...31).contains(o[1])) || (o[0] == 192 && o[1] == 168)
            || (o[0] == 198 && (18...19).contains(o[1])) || (o[0] == 192 && o[1] == 0 && o[2] == 2)
            || (o[0] == 169 && o[1] == 254) || o[1...].allSatisfy({ $0 == 255 || $0 == 0 })
        if !ok { problems.append("public IPv4 address \(o.map(String.init).joined(separator: "."))") }
    }
    let email = try! NSRegularExpression(pattern: #"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,}"#)
    for m in email.matches(in: text, range: NSRange(text.startIndex..., in: text)) {
        let s = (text as NSString).substring(with: m.range)
        if !s.lowercased().contains("example") { problems.append("e-mail address \(s)") }
    }
    if let r = file.header["redaction"] as? [String: Any], let w = r["withheld"] as? Int, w > 0 {
        print("note: the leak check withheld \(w) values when the file was written")
    }
    if problems.isEmpty {
        print("no problems found; still read the file before sharing it")
    } else {
        for p in Array(Set(problems)).sorted() { print("problem: \(p)") }
        exit(2)
    }

case "replay":
    let r = file.replay()
    for n in r.notes { print("note: \(n)") }
    print("final state: \(r.finalState)")
    print("recorded actions in the window: \(r.recorded.count), replayed: \(r.replayed.count)")
    if let d = r.divergence {
        print("first difference at action \(d): recorded \(d < r.recorded.count ? r.recorded[d] : "(end)"), replayed \(d < r.replayed.count ? r.replayed[d] : "(end)")")
        exit(1)
    }
    print("replay matches the recording")

case "scenario":
    var name: String?
    if args.first == "--name", args.count >= 2 { name = args[1] }
    print(ScenarioDraft.json(ScenarioDraft.make(from: file, name: name)), terminator: "")

default:
    fail(usage)
}
