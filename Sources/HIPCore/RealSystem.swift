import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// The System for the machine we are running on.
public final class RealSystem: System {
    public init() {}

    public func run(_ argv: [String], timeout: TimeInterval) -> RunResult {
        guard let exe = argv.first, exe.hasPrefix("/") else {
            return RunResult(stdout: "", exitCode: nil)
        }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: exe)
        p.arguments = Array(argv.dropFirst())
        p.environment = ["PATH": safePath, "LC_ALL": "C", "HOME": "/var/empty"]
        p.standardInput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        let pipe = Pipe()
        p.standardOutput = pipe

        let done = DispatchSemaphore(value: 0)
        p.terminationHandler = { _ in done.signal() }
        do {
            try p.run()
        } catch {
            return RunResult(stdout: "", exitCode: nil)
        }
        // Drain stdout while the command runs so a full pipe can't stall it.
        let reader = OutputReader(pipe.fileHandleForReading)
        let limit = timeout > 0 ? timeout : defaultTimeout
        var timedOut = false
        if done.wait(timeout: .now() + limit) == .timedOut {
            timedOut = true
            p.terminate()
            if done.wait(timeout: .now() + 1) == .timedOut {
                kill(p.processIdentifier, SIGKILL)
                _ = done.wait(timeout: .now() + 1)
            }
        }
        let out = reader.finish()
        return RunResult(stdout: String(decoding: out, as: UTF8.self),
                         exitCode: timedOut ? nil : p.terminationStatus)
    }

    public func readFile(_ path: String) -> Data? {
        FileManager.default.contents(atPath: path)
    }

    public func writeFile(_ path: String, _ data: Data) -> Bool {
        let u = URL(fileURLWithPath: path)
        do {
            try FileManager.default.createDirectory(at: u.deletingLastPathComponent(), withIntermediateDirectories: true)
            try data.write(to: u, options: .atomic)
            return true
        } catch {
            return false
        }
    }

    /// /Library/Caches/Albi for root, so the root helper's cache can't be
    /// written by users; otherwise the user's own.
    public func cacheDirectory() -> String {
        if getuid() == 0 { return "/Library/Caches/Albi" }
        let base = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first?.path
        return (base ?? NSTemporaryDirectory()) + "/Albi"
    }

    /// URLSession, on macOS only: on Linux hipreport only runs from
    /// fixtures, and this keeps FoundationNetworking out of the static build.
    public func fetch(_ url: String, timeout: TimeInterval) -> Data? {
        #if os(macOS)
        guard let u = URL(string: url) else { return nil }
        var req = URLRequest(url: u, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: timeout)
        // SOFA asks custom tools to identify themselves.
        req.setValue("Albi-hipreport (+https://github.com/njvack/albi)", forHTTPHeaderField: "User-Agent")
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForResource = timeout
        let session = URLSession(configuration: cfg)
        defer { session.invalidateAndCancel() }
        let box = FetchBox()
        session.dataTask(with: req) { d, resp, _ in
            if (resp as? HTTPURLResponse)?.statusCode == 200 { box.data = d }
            box.done.signal()
        }.resume()
        _ = box.done.wait(timeout: .now() + timeout + 1)
        return box.data
        #else
        return nil
        #endif
    }

    public func stat(_ path: String) -> FileStat? { statPath(path, follow: true) }
    public func lstat(_ path: String) -> FileStat? { statPath(path, follow: false) }

    private func statPath(_ path: String, follow: Bool) -> FileStat? {
        var st = posixStat()
        let rc = follow ? cStat(path, &st) : cLstat(path, &st)
        #if canImport(Darwin)
        let mtime = Double(st.st_mtimespec.tv_sec) + Double(st.st_mtimespec.tv_nsec) / 1e9
        #else
        let mtime = Double(st.st_mtim.tv_sec) + Double(st.st_mtim.tv_nsec) / 1e9
        #endif
        guard rc == 0 else { return nil }
        let type = UInt32(st.st_mode) & UInt32(S_IFMT)
        return FileStat(
            isDirectory: type == UInt32(S_IFDIR),
            isSymlink: type == UInt32(S_IFLNK),
            permissions: UInt32(st.st_mode) & 0o777,
            uid: UInt32(st.st_uid), gid: UInt32(st.st_gid),
            modified: Date(timeIntervalSince1970: mtime))
    }

    public func readlink(_ path: String) -> String? {
        try? FileManager.default.destinationOfSymbolicLink(atPath: path)
    }

    // gethostname(3), as the zsh and Go reporters use; ProcessInfo.hostName
    // resolves and lowercases the name.
    public func hostname() -> String {
        var buf = [CChar](repeating: 0, count: 256)
        guard gethostname(&buf, buf.count) == 0 else { return "" }
        return cString(buf)
    }
    public func uid() -> UInt32 { UInt32(getuid()) }
    public func now() -> Date { Date() }
    public func timeZone() -> TimeZone { .current }
}

typealias posixStat = stat

private func cStat(_ p: String, _ st: inout posixStat) -> Int32 { stat(p, &st) }
private func cLstat(_ p: String, _ st: inout posixStat) -> Int32 { lstat(p, &st) }

/// The result of a fetch, handed back from URLSession's queue. The
/// semaphore orders the write before the read.
private final class FetchBox: @unchecked Sendable {
    var data: Data?
    let done = DispatchSemaphore(value: 0)
}

/// Reads a pipe to EOF on a background queue.
private final class OutputReader: @unchecked Sendable {
    private var data = Data()
    private let group = DispatchGroup()

    init(_ handle: FileHandle) {
        group.enter()
        DispatchQueue.global().async {
            self.data = handle.readDataToEndOfFile()
            self.group.leave()
        }
    }

    func finish() -> Data {
        // A grandchild holding the pipe open must not hang us forever.
        _ = group.wait(timeout: .now() + 2)
        return data
    }
}
