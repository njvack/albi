#if canImport(Network)
import Foundation
import GPCore

/// Runs a hipreport that ships inside the extension's bundle, so the report
/// comes from a binary (and check library) the user can't swap out.
///
/// Whether a sandboxed system extension may exec it at all is one of the
/// things the Step 1 test build settles; `probe()` answers that.
public struct BundledHIP: Sendable {
    public var executable: URL?
    public var timeout: Double

    /// `executable` defaults to `hipreport` in the main bundle's Contents/MacOS.
    public init(executable: URL? = Bundle.main.url(forAuxiliaryExecutable: "hipreport"), timeout: Double = 20) {
        self.executable = executable
        self.timeout = timeout
    }

    public struct Output: Sendable {
        public var status: Int32
        public var stdout: Data
        public var stderr: Data
        public var seconds: Double
    }

    public struct Failure: Error, CustomStringConvertible {
        public var description: String
    }

    /// A report for the gateway's HIP request, or throws so the session retries.
    public func report(for c: HIPContext) async throws -> String {
        let out = try await run(ProviderMessage.HIPRequest(c).wrapperArguments + ["--client-version", c.appVersion])
        guard out.status == 0, !out.stdout.isEmpty else {
            throw Failure(description: "bundled hipreport exited \(out.status): \(Self.head(out.stderr))")
        }
        return String(decoding: out.stdout, as: UTF8.self)
    }

    /// Runs the helper once with a dummy request and says what happened.
    public func probe() async -> ProviderMessage.HIPProbe {
        let uid = getuid()
        guard let executable else { return .init(at: Date(), path: nil, uid: uid) }
        do {
            let out = try await run(["--cookie", "user=probe&computer=probe", "--md5", "probe", "--client-os", "Mac"])
            return .init(at: Date(), path: executable.path, exitStatus: out.status, seconds: out.seconds,
                         stdoutBytes: out.stdout.count, stdoutHead: Self.head(out.stdout), stderrHead: Self.head(out.stderr),
                         uid: uid)
        } catch {
            return .init(at: Date(), path: executable.path, launchError: "\(error)", uid: uid)
        }
    }

    func run(_ args: [String]) async throws -> Output {
        guard let executable else { throw Failure(description: "no hipreport in the extension's bundle") }
        let p = Process()
        p.executableURL = executable
        p.arguments = args
        // A clean environment: nothing from the caller steers the checks.
        p.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        let out = Pipe(), err = Pipe()
        p.standardOutput = out
        p.standardError = err
        p.standardInput = FileHandle.nullDevice
        let start = ContinuousClock.now
        let once = Once()
        let o = DataBox(), e = DataBox()
        return try await withCheckedThrowingContinuation { cont in
            // Read both pipes before waiting, so a large report can't block the child.
            let group = DispatchGroup()
            for (pipe, box) in [(out, o), (err, e)] {
                group.enter()
                DispatchQueue.global().async {
                    box.set(pipe.fileHandleForReading.readDataToEndOfFile())
                    group.leave()
                }
            }
            p.terminationHandler = { proc in
                let status = proc.terminationStatus
                group.notify(queue: .global()) {
                    let d = ContinuousClock.now - start
                    let secs = Double(d.components.seconds) + Double(d.components.attoseconds) / 1e18
                    once.run { cont.resume(returning: Output(status: status, stdout: o.get(), stderr: e.get(), seconds: secs)) }
                }
            }
            do {
                try p.run()
            } catch {
                // The read ends close when the Pipe objects go away.
                once.run { cont.resume(throwing: error) }
                return
            }
            let limit = timeout
            let running = ProcessBox(p)
            DispatchQueue.global().asyncAfter(deadline: .now() + limit) {
                guard running.process.isRunning else { return }
                running.process.terminate()
                once.run { cont.resume(throwing: Failure(description: "bundled hipreport timed out after \(Int(limit)) s")) }
            }
        }
    }

    static func head(_ d: Data, _ n: Int = 2000) -> String {
        String(decoding: d.prefix(n), as: UTF8.self)
    }
}
final class ProcessBox: @unchecked Sendable {
    let process: Process
    init(_ p: Process) { process = p }
}

final class DataBox: @unchecked Sendable {
    private let lock = NSLock()
    private var data = Data()
    func set(_ d: Data) { lock.withLock { data = d } }
    func get() -> Data { lock.withLock { data } }
}
#endif
