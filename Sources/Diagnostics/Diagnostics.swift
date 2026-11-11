import Foundation
import GPCore

/// Diagnostics mode for one session: owns the flight recorder, runs its
/// timer, and writes a redacted incident file when the recorder says to.
/// Give `recorder` to `SessionRunner` and wrap the connector with
/// `RecordingConnector` before logging in.
public final class Diagnostics: @unchecked Sendable {
    public let recorder: FlightRecorder
    public let directory: URL
    public let settings: DiagnosticsSettings
    private let clock: any SessionClock
    private let lock = NSLock()
    private var secrets: KnownSecrets
    private var incidents: [Int: (url: URL, incident: DumpWriter.Incident)] = [:]
    private var lastWrite: Date?
    private var _lastIncident: URL?
    private var timer: Task<Void, Never>?
    private let onWrite: @Sendable (URL, String) -> Void
    /// At most one new incident file this often.
    public var minimumInterval: TimeInterval = 600

    /// `onWrite` gets each file written and a one-line description, for a
    /// log line or a notification.
    /// `policy` overrides the one `settings` gives, for tests.
    public init(settings: DiagnosticsSettings, directory: URL, clock: any SessionClock,
                secrets: KnownSecrets = KnownSecrets(), policy: FlightRecorder.Policy? = nil,
                onWrite: @escaping @Sendable (URL, String) -> Void = { _, _ in }) {
        self.settings = settings
        self.directory = directory
        self.clock = clock
        self.secrets = secrets
        self.onWrite = onWrite
        let box = WeakBox()
        recorder = FlightRecorder(policy: policy ?? settings.recorderPolicy) { signal in box.target?.handle(signal) }
        box.target = self
        recorder.setInfo("transport", "https")
    }

    deinit { timer?.cancel() }

    /// Starts the poll timer that runs the recorder's time-based rules.
    public func start(every interval: Duration = .seconds(5)) {
        timer = Task { [weak self, clock] in
            while !Task.isCancelled {
                try? await Task.sleep(for: interval)
                guard let self else { return }
                self.recorder.poll(now: clock.now())
            }
        }
    }

    public func stop() {
        timer?.cancel()
        timer = nil
    }

    public func updateSecrets(_ f: (inout KnownSecrets) -> Void) {
        lock.withLock { f(&secrets) }
    }

    /// The newest incident file written this session.
    public var lastIncident: URL? { lock.withLock { _lastIncident } }

    /// "Save diagnostics now": writes the current window even if nothing
    /// looks wrong. Ignores the rate limit.
    @discardableResult
    public func saveNow(reason: String = "saved by the user") -> URL? {
        lock.withLock { lastWrite = nil }
        let id = recorder.requestDump(reason: reason, now: clock.now())
        return lock.withLock { incidents[id]?.url }
    }

    // MARK: Signals

    private func handle(_ signal: FlightRecorder.Signal) {
        switch signal {
        case .dump(let id, let reason):
            let now = Date()
            let limited = lock.withLock { lastWrite.map { now.timeIntervalSince($0) < minimumInterval } ?? false }
            if limited { return }
            let snap = recorder.snapshot(now: clock.now())
            let incident = DumpWriter.Incident(id: id, reason: reason, written: now, snapshot: snap,
                                               recorderPolicy: recorder.policy)
            let url = directory.appendingPathComponent(Self.fileName(now, id: id))
            lock.withLock {
                lastWrite = now
                incidents[id] = (url, incident)
            }
            if write(incident, to: url, note: "incident: \(reason)") {
                lock.withLock { _lastIncident = url }
            }
            prune()
        case .closed(let id, let outcome):
            guard let open = lock.withLock({ incidents.removeValue(forKey: id) }) else { return }
            let url = open.url
            var incident = open.incident
            let last = incident.snapshot.entries.last?.seq ?? incident.snapshot.pinned.last?.seq ?? 0
            incident.aftermath = recorder.entries(after: last)
            incident.outcome = outcome
            write(incident, to: url, note: "incident closed: \(outcome)")
        }
    }

    @discardableResult
    private func write(_ incident: DumpWriter.Incident, to url: URL, note: String) -> Bool {
        let s = lock.withLock { secrets }
        let r = DumpWriter.write(incident, secrets: s)
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o755])
            try Data(r.text.utf8).write(to: url, options: .atomic)
            try? FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: url.path)
            var line = "\(note) → \(url.path)"
            if r.withheld > 0 { line += " (\(r.withheld) values withheld by the leak check)" }
            onWrite(url, line)
            return true
        } catch {
            onWrite(url, "could not write \(url.path): \(error)")
            return false
        }
    }

    private func prune() {
        let fm = FileManager.default
        guard let names = try? fm.contentsOfDirectory(atPath: directory.path) else { return }
        let dumps = names.filter { $0.hasPrefix("albi-incident-") && $0.hasSuffix(".json") }.sorted()
        for n in dumps.dropLast(max(1, settings.keep)) {
            try? fm.removeItem(at: directory.appendingPathComponent(n))
        }
    }

    static func fileName(_ d: Date, id: Int) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyyMMdd-HHmmss"
        return "albi-incident-\(f.string(from: d))Z-\(id).json"
    }

    private final class WeakBox: @unchecked Sendable {
        weak var target: Diagnostics?
    }
}
