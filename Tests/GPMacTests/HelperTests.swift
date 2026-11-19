#if os(macOS)
import Diagnostics
import Foundation
import Testing
@testable import GPCore
@testable import GPMac

@Suite struct HelperProtocolTests {
    @Test func requestsRoundTrip() throws {
        let id = UUID()
        var p = Profile(server: "vpn.example.edu", username: "nate")
        p.secondFactor = nil
        let reqs: [HelperRequest] = [
            .hello, .connect(id, password: "pw"), .connect(id, password: nil),
            .saveProfile(StoredProfile(id: id, name: "Work", profile: p)), .answerSecondFactor("123456"),
            .setDiagnosticsSettings(DiagnosticsSettings(enabled: true, windowMinutes: 5)),
        ]
        for r in reqs {
            let back = try HelperCoding.decode(HelperRequest.self, HelperCoding.encode(r))
            #expect(HelperCoding.encode(back) == HelperCoding.encode(r))
        }
    }

    @Test func statusRoundTrips() throws {
        let s = HelperStatus(profileID: UUID(), state: .reconnecting(attempt: 2, reason: "dpd"), gateway: "gw",
                             connectedSince: Date(timeIntervalSince1970: 1_700_000_000), routes: ["10.0.0.0/8"])
        #expect(try HelperCoding.decode(HelperStatus.self, HelperCoding.encode(s)) == s)
    }

    @Test func buildIDChangesWithTheFile() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("albi-build-\(UUID())")
        try Data("a".utf8).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let a = try #require(HelperBuild.id(ofExecutableAt: url.path))
        try Data("ab".utf8).write(to: url)
        #expect(HelperBuild.id(ofExecutableAt: url.path) != a)
        #expect(HelperBuild.id(ofExecutableAt: "/nonexistent/albi") == nil)
    }
}

final class EventLog: @unchecked Sendable {
    private let lock = NSLock()
    private var events: [String] = []
    func add(_ e: TunnelController.Event) {
        let s: String = switch e {
        case .authenticating: "auth"
        case .waitingForPush: "push"
        case .needsSecondFactor(let p): "code:\(p)"
        case .state(let s): "state:\(s)"
        case .log: "log"
        }
        lock.withLock { events.append(s) }
    }
    var all: [String] { lock.withLock { events } }
}

@Suite struct ControllerCredentialsTests {
    @Test func fixedAnswerReportsAPush() async throws {
        let log = EventLog()
        let c = ControllerCredentials(username: "nate", password: "pw", secondFactor: "1", ask: nil, onEvent: log.add)
        #expect(try await c.answer(.username(label: "", message: nil)) == "nate")
        #expect(try await c.answer(.password(label: "", message: nil, server: "s", retry: false)) == "pw")
        #expect(try await c.answer(.challenge(message: "push?")) == "1")
        #expect(log.all == ["push"])
        await #expect(throws: GPError.self) {
            try await c.answer(.password(label: "", message: nil, server: "s", retry: true))
        }
    }

    @Test func asksTheUserForACode() async throws {
        let log = EventLog()
        let c = ControllerCredentials(username: "nate", password: "pw", secondFactor: nil,
                                      ask: { prompt in prompt == "Code?" ? "424242" : "" }, onEvent: log.add)
        #expect(try await c.answer(.challenge(message: "Code?")) == "424242")
        #expect(log.all == ["code:Code?", "auth"])
    }

    @Test func noWayToAskNeedsTheUser() async {
        let c = ControllerCredentials(username: "nate", password: "pw", secondFactor: nil, ask: nil, onEvent: { _ in })
        await #expect(throws: StoredCredentials.NeedsUser.self) {
            try await c.answer(.challenge(message: "Code?"))
        }
    }
}
#endif
