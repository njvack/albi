#if os(macOS)
    import Diagnostics
    import Foundation
    import Security
    import Testing
    @testable import GPCore
    @testable import GPMac

    @Suite struct CodeIdentityTests {
        @Test func teamRequirementPinsTeamAndIdentifiers() {
            let r = CodeIdentity.requirement(
                team: "ABCDE12345", identifiers: ["com.x.helper", "com.x.helper.daemon"], adHoc: [])
            #expect(
                r
                    == "anchor apple generic and certificate leaf[subject.OU] = \"ABCDE12345\" and (identifier \"com.x.helper\" or identifier \"com.x.helper.daemon\")"
            )
        }

        @Test func adHocRequirementPinsHashes() {
            let a = CodeIdentity(identifier: "a", teamID: nil, cdhash: "00ff")
            let b = CodeIdentity(identifier: "b", teamID: nil, cdhash: "abcd")
            #expect(
                CodeIdentity.requirement(team: nil, identifiers: [], adHoc: [a, b])
                    == "cdhash H\"00ff\" or cdhash H\"abcd\"")
            #expect(CodeIdentity.requirement(team: nil, identifiers: [], adHoc: []) == nil)
        }

        @Test func refusesUnsafeStrings() {
            #expect(CodeIdentity.requirement(team: "T\" or true", identifiers: ["x"], adHoc: []) == nil)
            #expect(CodeIdentity.requirement(team: "T", identifiers: ["x\") or (true"], adHoc: []) == nil)
        }

        @Test func requirementsCompile() throws {
            for r in [
                CodeIdentity.requirement(team: "ABCDE12345", identifiers: ["com.x.helper"], adHoc: []),
                CodeIdentity.requirement(
                    team: nil, identifiers: [],
                    adHoc: [CodeIdentity(identifier: "a", teamID: nil, cdhash: String(repeating: "ab", count: 20))]),
            ] {
                var req: SecRequirement?
                #expect(SecRequirementCreateWithString(try #require(r) as CFString, [], &req) == errSecSuccess)
            }
        }
    }

    @Suite struct HelperProtocolTests {
        /// albi-helper and the extension both follow TunnelController's events
        /// through `HelperStatus.apply`.
        @Test func statusFollowsControllerEvents() {
            // #expect can't call a mutating method, so record each result first.
            var s = HelperStatus()
            var changed = s.apply(.authenticating)
            #expect(changed && s.state == .authenticating)
            changed = s.apply(.needsSecondFactor(prompt: "Code?"))
            #expect(changed && s.state == .needsSecondFactor(prompt: "Code?"))
            changed = s.apply(.state(.connecting(.hip)))
            #expect(changed && s.state == .connecting(phase: "hip"))
            changed = s.apply(.state(.reauthenticating))
            #expect(changed && s.state == .authenticating)
            changed = s.apply(.state(.stopped(reason: "x")))
            #expect(!changed)
            changed = s.apply(.log("hello"))
            #expect(!changed && s.state == .authenticating)
        }

        @Test func providerStatusCarriesTheTunnelStatus() throws {
            var status = ProviderMessage.Status(state: "connected")
            status.tunnel = HelperStatus(state: .connected, routes: ["10.0.0.0/8"])
            let back = try JSONDecoder().decode(ProviderMessage.Status.self, from: JSONEncoder().encode(status))
            #expect(back.tunnel == status.tunnel)
            let req = try JSONDecoder().decode(
                ProviderMessage.Request.self,
                from: JSONEncoder().encode(ProviderMessage.Request(secondFactorCode: "123456")))
            #expect(req.secondFactorCode == "123456")
        }

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
            let s = HelperStatus(
                profileID: UUID(), state: .reconnecting(attempt: 2, reason: "dpd"), gateway: "gw",
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
            let s: String =
                switch e {
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
            let c = ControllerCredentials(
                username: "nate", password: "pw", secondFactor: "1", ask: nil, onEvent: log.add)
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
            let c = ControllerCredentials(
                username: "nate", password: "pw", secondFactor: nil,
                ask: { prompt in prompt == "Code?" ? "424242" : "" }, onEvent: log.add)
            #expect(try await c.answer(.challenge(message: "Code?")) == "424242")
            #expect(log.all == ["code:Code?", "auth"])
        }

        @Test func noWayToAskNeedsTheUser() async {
            let c = ControllerCredentials(
                username: "nate", password: "pw", secondFactor: nil, ask: nil, onEvent: { _ in })
            await #expect(throws: StoredCredentials.NeedsUser.self) {
                try await c.answer(.challenge(message: "Code?"))
            }
        }
    }
#endif
