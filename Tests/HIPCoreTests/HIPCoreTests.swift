import Testing
@testable import HIPCore

@Test func versionIsSet() {
    #expect(!HIPCore.version.isEmpty)
}
