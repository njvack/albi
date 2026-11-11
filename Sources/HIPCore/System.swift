import Foundation

/// The only PATH commands ever see.
public let safePath = "/usr/bin:/bin:/usr/sbin:/sbin"

/// What a command left behind.
public struct RunResult: Sendable, Equatable {
    public var stdout: String
    /// The exit status, or nil if the command could not start or timed out.
    public var exitCode: Int32?

    public init(stdout: String, exitCode: Int32?) {
        self.stdout = stdout
        self.exitCode = exitCode
    }

    public var succeeded: Bool { exitCode == 0 }
}

/// What lstat or stat said about a path.
public struct FileStat: Sendable, Equatable {
    public var isDirectory: Bool
    public var isSymlink: Bool
    /// Permission bits only (0o777).
    public var permissions: UInt32
    public var uid: UInt32
    public var gid: UInt32
    public var modified: Date

    public init(isDirectory: Bool, isSymlink: Bool, permissions: UInt32, uid: UInt32, gid: UInt32, modified: Date) {
        self.isDirectory = isDirectory
        self.isSymlink = isSymlink
        self.permissions = permissions
        self.uid = uid
        self.gid = gid
        self.modified = modified
    }
}

/// The boundary between hipreport and the machine it runs on. Every probe
/// reads the system through one, so tests can substitute recorded output for
/// real commands and files.
public protocol System: AnyObject {
    /// Runs argv[0] (an absolute path) with a fixed environment, no stdin
    /// and stderr discarded.
    func run(_ argv: [String], timeout: TimeInterval) -> RunResult
    func readFile(_ path: String) -> Data?
    /// Follows symlinks.
    func stat(_ path: String) -> FileStat?
    /// Does not follow a final symlink.
    func lstat(_ path: String) -> FileStat?
    func readlink(_ path: String) -> String?
    func hostname() -> String
    func uid() -> UInt32
    func now() -> Date
    /// The zone report times are written in.
    func timeZone() -> TimeZone
}

public let defaultTimeout: TimeInterval = 10
