import Foundation
#if os(macOS)
import Darwin
import SystemConfiguration
#endif

/// One mounted volume, as FileManager describes it.
public struct Volume: Sendable, Equatable {
    public var mountPoint: String
    public var name: String
    public var local: Bool
    public var browsable: Bool
    /// nil when the system doesn't say.
    public var isInternal: Bool?
    /// FileVault, or other volume encryption. nil when the system doesn't say.
    public var encrypted: Bool?

    public init(mountPoint: String, name: String, local: Bool = true, browsable: Bool = true,
                isInternal: Bool? = nil, encrypted: Bool? = nil) {
        self.mountPoint = mountPoint
        self.name = name
        self.local = local
        self.browsable = browsable
        self.isInternal = isInternal
        self.encrypted = encrypted
    }
}

// MARK: - Native implementations

// These use public frameworks instead of shelling out. On Linux, where
// hipreport only runs from fixtures, they report nothing.
extension RealSystem {
    /// ProcessInfo; formatted like `sw_vers -productVersion` (no ".0" patch).
    public func osVersion() -> String {
        #if os(macOS)
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return v.patchVersion == 0 ? "\(v.majorVersion).\(v.minorVersion)"
            : "\(v.majorVersion).\(v.minorVersion).\(v.patchVersion)"
        #else
        return ""
        #endif
    }

    /// libproc: proc_listallpids and proc_pidpath.
    public func processPaths() -> [String] {
        #if os(macOS)
        let n = proc_listallpids(nil, 0)
        guard n > 0 else { return [] }
        var pids = [pid_t](repeating: 0, count: Int(n) + 64)
        let got = pids.withUnsafeMutableBytes { proc_listallpids($0.baseAddress, Int32($0.count)) }
        guard got > 0 else { return [] }
        var buf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))  // PROC_PIDPATHINFO_MAXSIZE
        var out: [String] = []
        for pid in pids.prefix(Int(got)) where pid > 0 {
            if proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 {
                out.append(String(cString: buf))
            }
        }
        return out
        #else
        return []
        #endif
    }

    /// getfsstat(2) for the mount table, as mount(8) prints it, then each
    /// mount point's volume resource values from Foundation.
    /// FileManager.mountedVolumeURLs would be simpler, but it leaves out
    /// hidden volumes such as /System/Volumes/Data, where FileVault matters.
    public func mountedVolumes() -> [Volume]? {
        #if os(macOS)
        let n = getfsstat(nil, 0, MNT_NOWAIT)
        guard n > 0 else { return nil }
        var buf = [statfs](repeating: .init(), count: Int(n) + 8)
        let got = buf.withUnsafeMutableBufferPointer {
            getfsstat($0.baseAddress, Int32($0.count * MemoryLayout<statfs>.stride), MNT_NOWAIT)
        }
        guard got > 0 else { return nil }
        let keys: Set<URLResourceKey> = [.volumeNameKey, .volumeIsInternalKey, .volumeIsEncryptedKey]
        return buf.prefix(Int(got)).map { fs in
            var fs = fs
            let mp = withUnsafeBytes(of: &fs.f_mntonname) { String(cString: $0.bindMemory(to: CChar.self).baseAddress!) }
            let flags = UInt32(fs.f_flags)
            let local = flags & UInt32(MNT_LOCAL) != 0
            let v = local ? try? URL(fileURLWithPath: mp, isDirectory: true).resourceValues(forKeys: keys) : nil
            return Volume(mountPoint: mp, name: v?.volumeName ?? "", local: local,
                          browsable: flags & UInt32(MNT_DONTBROWSE) == 0, isInternal: v?.volumeIsInternal,
                          encrypted: v?.volumeIsEncrypted)
        }
        #else
        return nil
        #endif
    }

    /// SystemConfiguration for the hardware ports and their burned-in MACs,
    /// getifaddrs for addresses.
    public func networkInterfaces() -> [Interface] {
        #if os(macOS)
        guard let all = SCNetworkInterfaceCopyAll() as? [SCNetworkInterface] else { return [] }
        let addrs = interfaceAddresses()
        return all.compactMap { i in
            guard let dev = SCNetworkInterfaceGetBSDName(i) as String?, !dev.isEmpty else { return nil }
            var mac = SCNetworkInterfaceGetHardwareAddressString(i) as String? ?? ""
            if mac.filter({ $0 == ":" }).count < 2 { mac = addrs[dev]?.link ?? "" }  // e.g. bridge0
            return Interface(device: dev, mac: mac, ipv4: addrs[dev]?.ipv4 ?? [], ipv6: addrs[dev]?.ipv6 ?? [])
        }
        #else
        return []
        #endif
    }
}

#if os(macOS)
private struct Addresses {
    var link = ""
    var ipv4: [String] = []
    var ipv6: [String] = []
}

/// Per-device addresses from getifaddrs, in kernel order (as ifconfig
/// prints them). IPv6 scope suffixes (%en0) are dropped.
private func interfaceAddresses() -> [String: Addresses] {
    var head: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&head) == 0, let first = head else { return [:] }
    defer { freeifaddrs(head) }
    var out: [String: Addresses] = [:]
    var cur: UnsafeMutablePointer<ifaddrs>? = first
    while let p = cur {
        defer { cur = p.pointee.ifa_next }
        guard let sa = p.pointee.ifa_addr else { continue }
        let dev = String(cString: p.pointee.ifa_name)
        switch Int32(sa.pointee.sa_family) {
        case AF_LINK:
            let raw = UnsafeRawPointer(sa)
            let dl = raw.load(as: sockaddr_dl.self)
            guard dl.sdl_alen == 6, let off = MemoryLayout<sockaddr_dl>.offset(of: \.sdl_data) else { continue }
            let bytes = raw + off + Int(dl.sdl_nlen)
            out[dev, default: Addresses()].link = (0..<6)
                .map { String(format: "%02x", bytes.load(fromByteOffset: $0, as: UInt8.self)) }
                .joined(separator: ":")
        case AF_INET, AF_INET6:
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let len = socklen_t(sa.pointee.sa_family == UInt8(AF_INET) ? MemoryLayout<sockaddr_in>.size
                                : MemoryLayout<sockaddr_in6>.size)
            guard getnameinfo(sa, len, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else { continue }
            let s = String(String(cString: host).split(separator: "%", maxSplits: 1).first ?? "")
            if sa.pointee.sa_family == UInt8(AF_INET) {
                out[dev, default: Addresses()].ipv4.append(s)
            } else {
                out[dev, default: Addresses()].ipv6.append(s)
            }
        default:
            break
        }
    }
    return out
}
#endif

// MARK: - From recorded commands

// Older fixtures, and the ones shared with the Go reporter, record the
// commands the reporters used to run rather than native results. FakeSystem
// derives native answers from those commands with the parsing below.

func osVersion(fromCommands run: ([String]) -> RunResult) -> String {
    run(["/usr/bin/sw_vers", "-productVersion"]).stdout.trimmingCharacters(in: .whitespacesAndNewlines)
}

func processPaths(fromCommands run: ([String]) -> RunResult) -> [String] {
    run(["/bin/ps", "-axo", "comm="]).stdout
        .split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
}

/// mount(8) plus `diskutil info -plist` per local mount point.
func mountedVolumes(fromCommands run: ([String]) -> RunResult) -> [Volume]? {
    let r = run(["/sbin/mount"])
    if r.stdout.isEmpty { return nil }
    return r.stdout.split(separator: "\n").compactMap { line in
        guard let (mp, flags) = parseMountLine(String(line)) else { return nil }
        let local = flags.contains("local")
        let info = local ? decodePlist(Data(run(["/usr/sbin/diskutil", "info", "-plist", mp]).stdout.utf8)) ?? [:]
            : [:]
        return Volume(mountPoint: mp, name: info["VolumeName"].flatMap(plistString) ?? "", local: local,
                      browsable: !flags.contains("nobrowse"), isInternal: plistBool(info["Internal"]),
                      encrypted: plistBool(info["FileVault"]))
    }
}

/// "DEV on MOUNTPOINT (flag, flag, ...)" as printed by mount(8).
func parseMountLine(_ line: String) -> (String, [String])? {
    guard line.hasSuffix(")"), let open = line.range(of: " (", options: .backwards),
          let on = line.range(of: " on ", range: line.startIndex..<open.lowerBound) else { return nil }
    let mp = String(line[on.upperBound..<open.lowerBound])
    let flags = line[open.upperBound..<line.index(before: line.endIndex)]
        .split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
    return mp.isEmpty ? nil : (mp, flags)
}

/// `networksetup -listallhardwareports`, `-getmacaddress` and ifconfig.
func networkInterfaces(fromCommands run: ([String]) -> RunResult) -> [Interface] {
    run(["/usr/sbin/networksetup", "-listallhardwareports"]).stdout.split(separator: "\n").compactMap { line in
        let l = line.trimmingCharacters(in: .whitespaces)
        guard l.hasPrefix("Device:") else { return nil }
        let dev = l.dropFirst("Device:".count).trimmingCharacters(in: .whitespaces)
        guard !dev.isEmpty else { return nil }
        let ifconfig = run(["/sbin/ifconfig", dev]).stdout.split(separator: "\n")
        func field(_ name: String) -> [String] {
            ifconfig.compactMap { l in
                let f = l.split(whereSeparator: \.isWhitespace)
                guard f.count >= 2, f[0] == name else { return nil }
                return String(f[1].split(separator: "%", maxSplits: 1).first ?? "")
            }
        }
        let words = run(["/usr/sbin/networksetup", "-getmacaddress", dev]).stdout.split(whereSeparator: \.isWhitespace)
        var mac = words.count > 2 ? String(words[2]) : ""
        if mac.filter({ $0 == ":" }).count < 2 { mac = field("ether").first ?? "" }
        return Interface(device: dev, mac: mac, ipv4: field("inet"), ipv6: field("inet6"))
    }
}
