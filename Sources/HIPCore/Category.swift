/// One field a category's products report.
public struct FieldDef: Sendable {
    public var name: String
    public var required = false
    /// Used when an optional field is absent.
    public var defaultValue = ""
    /// Takes a list of drives (the volumes probe), not a string.
    public var drives = false
    /// A Unix time, reported as datemon/dateday/dateyear.
    public var epoch = false
}

/// One HIP report category. The report lists categories in this order.
public struct CategoryDef: Sendable {
    public var name: String
    public var fields: [FieldDef]

    public func field(_ name: String) -> FieldDef? { fields.first { $0.name == name } }
}

/// The pseudo-category for GP's custom plist checks, which sit outside
/// <categories> in the report.
public let customPlist = "custom-plist"

public let categories: [CategoryDef] = [
    CategoryDef(name: "anti-malware", fields: [
        FieldDef(name: "version", required: true),
        FieldDef(name: "defver"),
        FieldDef(name: "engver"),
        FieldDef(name: "updated", epoch: true),
        FieldDef(name: "real-time-protection", required: true),
        FieldDef(name: "last-full-scan-time", defaultValue: "n/a"),
    ]),
    CategoryDef(name: "disk-backup", fields: [
        FieldDef(name: "version", required: true),
        FieldDef(name: "last-backup-time", defaultValue: "n/a"),
    ]),
    CategoryDef(name: "disk-encryption", fields: [
        FieldDef(name: "version", required: true),
        FieldDef(name: "drives", required: true, drives: true),
    ]),
    CategoryDef(name: "firewall", fields: [
        FieldDef(name: "version", required: true),
        FieldDef(name: "is-enabled", required: true),
    ]),
    CategoryDef(name: "patch-management", fields: [
        FieldDef(name: "version", required: true),
        FieldDef(name: "is-enabled", required: true),
    ]),
    CategoryDef(name: "data-loss-prevention", fields: [
        FieldDef(name: "version", required: true),
    ]),
]

public func category(named name: String) -> CategoryDef? { categories.first { $0.name == name } }

func categoryRank(_ name: String) -> Int { categories.firstIndex { $0.name == name } ?? categories.count }
