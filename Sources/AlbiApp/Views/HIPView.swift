#if canImport(SwiftUI)
import SwiftUI

/// What Albi reports to the gateway: whether it asked this session, when the
/// last report went, and each check against the expected policy.
struct HIPView: View {
    let model: AppModel

    var body: some View {
        if let hip = model.status.hip {
            VStack(alignment: .leading, spacing: 0) {
                header(hip)
                    .padding(12)
                Divider()
                Table(hip.checks) {
                    TableColumn("") { c in ResultIcon(passed: c.passed) }
                        .width(22)
                    TableColumn("Check") { c in
                        VStack(alignment: .leading) {
                            Text(c.name)
                            Text(c.category).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    .width(min: 160, ideal: 200)
                    TableColumn("Expected", value: \.expected)
                    TableColumn("Collected", value: \.actual)
                    TableColumn("How It Was Checked") { c in
                        Text(c.method).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                    }
                    .width(min: 160, ideal: 220)
                }
            }
            .frame(minWidth: 640, minHeight: 260)
        } else {
            ContentUnavailableView(
                "No HIP Report Yet", systemImage: "checklist",
                description: Text("Connect to see what Albi reports to the gateway."))
            .frame(minWidth: 640, minHeight: 260)
        }
    }

    private func header(_ hip: HIPStatus) -> some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 4) {
                Label(hip.isCompliant ? "Meets the expected policy" : "\(hip.failing.count) failing",
                      systemImage: hip.isCompliant ? "checkmark.seal.fill" : "xmark.seal.fill")
                    .font(.headline)
                    .foregroundStyle(hip.isCompliant ? .green : .red)
                Text(hip.requested
                     ? "The gateway asked for a HIP report this session."
                     : "The gateway hasn't asked for a HIP report this session.")
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if let sent = hip.lastSent {
                Text("Last sent \(sent.formatted(date: .omitted, time: .shortened))")
                    .foregroundStyle(.secondary)
            }
        }
    }
}

private struct ResultIcon: View {
    let passed: Bool?

    var body: some View {
        switch passed {
        case true?:
            Image(systemName: "checkmark.circle.fill").foregroundStyle(.green).accessibilityLabel("Passes")
        case false?:
            Image(systemName: "xmark.circle.fill").foregroundStyle(.red).accessibilityLabel("Fails")
        case nil:
            Image(systemName: "minus.circle").foregroundStyle(.secondary).accessibilityLabel("No expectation")
        }
    }
}
#endif
