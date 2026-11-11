#if canImport(SwiftUI)
import Foundation
import ServiceManagement
import UserNotifications

/// Notifications through UNUserNotificationCenter. Needs a bundled app;
/// asks for permission the first time it posts.
@MainActor
public final class UserNotifier: Notifier {
    private var asked = false

    public init() {}

    public func post(id: String, title: String, body: String) {
        let center = UNUserNotificationCenter.current()
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        let request = UNNotificationRequest(identifier: id, content: content, trigger: nil)
        let ask = !asked
        asked = true
        Task {
            if ask { _ = try? await center.requestAuthorization(options: [.alert, .sound]) }
            try? await center.add(request)
        }
    }
}

/// Launch at login as the app itself (SMAppService.mainApp).
@MainActor
public final class MainAppLoginItem: LoginItem {
    public init() {}

    public var isEnabled: Bool { SMAppService.mainApp.status == .enabled }

    public func setEnabled(_ on: Bool) throws {
        if on {
            try SMAppService.mainApp.register()
        } else {
            try SMAppService.mainApp.unregister()
        }
    }
}
#endif
