#if canImport(SwiftUI)
import AlbiConstants
import AppKit
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

/// Disconnects before the app quits, however it quits (the menu, Cmd-Q,
/// logout, restart). Install with `@NSApplicationDelegateAdaptor` and set
/// `model`.
@MainActor
public final class QuitDisconnects: NSObject, NSApplicationDelegate {
    public weak var model: AppModel?

    override public init() {}

    public func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let model, model.status.state.isActive else { return .terminateNow }
        Task {
            // Don't hold up a logout for long if the helper doesn't answer.
            let done = Task { await model.disconnectForQuit() }
            let timeout = Task { try? await Task.sleep(for: .seconds(5)) }
            await withTaskGroup(of: Void.self) { g in
                g.addTask { await done.value }
                g.addTask { await timeout.value }
                await g.next()
                g.cancelAll()
            }
            sender.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
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
