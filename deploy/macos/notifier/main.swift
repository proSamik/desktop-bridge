// Desktop Bridge notifier: posts a notification as its own app, so clicking it (or "Show")
// opens the URL passed with --url instead of Script Editor.
//   notifier --title T --message M [--subtitle S] [--url U]    post and exit (0 ok, 3 not allowed, 4 error)
//   notifier                                                   (launched by a click or by `open`): ask for
//                                                              permission / handle the click, then quit
import Cocoa
import UserNotifications

final class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
  let args = CommandLine.arguments
  func arg(_ k: String) -> String? {
    guard let i = args.firstIndex(of: k), i + 1 < args.count else { return nil }
    return args[i + 1]
  }
  func fail(_ code: Int32, _ msg: String) -> Never {
    FileHandle.standardError.write((msg + "\n").data(using: .utf8)!)
    exit(code)
  }

  func applicationDidFinishLaunching(_ note: Notification) {
    let center = UNUserNotificationCenter.current()
    center.delegate = self
    guard let title = arg("--title"), let message = arg("--message") else {
      // Opened by a notification click (didReceive follows) or by the installer to ask for permission.
      center.requestAuthorization(options: [.alert, .sound]) { _, _ in }
      DispatchQueue.main.asyncAfter(deadline: .now() + 30) { NSApp.terminate(nil) }
      return
    }
    center.requestAuthorization(options: [.alert, .sound]) { granted, _ in
      if !granted { self.fail(3, "notifications not allowed for Desktop Bridge (System Settings > Notifications)") }
      let content = UNMutableNotificationContent()
      content.title = title
      content.body = message
      if let s = self.arg("--subtitle") { content.subtitle = s }
      if let u = self.arg("--url") { content.userInfo = ["url": u] }
      let req = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
      center.add(req) { err in
        if let err = err { self.fail(4, "\(err)") }
        exit(0)
      }
    }
  }

  // Click on the notification or its "Show" button.
  func userNotificationCenter(_ c: UNUserNotificationCenter, didReceive r: UNNotificationResponse,
                              withCompletionHandler done: @escaping () -> Void) {
    if let s = r.notification.request.content.userInfo["url"] as? String, let u = URL(string: s) {
      NSWorkspace.shared.open(u)
    }
    done()
    DispatchQueue.main.asyncAfter(deadline: .now() + 1) { NSApp.terminate(nil) }
  }

  func userNotificationCenter(_ c: UNUserNotificationCenter, willPresent n: UNNotification,
                              withCompletionHandler done: @escaping (UNNotificationPresentationOptions) -> Void) {
    done([.banner, .list, .sound])
  }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
