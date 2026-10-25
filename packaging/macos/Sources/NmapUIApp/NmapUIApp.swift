import AppKit
import SwiftUI

@main
struct NmapUIApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        WindowGroup("TM-NMAPUI") {
            if ScheduledScanRunner.isScheduledScanInvocation {
                Color.clear.frame(width: 1, height: 1)
            } else {
                ExecutionRootView(appDelegate: appDelegate, router: appDelegate.executionRouter)
            }
        }.commands {
            ExecutionCommands(appDelegate: appDelegate, router: appDelegate.executionRouter, model: appDelegate.executionRouter.sharedScanner)
        }
        Settings {
            ExecutionSettingsView(appDelegate: appDelegate, router: appDelegate.executionRouter)
        }
    }
}
