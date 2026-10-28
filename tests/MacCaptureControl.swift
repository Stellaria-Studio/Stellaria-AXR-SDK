// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
// Manual developer qualification, never installed in the product or auto-run.
// Exactly one owned synthetic window. No display capture, consent requests,
// private application data, image files, fallback routes or input events.
import AppKit
import ScreenCaptureKit
import CoreVideo
import Vision

func emit(_ fields: [String: Any]) {
    guard let data = try? JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys]) else { return }
    FileHandle.standardOutput.write(data); FileHandle.standardOutput.write(Data([10]))
}
guard CommandLine.arguments == [CommandLine.arguments[0], "--self-test"] else {
    emit(["verified": false, "reason": "explicit_self_test_required"]); exit(2)
}
guard #available(macOS 14.0, *) else {
    emit(["verified": false, "reason": "macos_14_required"]); exit(2)
}
guard CGPreflightScreenCaptureAccess() else {
    emit(["verified": false, "reason": "screen_recording_consent_required"]); exit(2)
}
let app = NSApplication.shared
app.setActivationPolicy(.regular)
let expected = "AXR Synthetic Capture Control"
let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 680, height: 320),
    styleMask: [.titled, .closable], backing: .buffered, defer: false)
window.title = expected
window.contentView!.wantsLayer = true
window.contentView!.layer!.backgroundColor = NSColor.white.cgColor
let label = NSTextField(labelWithString: expected)
label.textColor = .black; label.font = .systemFont(ofSize: 20)
label.frame = NSRect(x: 30, y: 140, width: 600, height: 40)
window.contentView!.addSubview(label)
window.center(); window.makeKeyAndOrderFront(nil); app.activate(ignoringOtherApps: true)
var finished = false
func finish(_ result: [String: Any]) {
    guard !finished else { return }; finished = true
    emit(result.merging(["synthetic_only": true, "capture_count_limit": 1, "image_saved": false,
                        "send_available": false]) { first, _ in first })
    exit(result["verified"] as? Bool == true ? 0 : 1)
}
DispatchQueue.main.asyncAfter(deadline: .now() + 20) {
    finish(["verified": false, "reason": "capture_or_ocr_timeout"])
}
DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
    Task { @MainActor in
        do {
            let content = try await SCShareableContent.excludingDesktopWindows(true, onScreenWindowsOnly: true)
            let matches = content.windows.filter {
                $0.owningApplication?.processID == getpid() && $0.windowID == CGWindowID(window.windowNumber)
            }
            guard matches.count == 1, let owned = matches.first else {
                finish(["verified": false, "reason": "owned_window_missing"]); return
            }
            let rows = CGWindowListCopyWindowInfo(.optionIncludingWindow, owned.windowID) as? [[String: Any]] ?? []
            guard rows.count == 1, rows[0][kCGWindowSharingState as String] as? Int == 1 else {
                finish(["verified": false, "reason": "sharing_not_allowed"]); return
            }
            let configuration = SCStreamConfiguration()
            configuration.width = 1360; configuration.height = 704
            configuration.pixelFormat = kCVPixelFormatType_32BGRA
            configuration.showsCursor = false; configuration.capturesAudio = false
            configuration.captureMicrophone = false; configuration.includeChildWindows = false
            let image = try await SCScreenshotManager.captureImage(
                contentFilter: SCContentFilter(desktopIndependentWindow: owned), configuration: configuration)
            guard !finished else { return }
            // Keep the main run loop free so its deadline can also interrupt
            // a stalled Vision request, rather than just the capture await.
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let request = VNRecognizeTextRequest()
                    request.recognitionLevel = .accurate; request.recognitionLanguages = ["en-US"]
                    request.usesLanguageCorrection = false
                    try VNImageRequestHandler(cgImage: image).perform([request])
                    let lines = (request.results ?? []).compactMap { $0.topCandidates(1).first }
                    let matched = lines.contains { $0.string == expected && $0.confidence >= 0.8 }
                    DispatchQueue.main.async {
                        finish(["verified": matched, "expected_text_matched": matched,
                                "ocr_line_count": lines.count, "width": image.width, "height": image.height])
                    }
                } catch {
                    DispatchQueue.main.async {
                        finish(["verified": false, "reason": "system_capture_or_ocr_failed",
                                "error_domain": (error as NSError).domain, "error_code": (error as NSError).code])
                    }
                }
            }
        } catch {
            finish(["verified": false, "reason": "system_capture_or_ocr_failed",
                    "error_domain": (error as NSError).domain, "error_code": (error as NSError).code])
        }
    }
}
app.run()
