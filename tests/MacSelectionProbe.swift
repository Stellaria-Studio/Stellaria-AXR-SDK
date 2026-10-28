// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
// Owner-operated system picker qualification. Metadata by default. The optional
// scoped read captures one owner-selected window, runs local Vision and returns
// text only over the parent's private pipe. Never an input or network capability.
import AppKit
import ScreenCaptureKit
import Darwin
import Vision
import AXRCommit

@available(macOS 15.2, *)
final class SelectionProbe: NSObject, SCContentSharingPickerObserver {
    let bundle: String
    let pid: pid_t
    let picker = SCContentSharingPicker.shared
    var finished = false
    var capturing = false
    var contentRead = false
    var request: [String: Any]?
    init(bundle: String, pid: pid_t) { self.bundle = bundle; self.pid = pid }
    func finish(_ fields: [String: Any], _ status: Int32 = 0) {
        guard !finished else { return }
        finished = true
        picker.remove(self); picker.isActive = false
        let value = fields.merging(["metadata_only": request == nil, "content_read": contentRead,
                                   "send_available": false]) { first, _ in first }
        if let bytes = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) {
            FileHandle.standardOutput.write(bytes); FileHandle.standardOutput.write(Data([10]))
        }
        // Scoped reads report safe structured failure to the private parent.
        // The broker requires verified=true, so transport success is not a read success.
        exit(request != nil && status == 1 ? 0 : status)
    }
    func verifyRead() throws {
        guard let request, let binding = request["visual_binding"] as? [String: Any],
              binding["bundle"] as? String == bundle, binding["pid"] as? Int == Int(pid),
              let id = binding["window_id"] as? UInt32, id > 0,
              let title = binding["title"] as? String, !title.isEmpty,
              let bounds = binding["bounds"] as? [Double], bounds.count == 4,
              bounds.allSatisfy({ $0.isFinite }), bounds[2] >= 100, bounds[3] >= 100,
              bounds[2] <= 4096, bounds[3] <= 4096,
              let context = request["guard_context"] as? [String: String],
              let store = context["store"], let proof = context["proof"],
              let resource = request["resource"] as? [String: String],
              Set(resource.keys) == Set(["platform", "account_id", "conversation_id"]),
              NSRunningApplication.runningApplications(withBundleIdentifier: bundle).map({$0.processIdentifier}) == [pid]
        else { throw ProbeError("window_scope_changed") }
        let scope: [String: Any] = ["operations": ["messages.read"], "resource": resource, "visual_binding": binding]
        let encoded = String(decoding: try JSONSerialization.data(withJSONObject: scope), as: UTF8.self)
        guard store.withCString({p in proof.withCString({q in encoded.withCString({s in axr_check_scoped_commit(p,q,s)})})}) == 1
        else { throw ProbeError("capability_scope_changed") }
        let rows = CGWindowListCopyWindowInfo(.optionIncludingWindow, id) as? [[String: Any]] ?? []
        guard rows.count == 1, let row = rows.first,
              row[kCGWindowOwnerPID as String] as? Int == Int(pid),
              row[kCGWindowIsOnscreen as String] as? Bool == true,
              row[kCGWindowLayer as String] as? Int == 0,
              row[kCGWindowName as String] as? String == title,
              let raw = row[kCGWindowBounds as String] as? [String: Any],
              let actual = CGRect(dictionaryRepresentation: raw as CFDictionary),
              [actual.minX,actual.minY,actual.width,actual.height].map({Double($0)}) == bounds
        else { throw ProbeError("window_scope_changed") }
    }
    func capture(_ filter: SCContentFilter, window: SCWindow) {
        do { try verifyRead() } catch { finish(["selected":false,"reason":(error as? ProbeError)?.code ?? "read_scope_changed"],1); return }
        guard let binding = request?["visual_binding"] as? [String:Any],
              binding["window_id"] as? UInt32 == window.windowID else {
            finish(["selected":false,"reason":"selected_window_not_authorized"],1); return
        }
        capturing = true
        let configuration = SCStreamConfiguration()
        configuration.width = min(2048, max(1,Int(window.frame.width * 2)))
        configuration.height = min(2048, max(1,Int(window.frame.height * 2)))
        configuration.showsCursor = false; configuration.capturesAudio = false
        configuration.includeChildWindows = false; configuration.captureMicrophone = false
        Timer.scheduledTimer(withTimeInterval: 15, repeats: false) { [self] _ in
            finish(["selected":true,"reason":"capture_or_ocr_timeout"],1)
        }
        // Use EXACTLY the filter returned by the owner's picker. Never construct
        // a desktop/display filter or switch routes after an exclusion/failure.
        SCScreenshotManager.captureImage(contentFilter:filter,configuration:configuration) { [self] image,error in
            guard let image, error == nil else {
                let code = (error as NSError?)?.code ?? 0
                DispatchQueue.main.async { self.finish(["selected":true,"reason":"owner_selected_capture_failed","system_error_code":code],1) }; return
            }
            guard image.width <= 2048, image.height <= 2048 else {
                DispatchQueue.main.async { self.finish(["selected":true,"reason":"frame_size_budget_exceeded"],1) }; return
            }
            DispatchQueue.main.async { self.contentRead = true }
            DispatchQueue.global(qos:.userInitiated).async { [self] in
                do {
                    try verifyRead()
                    // Coarse, local pixel statistics distinguish a returned
                    // blank canvas from a usable frame. No pixel data leaves here.
                    var pixels = [UInt8](repeating:0,count:64*64*4)
                    let statistics = pixels.withUnsafeMutableBytes { buffer -> (Int,Int,Int)? in
                        guard let context = CGContext(data:buffer.baseAddress,width:64,height:64,
                            bitsPerComponent:8,bytesPerRow:64*4,space:CGColorSpaceCreateDeviceRGB(),
                            bitmapInfo:CGImageAlphaInfo.premultipliedLast.rawValue) else { return nil }
                        context.draw(image,in:CGRect(x:0,y:0,width:64,height:64))
                        var minimum = 255, maximum = 0, opaque = 0
                        for index in stride(from:0,to:64*64*4,by:4) {
                            guard buffer[index+3] >= 250 else { continue }
                            opaque += 1
                            let luma = (Int(buffer[index])+Int(buffer[index+1])+Int(buffer[index+2]))/3
                            minimum = min(minimum,luma); maximum = max(maximum,luma)
                        }
                        return (minimum,maximum,opaque)
                    }
                    guard let statistics else { throw ProbeError("frame_statistics_unavailable") }
                    let recognition = VNRecognizeTextRequest()
                    recognition.recognitionLevel = .accurate
                    recognition.recognitionLanguages = ["zh-Hans","en-US"]
                    recognition.usesLanguageCorrection = false
                    try VNImageRequestHandler(cgImage:image).perform([recognition])
                    let observations = recognition.results ?? []
                    guard observations.count <= 100 else { throw ProbeError() }
                    var bytes = 0
                    let lines = try observations.sorted {$0.boundingBox.midY > $1.boundingBox.midY}.compactMap { item -> [String:Any]? in
                        guard let text = item.topCandidates(1).first else { return nil }
                        bytes += text.string.utf8.count
                        guard bytes <= 64000 else { throw ProbeError() }
                        return ["text":text.string,"confidence":text.confidence]
                    }
                    try verifyRead()
                    let fields: [String:Any] = ["selected":true,"verified":true,"single_window":true,
                        "frame_received":true,"width":image.width,"height":image.height,"lines":lines,
                        "images_persisted":false,"network_used":false,"identity_assurance":"owner_selected_window_unqualified_for_send",
                        "foreground":NSRunningApplication(processIdentifier:pid)?.isActive ?? false,
                        "frame_luma_min":statistics.2 > 0 ? statistics.0 as Any : NSNull(),
                        "frame_luma_max":statistics.2 > 0 ? statistics.1 as Any : NSNull(),"opaque_samples":statistics.2,
                        "frame_has_variation":statistics.2 > 0 && statistics.1-statistics.0 > 2]
                    DispatchQueue.main.async { self.contentRead = true; self.finish(fields) }
                } catch {
                    let reason = (error as? ProbeError)?.code ?? "local_ocr_failed"
                    DispatchQueue.main.async { self.finish(["selected":true,"reason":reason],1) }
                }
            }
        }
    }
    func contentSharingPicker(_ picker: SCContentSharingPicker, didCancelFor stream: SCStream?) {
        finish(["selected": false, "reason": "owner_cancelled"])
    }
    func contentSharingPickerStartDidFailWithError(_ error: Error) {
        finish(["selected": false, "reason": "system_picker_failed", "error_code": (error as NSError).code], 1)
    }
    func contentSharingPicker(_ picker: SCContentSharingPicker, didUpdateWith filter: SCContentFilter, for stream: SCStream?) {
        guard !capturing else { finish(["selected":false,"reason":"selection_changed_during_read"],1); return }
        guard stream == nil, filter.style == .window, filter.includedWindows.count == 1,
              let window = filter.includedWindows.first,
              let application = window.owningApplication,
              application.bundleIdentifier == bundle, application.processID == pid,
              NSRunningApplication(processIdentifier: pid)?.bundleIdentifier == bundle else {
            finish(["selected": false, "reason": "selection_scope_mismatch"], 1); return
        }
        if request != nil { capture(filter,window:window); return }
        let rows = CGWindowListCopyWindowInfo([.optionIncludingWindow], window.windowID) as? [[String: Any]] ?? []
        let sharing = rows.first?[kCGWindowSharingState as String] as? Int ?? -1
        finish(["selected": true, "single_window": true, "pid": Int(pid),
                "window_id": Int(window.windowID), "legacy_sharing_state": sharing,
                "filter_validated": true])
    }
    func start(timeout: TimeInterval) {
        var configuration = SCContentSharingPickerConfiguration()
        configuration.allowedPickerModes = [.singleWindow]
        configuration.allowsChangingSelectedContent = false
        if let binding = request?["visual_binding"] as? [String:Any], let id = binding["window_id"] as? UInt32 {
            let rows = CGWindowListCopyWindowInfo(.optionAll,kCGNullWindowID) as? [[String:Any]] ?? []
            configuration.excludedWindowIDs = rows.compactMap { row -> Int? in
                guard (row[kCGWindowOwnerPID as String] as? Int) == Int(pid),
                      let other = row[kCGWindowNumber as String] as? UInt32, other != id else { return nil }
                return Int(other)
            }
        }
        configuration.excludedBundleIDs = Array(Set(NSWorkspace.shared.runningApplications.compactMap {
            $0.bundleIdentifier == bundle ? nil : $0.bundleIdentifier
        }))
        picker.defaultConfiguration = configuration; picker.maximumStreamCount = 1
        picker.add(self); picker.isActive = true
        Timer.scheduledTimer(withTimeInterval: timeout, repeats: false) { [self] _ in
            finish(["selected": false, "reason": "selection_timeout"], 1)
        }
        picker.present(using: .window)
    }
}
struct ProbeError: Error { let code: String; init(_ code: String = "read_scope_invalid") { self.code = code } }

if #available(macOS 15.2, *) {
    let args = Array(CommandLine.arguments.dropFirst())
    var request: [String:Any]? = nil
    var bundle = "", timeout: TimeInterval = 0
    if args == ["--read-ocr"] || args == ["--read-ocr-fixture"] {
        guard let line = readLine(), line.utf8.count <= 524288,
              let value = try? JSONSerialization.jsonObject(with:Data(line.utf8)) as? [String:Any],
              let binding = value["visual_binding"] as? [String:Any],
              let name = binding["bundle"] as? String else { exit(2) }
        if args == ["--read-ocr-fixture"] {
            guard name == "dev.axr.input-fixture",
                  binding["title"] as? String == "AXR synthetic input fixture",
                  value["resource"] as? [String:String] == ["platform":"fixture", "account_id":"fixture-account", "conversation_id":"fixture-chat"] else { exit(2) }
        }
        request = value; bundle = name; timeout = args == ["--read-ocr-fixture"] ? 260 : 180
    } else if args.count == 2, let value = TimeInterval(args[1]) {
        bundle = args[0]; timeout = value
    }
    guard !bundle.isEmpty, bundle.utf8.count <= 256, timeout.isFinite, timeout >= 1,
          timeout <= (args == ["--read-ocr-fixture"] ? 260 : 180) else { exit(2) }
    let applications = NSRunningApplication.runningApplications(withBundleIdentifier: bundle)
    guard applications.count == 1, let application = applications.first else { exit(2) }
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    let probe = SelectionProbe(bundle: bundle, pid: application.processIdentifier)
    probe.request = request
    if request != nil { do { try probe.verifyRead() } catch { probe.finish(["selected":false,"reason":(error as? ProbeError)?.code ?? "read_scope_invalid"],1) } }
    probe.start(timeout: timeout)
    app.run()
} else { exit(2) }
