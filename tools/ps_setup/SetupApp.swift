// SetupApp.swift - NFS ProStreet Native Setup. It checks the player's nfs.exe (a file, the game folder, or a disc
// image) with the bundled check backend (Resources/check/check.py), and for the supported build (EA's ProStreet demo
// release) builds the game on this Mac with the build backend (Resources/build.py): recompile, host libraries, runtime,
// signed app installed in Applications, then Play. Both backends run on the Python of Apple's Command Line Tools.
// Nothing is uploaded; the game folder is only read. `Setup --check <path>` and `Setup --build <path>` run the same
// steps without a window (build tests).
import AppKit
import SwiftUI

struct CheckResult {
    var verdict = "", title = "", detail = "", next = "", exe = ""
    var facts: [(String, String)] = []
    var findings: [String] = []
    var coverage = ""
    var raw = ""
}

enum Backend {
    static let python = "/usr/bin/python3"
    static var script: String { Bundle.main.resourcePath.map { $0 + "/check/check.py" } ?? "check.py" }

    // The Command Line Tools provide /usr/bin/python3; without them it is only a stub that offers to install them.
    static func toolsInstalled() -> Bool {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/xcode-select")
        p.arguments = ["-p"]
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return false }
        p.waitUntilExit()
        return p.terminationStatus == 0
    }

    static func run(_ path: String) -> Result<CheckResult, Error> {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: python)
        p.arguments = ["-I", script, path]
        let out = Pipe(), err = Pipe()
        p.standardOutput = out
        p.standardError = err
        do { try p.run() } catch { return .failure(error) }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        let errText = String(data: err.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        p.waitUntilExit()
        guard p.terminationStatus == 0,
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return .failure(NSError(domain: "Setup", code: Int(p.terminationStatus),
                                    userInfo: [NSLocalizedDescriptionKey: "The check didn't finish. \(errText)"]))
        }
        var r = CheckResult()
        r.raw = String(data: data, encoding: .utf8) ?? ""
        r.verdict = obj["verdict"] as? String ?? ""
        r.title = obj["title"] as? String ?? ""
        r.detail = obj["detail"] as? String ?? ""
        r.next = obj["next"] as? String ?? ""
        r.exe = obj["exe"] as? String ?? ""
        if let f = obj["facts"] as? [String: Any] {
            let order = ["build", "signature", "size", "sha256", "linked", "entry", "sections", "imports"]
            let label = ["build": "Build", "signature": "Signature", "size": "Size", "sha256": "SHA-256", "linked": "Linked",
                         "entry": "Entry point", "sections": "Sections (entropy)", "imports": "Imports"]
            for k in order {
                if let v = f[k] { r.facts.append((label[k] ?? k, k == "size" ? "\(v) bytes" : "\(v)")) }
            }
        }
        r.findings = obj["findings"] as? [String] ?? []
        if let c = obj["coverage"] as? [String: Any], let h = c["handled"], let t = c["total"] {
            r.coverage = "\(h) of \(t) imported functions already have a Mac implementation"
        }
        return .success(r)
    }
}

// The build backend's JSON events (tools/ps_setup/build.py).
struct BuildStage: Identifiable { let id: String; let title: String; var state: Int }   // 0 waiting, 1 running, 2 done, 3 failed

enum Builder {
    static var script: String { Bundle.main.resourcePath.map { $0 + "/build.py" } ?? "build.py" }
    static var logPath: String { NSHomeDirectory() + "/Library/Logs/NFSPS-Setup/build.log" }

    // Runs the backend, calling `event` for each JSON line (on the reading thread); returns the exit status.
    static func run(_ path: String, event: @escaping ([String: Any]) -> Void) -> Int32 {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: Backend.python)
        p.arguments = ["-I", script, "--game", path, "--resources", Bundle.main.resourcePath ?? "."]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { event(["event": "error", "message": error.localizedDescription, "fix": ""]); return 1 }
        var pending = Data()
        let h = out.fileHandleForReading
        while true {
            let chunk = h.availableData
            if chunk.isEmpty { break }
            pending.append(chunk)
            while let nl = pending.firstIndex(of: 0x0A) {
                let line = pending.subdata(in: pending.startIndex..<nl)
                pending.removeSubrange(pending.startIndex...nl)
                if let obj = try? JSONSerialization.jsonObject(with: line) as? [String: Any] { event(obj) }
            }
        }
        p.waitUntilExit()
        return p.terminationStatus
    }
}

final class Model: ObservableObject {
    @Published var stages: [BuildStage] = []
    @Published var building = false
    @Published var lastLine = ""
    @Published var installed = ""
    @Published var buildError = ""
    @Published var buildFix = ""

    @Published var path = ""
    @Published var result: CheckResult?
    @Published var error = ""
    @Published var busy = false
    @Published var toolsReady = Backend.toolsInstalled()

    func choose() {
        let panel = NSOpenPanel()
        panel.title = "Choose nfs.exe, your game folder, or your disc image"
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        if panel.runModal() == .OK, let url = panel.url { check(url.path) }
    }

    func check(_ p: String) {
        path = p
        result = nil
        error = ""
        busy = true
        DispatchQueue.global(qos: .userInitiated).async {
            let r = Backend.run(p)
            DispatchQueue.main.async {
                self.busy = false
                switch r {
                case .success(let v): self.result = v
                case .failure(let e): self.error = e.localizedDescription
                }
            }
        }
    }

    func build() {
        guard !building else { return }
        building = true
        installed = ""; buildError = ""; buildFix = ""; lastLine = ""
        stages = []
        let target = path
        DispatchQueue.global(qos: .userInitiated).async {
            let status = Builder.run(target) { e in
                DispatchQueue.main.async { self.apply(e) }
            }
            DispatchQueue.main.async {
                self.building = false
                if status != 0 && self.buildError.isEmpty { self.buildError = "The build stopped (exit \(status))." }
            }
        }
    }

    func apply(_ e: [String: Any]) {
        switch e["event"] as? String ?? "" {
        case "stage":
            let id = e["id"] as? String ?? "", title = e["title"] as? String ?? id
            for i in stages.indices where stages[i].state == 1 { stages[i].state = 2 }
            stages.append(BuildStage(id: id, title: title, state: 1))
        case "log":
            lastLine = e["line"] as? String ?? ""
        case "done":
            for i in stages.indices where stages[i].state == 1 { stages[i].state = 2 }
            installed = e["app"] as? String ?? ""
        case "error":
            for i in stages.indices where stages[i].state == 1 { stages[i].state = 3 }
            buildError = e["message"] as? String ?? "The build failed."
            buildFix = e["fix"] as? String ?? ""
        default: break
        }
    }

    func play() { if !installed.isEmpty { NSWorkspace.shared.open(URL(fileURLWithPath: installed)) } }
    func reveal() { if !installed.isEmpty { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: installed)]) } }
    func openLog() { NSWorkspace.shared.open(URL(fileURLWithPath: Builder.logPath)) }

    func installTools() {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/xcode-select")
        p.arguments = ["--install"]
        try? p.run()
    }

    func copyReport() {
        guard let r = result else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(r.raw, forType: .string)
    }
}

struct ContentView: View {
    @StateObject var m = Model()

    var icon: (String, Color) {
        switch m.result?.verdict ?? "" {
        case "supported": return ("checkmark.seal.fill", .green)
        case "plain": return ("checkmark.circle.fill", .blue)
        case "unverified": return ("exclamationmark.shield.fill", .yellow)
        case "protected": return ("lock.fill", .orange)
        case "packed": return ("exclamationmark.triangle.fill", .orange)
        default: return ("questionmark.circle.fill", .secondary)
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("NFS ProStreet Native Setup").font(.title2).bold()
            Text("Builds the Mac version of NFS ProStreet from your own copy of EA's ProStreet demo, on this Mac. "
                 + "Setup contains no game files, nothing is uploaded, and your game folder is only read.")
                .foregroundColor(.secondary).fixedSize(horizontal: false, vertical: true)

            if !m.toolsReady {
                GroupBox {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Apple's Command Line Tools are needed (free). Setup uses the Python they include.")
                        HStack {
                            Button("Install Command Line Tools") { m.installTools() }
                            Button("I've installed them") { m.toolsReady = Backend.toolsInstalled() }
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                }
            }

            HStack {
                Button("Choose…") { m.choose() }.disabled(!m.toolsReady || m.busy)
                Text(m.path.isEmpty ? "nfs.exe, the installed game folder, or a disc image (.iso). You can also drop it here."
                                    : m.path)
                    .lineLimit(2).truncationMode(.middle).foregroundColor(m.path.isEmpty ? .secondary : .primary)
            }
            if m.busy { ProgressView("Checking…").controlSize(.small) }
            if !m.error.isEmpty { Text(m.error).foregroundColor(.red) }

            if let r = m.result {
                GroupBox {
                    VStack(alignment: .leading, spacing: 10) {
                        HStack(alignment: .top) {
                            Image(systemName: icon.0).foregroundColor(icon.1).font(.title)
                            VStack(alignment: .leading, spacing: 6) {
                                Text(r.title).font(.headline)
                                Text(r.detail).fixedSize(horizontal: false, vertical: true)
                            }
                        }
                        if !r.facts.isEmpty || !r.findings.isEmpty {
                            DisclosureGroup("Details") {
                                VStack(alignment: .leading, spacing: 4) {
                                    if !r.exe.isEmpty { Text("File: \(r.exe)").font(.caption).textSelection(.enabled) }
                                    ForEach(r.facts, id: \.0) { k, v in
                                        Text("\(k): \(v)").font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                                    }
                                    if !r.coverage.isEmpty { Text(r.coverage).font(.caption) }
                                    ForEach(r.findings, id: \.self) { Text("• \($0)").font(.caption) }
                                }.frame(maxWidth: .infinity, alignment: .leading).padding(.top, 4)
                            }
                        }
                        Divider()
                        Text(r.next).font(.callout).foregroundColor(.secondary).fixedSize(horizontal: false, vertical: true)
                        Button("Copy Report") { m.copyReport() }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                }
                if r.verdict == "supported" { buildBox }
            }
            Spacer(minLength: 0)
        }
        .padding(20)
        .frame(minWidth: 600, minHeight: 420, alignment: .topLeading)
        .onDrop(of: ["public.file-url"], isTargeted: nil) { providers in
            guard m.toolsReady, let item = providers.first else { return false }
            _ = item.loadObject(ofClass: URL.self) { url, _ in
                if let url = url { DispatchQueue.main.async { m.check(url.path) } }
            }
            return true
        }
    }
}

extension ContentView {
    var buildBox: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Button(m.installed.isEmpty ? "Build and Install" : "Build Again") { m.build() }
                        .disabled(m.building).keyboardShortcut(.defaultAction)
                    Text("About 5 minutes the first time (the video decoder is built once), about 2 after that.")
                        .font(.caption).foregroundColor(.secondary)
                }
                ForEach(m.stages) { st in
                    HStack(spacing: 6) {
                        switch st.state {
                        case 1: ProgressView().controlSize(.small)
                        case 2: Image(systemName: "checkmark.circle.fill").foregroundColor(.green)
                        case 3: Image(systemName: "xmark.octagon.fill").foregroundColor(.red)
                        default: Image(systemName: "circle").foregroundColor(.secondary)
                        }
                        Text(st.title)
                    }
                }
                if m.building && !m.lastLine.isEmpty {
                    Text(m.lastLine).font(.system(.caption, design: .monospaced)).foregroundColor(.secondary).lineLimit(1)
                }
                if !m.buildError.isEmpty {
                    Text(m.buildError).foregroundColor(.red).fixedSize(horizontal: false, vertical: true)
                    if !m.buildFix.isEmpty { Text(m.buildFix).font(.callout).fixedSize(horizontal: false, vertical: true) }
                    Button("Open Log") { m.openLog() }
                }
                if !m.installed.isEmpty {
                    Text("Installed: \(m.installed)").font(.callout)
                    HStack {
                        Button("Play") { m.play() }.keyboardShortcut(.defaultAction)
                        Button("Show in Finder") { m.reveal() }
                    }
                }
            }.frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

@main
struct SetupApp: App {
    init() {
        // Headless check for build tests: Setup --check <path> prints "verdict<TAB>title" and exits.
        let args = CommandLine.arguments
        if args.count == 3, args[1] == "--build" {             // headless build: prints the backend's events
            let status = Builder.run(args[2]) { e in
                switch e["event"] as? String ?? "" {
                case "stage": print("stage\t\(e["title"] ?? "")")
                case "done": print("done\t\(e["app"] ?? "")")
                case "error": print("error\t\(e["message"] ?? "")\t\(e["fix"] ?? "")")
                default: break
                }
                fflush(stdout)
            }
            exit(status)
        }
        if args.count == 3, args[1] == "--check" {
            switch Backend.run(args[2]) {
            case .success(let r): print("\(r.verdict)\t\(r.title)\t\(r.facts.count) facts\t\(r.coverage)"); exit(0)
            case .failure(let e): FileHandle.standardError.write(Data((e.localizedDescription + "\n").utf8)); exit(1)
            }
        }
    }

    var body: some Scene {
        WindowGroup("NFS ProStreet Native Setup") { ContentView() }
            .windowResizability(.contentMinSize)
        .commands { CommandGroup(replacing: .newItem) {} }
    }
}
