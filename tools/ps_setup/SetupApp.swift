// SetupApp.swift - the early NFS ProStreet Native Setup. It checks the player's nfs.exe (a file, the game folder, or a
// disc image) with the bundled backend (Resources/check/check.py, run on macOS's own Python) and says whether the port
// can use it. Building the game isn't available yet; the window says so. Nothing is uploaded, nothing from the game is
// run or changed. `Setup --check <path>` runs the same check without a window and prints the verdict (build tests).
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

final class Model: ObservableObject {
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
            Text("Early preview. It checks your own copy of the PC game and tells you whether the Mac port can use it. "
                 + "It can't build the game yet. It contains no game files, and nothing is uploaded.")
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
            }
            Spacer(minLength: 0)
        }
        .padding(20)
        .frame(minWidth: 560, minHeight: 360, alignment: .topLeading)
        .onDrop(of: ["public.file-url"], isTargeted: nil) { providers in
            guard m.toolsReady, let item = providers.first else { return false }
            _ = item.loadObject(ofClass: URL.self) { url, _ in
                if let url = url { DispatchQueue.main.async { m.check(url.path) } }
            }
            return true
        }
    }
}

@main
struct SetupApp: App {
    init() {
        // Headless check for build tests: Setup --check <path> prints "verdict<TAB>title" and exits.
        let args = CommandLine.arguments
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
