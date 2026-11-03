import Darwin
import Foundation

/// Reads the libraries a Mach-O image asks dyld to load, and resolves them the
/// way dyld would for a process started with a clean environment.
///
/// The root helper uses this to refuse an nmap whose libraries a non-root user
/// could replace. The app uses it to plan a self-contained root-owned copy.
public enum MachOLinkage {
    public struct LibraryReference: Equatable, Sendable {
        /// The install name exactly as written in the load command.
        public let installName: String
        public let isWeak: Bool
    }

    public struct Image: Equatable, Sendable {
        public var libraries: [LibraryReference] = []
        public var rpaths: [String] = []
        /// LC_DYLD_ENVIRONMENT entries, which can set dyld search paths.
        public var dyldEnvironment: [String] = []
        public var dylinker: String?
    }

    /// One resolved dependency edge.
    public struct ResolvedReference: Equatable, Sendable {
        public let installName: String
        /// The referencing image's real path.
        public let referencedFrom: String
        /// The candidate path dyld would load, or nil if it could not be resolved.
        public let path: String?
        public let isWeak: Bool
        public let isSystem: Bool
    }

    public struct Closure: Equatable, Sendable {
        /// Real paths of every non-system image, the executable first.
        public var images: [String] = []
        public var references: [ResolvedReference] = []
        /// Expanded LC_RPATH entries, keyed by the image that declares them.
        public var rpaths: [String: [String]] = [:]
        /// LC_RPATH entries exactly as written, keyed the same way.
        public var declaredRpaths: [String: [String]] = [:]
        public var problems: [String] = []
    }

    public enum ParseError: Error, Equatable, LocalizedError {
        case notMachO(String)
        case malformed(String)

        public var errorDescription: String? {
            switch self {
            case .notMachO(let path): return "\(path) is not a Mach-O image"
            case .malformed(let message): return "malformed Mach-O image: \(message)"
            }
        }
    }

    // Load command numbers from <mach-o/loader.h>.
    private static let lcReqDyld: UInt32 = 0x8000_0000
    private static let lcLoadDylib: UInt32 = 0xC
    private static let lcLoadDylinker: UInt32 = 0xE
    private static let lcLoadWeakDylib: UInt32 = 0x18 | lcReqDyld
    private static let lcRpath: UInt32 = 0x1C | lcReqDyld
    private static let lcReexportDylib: UInt32 = 0x1F | lcReqDyld
    private static let lcLazyLoadDylib: UInt32 = 0x20
    private static let lcLoadUpwardDylib: UInt32 = 0x23 | lcReqDyld
    private static let lcDyldEnvironment: UInt32 = 0x27

    /// Parses every architecture slice of a thin or universal file.
    public static func parse(_ data: Data, path: String = "image") throws -> [Image] {
        guard data.count >= 8 else { throw ParseError.notMachO(path) }
        let magicBE = readUInt32(data, 0, bigEndian: true)
        if magicBE == 0xCAFE_BABE || magicBE == 0xCAFE_BABF {
            let is64 = magicBE == 0xCAFE_BABF
            let count = Int(readUInt32(data, 4, bigEndian: true))
            guard count > 0, count <= 32 else { throw ParseError.malformed("\(path): bad fat arch count") }
            let entrySize = is64 ? 32 : 20
            var images: [Image] = []
            for index in 0..<count {
                let entry = 8 + index * entrySize
                guard entry + entrySize <= data.count else { throw ParseError.malformed("\(path): truncated fat header") }
                let offset: Int
                let size: Int
                if is64 {
                    offset = Int(clamping: readUInt64(data, entry + 8, bigEndian: true))
                    size = Int(clamping: readUInt64(data, entry + 16, bigEndian: true))
                } else {
                    offset = Int(readUInt32(data, entry + 8, bigEndian: true))
                    size = Int(readUInt32(data, entry + 12, bigEndian: true))
                }
                guard offset >= 0, size > 0, offset <= data.count, size <= data.count - offset else {
                    throw ParseError.malformed("\(path): fat slice outside the file")
                }
                images.append(try parseThin(data, base: offset, end: offset + size, path: path))
            }
            return images
        }
        return [try parseThin(data, base: 0, end: data.count, path: path)]
    }

    public static func parse(contentsOf url: URL) throws -> [Image] {
        try parse(try Data(contentsOf: url, options: .mappedIfSafe), path: url.path)
    }

    private static func parseThin(_ data: Data, base: Int, end: Int, path: String) throws -> Image {
        guard end - base >= 28 else { throw ParseError.notMachO(path) }
        let magic = readUInt32(data, base, bigEndian: false)
        let headerSize: Int
        switch magic {
        case 0xFEED_FACF: headerSize = 32
        case 0xFEED_FACE: headerSize = 28
        default: throw ParseError.notMachO(path)
        }
        let commandCount = Int(readUInt32(data, base + 16, bigEndian: false))
        let commandBytes = Int(readUInt32(data, base + 20, bigEndian: false))
        guard commandBytes <= end - base - headerSize else { throw ParseError.malformed("\(path): load commands exceed the slice") }
        var image = Image()
        var cursor = base + headerSize
        let commandsEnd = cursor + commandBytes
        for _ in 0..<commandCount {
            guard cursor + 8 <= commandsEnd else { throw ParseError.malformed("\(path): truncated load command") }
            let command = readUInt32(data, cursor, bigEndian: false)
            let size = Int(readUInt32(data, cursor + 4, bigEndian: false))
            guard size >= 8, size <= commandsEnd - cursor else { throw ParseError.malformed("\(path): bad load command size") }
            switch command {
            case lcLoadDylib, lcLoadWeakDylib, lcReexportDylib, lcLazyLoadDylib, lcLoadUpwardDylib:
                let name = try string(data, command: cursor, size: size, path: path)
                image.libraries.append(LibraryReference(installName: name, isWeak: command == lcLoadWeakDylib))
            case lcRpath:
                image.rpaths.append(try string(data, command: cursor, size: size, path: path))
            case lcDyldEnvironment:
                image.dyldEnvironment.append(try string(data, command: cursor, size: size, path: path))
            case lcLoadDylinker:
                image.dylinker = try string(data, command: cursor, size: size, path: path)
            default:
                break
            }
            cursor += size
        }
        return image
    }

    /// dylib, rpath, dylinker and dyld-environment commands all store a
    /// string offset (from the command start) at byte 8.
    private static func string(_ data: Data, command: Int, size: Int, path: String) throws -> String {
        guard size >= 12 else { throw ParseError.malformed("\(path): short string command") }
        let offset = Int(readUInt32(data, command + 8, bigEndian: false))
        guard offset >= 12, offset < size else { throw ParseError.malformed("\(path): string outside its command") }
        let bytes = data[(data.startIndex + command + offset)..<(data.startIndex + command + size)]
        let terminated = bytes.prefix { $0 != 0 }
        guard let value = String(bytes: terminated, encoding: .utf8), !value.isEmpty else {
            throw ParseError.malformed("\(path): empty or non-UTF-8 path")
        }
        return value
    }

    private static func readUInt32(_ data: Data, _ offset: Int, bigEndian: Bool) -> UInt32 {
        var value: UInt32 = 0
        withUnsafeMutableBytes(of: &value) { buffer in
            buffer.copyBytes(from: data[(data.startIndex + offset)..<(data.startIndex + offset + 4)])
        }
        return bigEndian ? UInt32(bigEndian: value) : UInt32(littleEndian: value)
    }

    private static func readUInt64(_ data: Data, _ offset: Int, bigEndian: Bool) -> UInt64 {
        var value: UInt64 = 0
        withUnsafeMutableBytes(of: &value) { buffer in
            buffer.copyBytes(from: data[(data.startIndex + offset)..<(data.startIndex + offset + 8)])
        }
        return bigEndian ? UInt64(bigEndian: value) : UInt64(littleEndian: value)
    }

    // MARK: - Resolution

    /// System libraries live in the SIP-protected dyld shared cache, often
    /// with no file on disk, so they are trusted by location.
    public static func isSystemPath(_ path: String) -> Bool {
        path.hasPrefix("/usr/lib/") || path.hasPrefix("/System/Library/")
    }

    /// Walks the executable's library graph. System libraries are recorded
    /// but not followed.
    public static func closure(ofExecutable executable: String) -> Closure {
        var result = Closure()
        guard let executableReal = realPath(executable) else {
            result.problems.append("cannot resolve \(executable)")
            return result
        }
        let executableDirectory = (executableReal as NSString).deletingLastPathComponent
        var queue = [executableReal]
        var seen: Set<String> = [executableReal]
        while !queue.isEmpty {
            let current = queue.removeFirst()
            result.images.append(current)
            let slices: [Image]
            do {
                slices = try parse(contentsOf: URL(fileURLWithPath: current))
            } catch {
                result.problems.append(error.localizedDescription)
                continue
            }
            let loaderDirectory = (current as NSString).deletingLastPathComponent
            func expand(_ value: String) -> String {
                if value.hasPrefix("@executable_path/") {
                    return executableDirectory + "/" + value.dropFirst("@executable_path/".count)
                }
                if value.hasPrefix("@loader_path/") {
                    return loaderDirectory + "/" + value.dropFirst("@loader_path/".count)
                }
                return value
            }
            var rpaths: [String] = []
            var declared: [String] = []
            for slice in slices {
                if let dylinker = slice.dylinker, dylinker != "/usr/lib/dyld" {
                    result.problems.append("\(current) uses dynamic linker \(dylinker)")
                }
                if !slice.dyldEnvironment.isEmpty {
                    result.problems.append("\(current) sets dyld environment \(slice.dyldEnvironment.joined(separator: ", "))")
                }
                for rpath in slice.rpaths {
                    if !declared.contains(rpath) { declared.append(rpath) }
                    let expanded = expand(rpath)
                    if !expanded.hasPrefix("/") {
                        result.problems.append("\(current) has relative LC_RPATH \(rpath)")
                    } else if !rpaths.contains(expanded) {
                        rpaths.append(expanded)
                    }
                }
            }
            if !rpaths.isEmpty { result.rpaths[current] = rpaths }
            if !declared.isEmpty { result.declaredRpaths[current] = declared }
            // dyld searches the requesting image's rpaths, then the executable's.
            let searchRpaths = rpaths + (current == executableReal ? [] : (result.rpaths[executableReal] ?? []))
            var references: [LibraryReference] = []
            for slice in slices {
                for library in slice.libraries where !references.contains(library) {
                    references.append(library)
                }
            }
            for library in references {
                let name = library.installName
                var candidate: String?
                if name.hasPrefix("@rpath/") {
                    let leaf = String(name.dropFirst("@rpath/".count))
                    candidate = searchRpaths.map { $0 + "/" + leaf }.first { access($0, F_OK) == 0 }
                } else if name.hasPrefix("@") {
                    candidate = expand(name)
                    if candidate?.hasPrefix("@") == true { candidate = nil }
                } else if name.hasPrefix("/") {
                    candidate = name
                }
                let system = candidate.map(isSystemPath) ?? false
                result.references.append(ResolvedReference(
                    installName: name,
                    referencedFrom: current,
                    path: candidate,
                    isWeak: library.isWeak,
                    isSystem: system
                ))
                guard let candidate, !system else {
                    if candidate == nil {
                        result.problems.append("\(current) links \(name), which does not resolve to an absolute path")
                    }
                    continue
                }
                guard let real = realPath(candidate) else {
                    if !library.isWeak {
                        result.problems.append("\(current) links missing library \(candidate)")
                    }
                    continue
                }
                if seen.insert(real).inserted { queue.append(real) }
            }
        }
        return result
    }

    /// Problems that would let a non-root user change code the executable
    /// loads. An empty result means every image, rpath and library location
    /// is root-controlled (or a SIP-protected system path).
    public static func untrustedLinkage(
        ofExecutable executable: String,
        isTrusted: (String) -> Bool = NmapPrivilegedHelperContract.isRootControlledPath
    ) -> [String] {
        let closure = closure(ofExecutable: executable)
        var problems = closure.problems
        for image in closure.images where !isTrusted(image) {
            problems.append("\(image) is not root-owned and read-only")
        }
        for (image, rpaths) in closure.rpaths {
            for rpath in rpaths where !isSystemPath(rpath + "/") && !isTrusted(rpath) {
                problems.append("\(image) searches LC_RPATH \(rpath), which is not root-controlled")
            }
        }
        for reference in closure.references where !reference.isSystem {
            guard let path = reference.path else { continue }
            if access(path, F_OK) == 0 {
                // The install name itself (not just its target) must be
                // root-controlled, or a user could repoint a symlink in it.
                if !isTrusted(path) {
                    problems.append("\(reference.referencedFrom) links \(path), which is not root-owned and read-only")
                }
            } else if reference.isWeak, !isTrusted((path as NSString).deletingLastPathComponent) {
                // dyld skips a missing weak library, so a user must not be
                // able to create one there later.
                problems.append("\(reference.referencedFrom) weakly links \(path) in a user-writable location")
            }
        }
        return problems
    }

    public static func realPath(_ path: String) -> String? {
        guard let resolved = Darwin.realpath(path, nil) else { return nil }
        defer { free(resolved) }
        return String(cString: resolved)
    }
}
