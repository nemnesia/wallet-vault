import Foundation

struct SnapshotStore {
    let directory: URL
    let backend: Backend

    init(root: URL, backend: Backend) throws {
        self.backend = backend
        directory = root.appendingPathComponent(backend.rawValue, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        var resourceURL = directory
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try resourceURL.setResourceValues(values)
    }

    func load() throws -> [Snapshot] {
        var result: [Snapshot] = []
        for url in try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: [.fileSizeKey])
            where url.pathExtension == "json" {
            guard try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? Int.max <= 32768 else {
                throw VaultFailure("STORAGE_CORRUPT")
            }
            let snapshot = try JSONDecoder().decode(Snapshot.self, from: Data(contentsOf: url))
            try snapshot.validate()
            guard snapshot.backend == backend, url.deletingPathExtension().lastPathComponent == snapshot.records.id else {
                throw VaultFailure("STORAGE_CORRUPT")
            }
            result.append(snapshot)
        }
        return result.sorted { $0.records.id < $1.records.id }
    }

    func save(_ snapshot: Snapshot, abort: Bool = false) throws {
        try snapshot.validate()
        guard snapshot.backend == backend else { throw VaultFailure("INVALID_INPUT") }
        let target = directory.appendingPathComponent(snapshot.records.id + ".json")
        guard !FileManager.default.fileExists(atPath: target.path) else { throw VaultFailure("PROFILE_EXISTS") }
        let staging = directory.appendingPathComponent(".pending-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: staging, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: staging) }
        let staged = staging.appendingPathComponent("snapshot")
        let data = try JSONEncoder().encode(snapshot)
        guard data.count <= 32768 else { throw VaultFailure("INVALID_INPUT") }
        #if os(iOS)
        try data.write(to: staged, options: [.atomic, .completeFileProtection])
        #else
        try data.write(to: staged, options: .atomic)
        #endif
        if abort { throw VaultFailure("STORAGE_FAILED") }
        // moveItem refuses an existing destination. The same-volume rename exposes
        // a whole new snapshot, with no partial Profile visible to the loader.
        try FileManager.default.moveItem(at: staged, to: target)
    }
}
