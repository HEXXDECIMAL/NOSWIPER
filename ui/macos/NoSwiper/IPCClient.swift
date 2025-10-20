//
//  IPCClient.swift
//  NoSwiper
//
//  IPC client for communicating with NoSwiper daemon via Unix socket.
//

import Foundation

struct ViolationEvent: Codable {
    let id: String
    let timestamp: String
    let type: String
    let ruleName: String?
    let filePath: String
    let processPath: String
    let processPid: UInt32
    let processCmdline: String?
    let processEuid: UInt32?
    let parentPid: UInt32?
    let teamId: String?
    let action: String?
    let processTree: [ProcessTreeEntry]?

    enum CodingKeys: String, CodingKey {
        case id
        case timestamp
        case type
        case ruleName = "rule_name"
        case filePath = "file_path"
        case processPath = "process_path"
        case processPid = "process_pid"
        case processCmdline = "process_cmdline"
        case processEuid = "process_euid"
        case parentPid = "parent_pid"
        case teamId = "team_id"
        case action
        case processTree = "process_tree"
    }
}

struct ProcessTreeEntry: Codable {
    let pid: UInt32
    let ppid: UInt32?
    let name: String
    let path: String
    let cmdline: String?
    let teamId: String?
    let signingId: String?

    enum CodingKeys: String, CodingKey {
        case pid, ppid, name, path, cmdline
        case teamId = "team_id"
        case signingId = "signing_id"
    }
}

struct ClientResponse: Codable {
    let status: String
    let message: String?
    let mode: String?
    let eventsPending: Int?
    let connectedClients: Int?
    let events: [ViolationEvent]?

    enum CodingKeys: String, CodingKey {
        case status
        case message
        case mode
        case eventsPending = "events_pending"
        case connectedClients = "connected_clients"
        case events
    }
}

enum DaemonMode: String {
    case monitor
    case enforce
}

class IPCClient {
    private let socketPath = "/var/run/noswiper.sock"
    private var monitoringTask: Task<Void, Never>?

    func connect() -> FileHandle? {
        let sockaddr = sockaddr_un.unix(path: socketPath)
        guard let sockaddr = sockaddr else {
            print("Failed to create socket address")
            return nil
        }

        let sock = socket(AF_UNIX, SOCK_STREAM, 0)
        guard sock >= 0 else {
            print("Failed to create socket: \(String(cString: strerror(errno)))")
            return nil
        }

        var addr = sockaddr
        let connectResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: Darwin.sockaddr.self, capacity: 1) { sockaddrPtr in
                Darwin.connect(sock, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }

        guard connectResult >= 0 else {
            print("Failed to connect to socket: \(String(cString: strerror(errno)))")
            close(sock)
            return nil
        }

        return FileHandle(fileDescriptor: sock, closeOnDealloc: true)
    }

    func sendRequest(_ request: [String: Any]) -> ClientResponse? {
        guard let handle = connect() else {
            print("Failed to connect to daemon")
            return nil
        }

        defer { try? handle.close() }

        do {
            let jsonData = try JSONSerialization.data(withJSONObject: request)
            var dataWithNewline = jsonData
            dataWithNewline.append(contentsOf: [0x0A]) // newline

            try handle.write(contentsOf: dataWithNewline)

            // Read response line (newline-delimited)
            guard let line = try handle.readLine() else {
                print("No response from daemon")
                return nil
            }

            guard let lineData = line.data(using: .utf8) else {
                print("Invalid response encoding")
                return nil
            }

            let response = try JSONDecoder().decode(ClientResponse.self, from: lineData)
            print("Daemon response: \(response.status)")
            return response
        } catch {
            print("Error sending request: \(error)")
            return nil
        }
    }

    func getStatus() -> (mode: DaemonMode, running: Bool)? {
        guard let response = sendRequest(["action": "status"]) else {
            return nil
        }

        if response.status == "status", let modeStr = response.mode {
            let mode = DaemonMode(rawValue: modeStr) ?? .monitor
            return (mode: mode, running: true)
        }

        return nil
    }

    func setMode(_ mode: DaemonMode) -> Bool {
        guard let response = sendRequest(["action": "set_mode", "mode": mode.rawValue]) else {
            return false
        }
        return response.status == "success"
    }

    func allowOnce(eventId: String) -> Bool {
        guard let response = sendRequest(["action": "allow_once", "event_id": eventId]) else {
            return false
        }
        return response.status == "success"
    }

    func allowPermanently(eventId: String) -> Bool {
        guard let response = sendRequest(["action": "allow_permanently", "event_id": eventId]) else {
            return false
        }
        return response.status == "success"
    }

    func killProcess(eventId: String) -> Bool {
        guard let response = sendRequest(["action": "kill", "event_id": eventId]) else {
            return false
        }
        return response.status == "success"
    }

    func getOverrides() -> String? {
        guard let response = sendRequest(["action": "get_overrides"]) else {
            return nil
        }

        if response.status == "success" {
            return response.message
        }

        return nil
    }

    func getViolations(limit: Int? = nil) -> [ViolationEvent]? {
        var request: [String: Any] = ["action": "get_violations"]
        if let limit = limit {
            request["limit"] = limit
        }

        guard let handle = connect() else {
            return nil
        }

        defer { try? handle.close() }

        do {
            let jsonData = try JSONSerialization.data(withJSONObject: request)
            var dataWithNewline = jsonData
            dataWithNewline.append(contentsOf: [0x0A]) // newline

            try handle.write(contentsOf: dataWithNewline)

            // Read response
            let responseData = handle.availableData
            let response = try JSONDecoder().decode(ClientResponse.self, from: responseData)

            if response.status == "violations" {
                return response.events
            }

            return nil
        } catch {
            print("Error getting violations: \(error)")
            return nil
        }
    }

    func startMonitoring(onEvent: @escaping (ViolationEvent) -> Void) {
        monitoringTask = Task {
            while !Task.isCancelled {
                guard let handle = connect() else {
                    try? await Task.sleep(nanoseconds: 5_000_000_000) // 5 seconds
                    continue
                }

                do {
                    // Subscribe to events
                    let request: [String: Any] = ["action": "subscribe", "filter": NSNull()]
                    let jsonData = try JSONSerialization.data(withJSONObject: request)
                    var dataWithNewline = jsonData
                    dataWithNewline.append(contentsOf: [0x0A])

                    try handle.write(contentsOf: dataWithNewline)

                    // Read events continuously
                    while !Task.isCancelled {
                        guard let line = try handle.readLine() else {
                            break
                        }

                        if let lineData = line.data(using: .utf8) {
                            do {
                                // First try to decode as a violation event
                                let event = try JSONDecoder().decode(ViolationEvent.self, from: lineData)
                                onEvent(event)
                            } catch {
                                // Might be a status response or other message
                                print("Received non-event message: \(line)")
                            }
                        }
                    }
                } catch {
                    print("Error during monitoring: \(error)")
                }

                try? handle.close()
                try? await Task.sleep(nanoseconds: 2_000_000_000) // 2 seconds before reconnect
            }
        }
    }

    func stopMonitoring() {
        monitoringTask?.cancel()
        monitoringTask = nil
    }

    deinit {
        stopMonitoring()
    }
}

// Helper extensions
extension sockaddr_un {
    static func unix(path: String) -> sockaddr_un? {
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)

        guard path.utf8.count < MemoryLayout.size(ofValue: addr.sun_path) else {
            return nil
        }

        _ = withUnsafeMutablePointer(to: &addr.sun_path.0) { ptr in
            path.withCString { cString in
                strcpy(ptr, cString)
            }
        }

        return addr
    }
}

extension FileHandle {
    func readLine() throws -> String? {
        var lineData = Data()

        while true {
            guard let byte = try? read(upToCount: 1), !byte.isEmpty else {
                return lineData.isEmpty ? nil : String(data: lineData, encoding: .utf8)
            }

            if byte[0] == 0x0A { // newline
                return String(data: lineData, encoding: .utf8)
            }

            lineData.append(byte)
        }
    }
}
