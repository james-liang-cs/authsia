import Foundation
#if os(macOS)
import Darwin
#endif

public enum AgentNetworkSocketTransport: Equatable, Sendable {
    case tcp
    case udp
    case unsupported
}

public enum AgentNetworkIPAddress: Equatable, Sendable {
    case ipv4([UInt8])
    case ipv6([UInt8])
    case unsupported
}

public struct AgentNetworkSocketMetadata: Equatable, Sendable {
    public let fileDescriptor: Int32
    public let socketGeneration: UInt64
    public let transport: AgentNetworkSocketTransport
    public let remoteAddress: AgentNetworkIPAddress
    public let remotePort: UInt16
    public let isListening: Bool

    public init(
        fileDescriptor: Int32,
        socketGeneration: UInt64,
        transport: AgentNetworkSocketTransport,
        remoteAddress: AgentNetworkIPAddress,
        remotePort: UInt16,
        isListening: Bool
    ) {
        self.fileDescriptor = fileDescriptor
        self.socketGeneration = socketGeneration
        self.transport = transport
        self.remoteAddress = remoteAddress
        self.remotePort = remotePort
        self.isListening = isListening
    }
}

public struct AgentNetworkSocketBatch: Equatable, Sendable {
    public let sockets: [AgentNetworkSocketMetadata]
    public let wasTruncated: Bool

    public init(sockets: [AgentNetworkSocketMetadata], wasTruncated: Bool) {
        self.sockets = sockets
        self.wasTruncated = wasTruncated
    }
}

public struct AgentNetworkInspectionResult: Equatable, Sendable {
    public let observations: [AgentNetworkSocketObservation]
    public let coverage: AgentNetworkCaptureCoverage
    public let failedProcessIdentityKeys: [String]

    public init(
        observations: [AgentNetworkSocketObservation],
        coverage: AgentNetworkCaptureCoverage,
        failedProcessIdentityKeys: [String]
    ) {
        self.observations = observations
        self.coverage = coverage
        self.failedProcessIdentityKeys = failedProcessIdentityKeys.sorted()
    }
}

public enum AgentNetworkSocketInspector {
    public typealias SocketProvider = (
        _ sample: InjectedProcessTreeSample,
        _ remainingDescriptorCount: Int
    ) throws -> AgentNetworkSocketBatch

    public static func inspect(
        samples: [InjectedProcessTreeSample],
        observedAt: Date = Date(),
        processLimit: Int = 256,
        descriptorLimit: Int = 4_096,
        socketProvider: SocketProvider
    ) -> AgentNetworkInspectionResult {
        let boundedProcessLimit = max(0, processLimit)
        let boundedDescriptorLimit = max(0, descriptorLimit)
        let selectedSamples = Array(samples.prefix(boundedProcessLimit))
        let depths = processDepths(samples: selectedSamples)
        var observations: [AgentNetworkSocketObservation] = []
        var failedProcessIdentityKeys: [String] = []
        var remainingDescriptorCount = boundedDescriptorLimit
        var isPartial = selectedSamples.count < samples.count

        for sample in selectedSamples {
            guard remainingDescriptorCount > 0 else {
                isPartial = true
                break
            }
            do {
                let batch = try socketProvider(sample, remainingDescriptorCount)
                let sockets = Array(batch.sockets.prefix(remainingDescriptorCount))
                remainingDescriptorCount -= sockets.count
                isPartial = isPartial
                    || batch.wasTruncated
                    || sockets.count < batch.sockets.count
                observations.append(
                    contentsOf: sockets.compactMap {
                        observation(
                            metadata: $0,
                            sample: sample,
                            depth: depths[sample.identityKey] ?? 0,
                            observedAt: observedAt
                        )
                    }
                )
            } catch {
                isPartial = true
                failedProcessIdentityKeys.append(sample.identityKey)
            }
        }

        return AgentNetworkInspectionResult(
            observations: observations,
            coverage: isPartial ? .partial : .observed,
            failedProcessIdentityKeys: failedProcessIdentityKeys
        )
    }

    public static func liveInspection(
        samples: [InjectedProcessTreeSample],
        observedAt: Date = Date()
    ) -> AgentNetworkInspectionResult {
        #if os(macOS)
        return inspect(samples: samples, observedAt: observedAt) {
            try liveSocketBatch(
                sample: $0,
                remainingDescriptorCount: $1
            )
        }
        #else
        _ = samples
        _ = observedAt
        return AgentNetworkInspectionResult(
            observations: [],
            coverage: .unavailable,
            failedProcessIdentityKeys: []
        )
        #endif
    }

    private static func observation(
        metadata: AgentNetworkSocketMetadata,
        sample: InjectedProcessTreeSample,
        depth: Int,
        observedAt: Date
    ) -> AgentNetworkSocketObservation? {
        guard !metadata.isListening,
              metadata.remotePort > 0,
              let remoteAddress = normalized(metadata.remoteAddress) else {
            return nil
        }

        let networkProtocol: AgentNetworkProtocol
        switch metadata.transport {
        case .tcp:
            networkProtocol = .tcp
        case .udp:
            networkProtocol = .udp
        case .unsupported:
            return nil
        }

        let connectionID = [
            sample.identityKey,
            String(metadata.fileDescriptor),
            String(metadata.socketGeneration),
            remoteAddress,
            String(metadata.remotePort),
            networkProtocol.rawValue,
        ].joined(separator: ":")
        return AgentNetworkSocketObservation(
            connectionID: connectionID,
            observedAt: observedAt,
            pid: sample.pid,
            processStartTime: sample.startTime,
            executable: sample.executable,
            depth: depth,
            remoteAddress: remoteAddress,
            remotePort: metadata.remotePort,
            networkProtocol: networkProtocol,
            sentBytes: nil,
            receivedBytes: nil
        )
    }

    private static func normalized(_ address: AgentNetworkIPAddress) -> String? {
        switch address {
        case .ipv4(let bytes):
            guard bytes.count == 4 else { return nil }
            return bytes.map(String.init).joined(separator: ".")
        case .ipv6(let bytes):
            guard bytes.count == 16 else { return nil }
            #if canImport(Darwin)
            var nativeAddress = in6_addr()
            withUnsafeMutableBytes(of: &nativeAddress) {
                $0.copyBytes(from: bytes)
            }
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            guard inet_ntop(AF_INET6, &nativeAddress, &buffer, socklen_t(buffer.count)) != nil else {
                return nil
            }
            let bytes = buffer.prefix { $0 != 0 }.map(UInt8.init(bitPattern:))
            return String(decoding: bytes, as: UTF8.self)
            #else
            return nil
            #endif
        case .unsupported:
            return nil
        }
    }

    private static func processDepths(
        samples: [InjectedProcessTreeSample]
    ) -> [String: Int] {
        guard let root = samples.first else { return [:] }
        let samplesByPID = Dictionary(uniqueKeysWithValues: samples.map { ($0.pid, $0) })
        var result: [String: Int] = [root.identityKey: 0]

        func depth(for sample: InjectedProcessTreeSample, visited: Set<Int32>) -> Int {
            if let known = result[sample.identityKey] {
                return known
            }
            guard !visited.contains(sample.pid),
                  let parent = samplesByPID[sample.ppid] else {
                return 0
            }
            let value = depth(
                for: parent,
                visited: visited.union([sample.pid])
            ) + 1
            result[sample.identityKey] = value
            return value
        }

        for sample in samples {
            _ = depth(for: sample, visited: [])
        }
        return result
    }

    #if os(macOS)
    private static func liveSocketBatch(
        sample: InjectedProcessTreeSample,
        remainingDescriptorCount: Int
    ) throws -> AgentNetworkSocketBatch {
        let requiredBytes = proc_pidinfo(
            sample.pid,
            PROC_PIDLISTFDS,
            0,
            nil,
            0
        )
        guard requiredBytes >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        let descriptorSize = MemoryLayout<proc_fdinfo>.size
        let requiredCount = Int(requiredBytes) / descriptorSize
        let requestedCount = min(requiredCount, remainingDescriptorCount)
        guard requestedCount > 0 else {
            return AgentNetworkSocketBatch(
                sockets: [],
                wasTruncated: requiredCount > 0
            )
        }

        var descriptors = [proc_fdinfo](repeating: proc_fdinfo(), count: requestedCount)
        let readBytes = descriptors.withUnsafeMutableBytes {
            proc_pidinfo(
                sample.pid,
                PROC_PIDLISTFDS,
                0,
                $0.baseAddress,
                Int32($0.count)
            )
        }
        guard readBytes >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        let readCount = min(Int(readBytes) / descriptorSize, descriptors.count)
        var sockets: [AgentNetworkSocketMetadata] = []

        for descriptor in descriptors.prefix(readCount)
        where descriptor.proc_fdtype == PROX_FDTYPE_SOCKET {
            if let metadata = socketMetadata(
                pid: sample.pid,
                fileDescriptor: descriptor.proc_fd
            ) {
                sockets.append(metadata)
            }
        }
        return AgentNetworkSocketBatch(
            sockets: sockets,
            wasTruncated: requiredCount > requestedCount
        )
    }

    private static func socketMetadata(
        pid: Int32,
        fileDescriptor: Int32
    ) -> AgentNetworkSocketMetadata? {
        var info = socket_fdinfo()
        let expectedSize = Int32(MemoryLayout<socket_fdinfo>.size)
        let readSize = proc_pidfdinfo(
            pid,
            fileDescriptor,
            PROC_PIDFDSOCKETINFO,
            &info,
            expectedSize
        )
        guard readSize == expectedSize else { return nil }

        let socketInfo = info.psi
        let transport: AgentNetworkSocketTransport
        let internetInfo: in_sockinfo
        let isListening: Bool
        switch socketInfo.soi_kind {
        case Int32(SOCKINFO_TCP):
            transport = .tcp
            internetInfo = socketInfo.soi_proto.pri_tcp.tcpsi_ini
            isListening = socketInfo.soi_proto.pri_tcp.tcpsi_state == TSI_S_LISTEN
        case Int32(SOCKINFO_IN)
        where socketInfo.soi_protocol == Int32(IPPROTO_UDP):
            transport = .udp
            internetInfo = socketInfo.soi_proto.pri_in
            isListening = false
        default:
            return nil
        }

        let remoteAddress: AgentNetworkIPAddress
        if internetInfo.insi_vflag & UInt8(INI_IPV4) != 0 {
            var address = internetInfo.insi_faddr.ina_46.i46a_addr4
            remoteAddress = .ipv4(withUnsafeBytes(of: &address) { Array($0) })
        } else if internetInfo.insi_vflag & UInt8(INI_IPV6) != 0 {
            var address = internetInfo.insi_faddr.ina_6
            remoteAddress = .ipv6(withUnsafeBytes(of: &address) { Array($0) })
        } else {
            remoteAddress = .unsupported
        }

        let networkPort = UInt16(truncatingIfNeeded: internetInfo.insi_fport)
        return AgentNetworkSocketMetadata(
            fileDescriptor: fileDescriptor,
            socketGeneration: internetInfo.insi_gencnt,
            transport: transport,
            remoteAddress: remoteAddress,
            remotePort: UInt16(bigEndian: networkPort),
            isListening: isListening
        )
    }
    #endif
}
