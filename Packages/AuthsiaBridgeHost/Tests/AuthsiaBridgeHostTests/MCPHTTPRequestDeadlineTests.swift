import XCTest
import NIOCore
import NIOEmbedded
import NIOHTTP1
@testable import AuthsiaBridgeHost

final class MCPHTTPRequestDeadlineTests: XCTestCase {
    private func channel() throws -> EmbeddedChannel {
        let channel = EmbeddedChannel()
        try channel.pipeline.configureHTTPServerPipeline().wait()
        try channel.pipeline.addHandler(MCPHTTPRequestDeadline(timeout: .seconds(2))).wait()
        try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 9000)).wait()
        return channel
    }

    func testSilentPartialHeaderAndTrickledBodyConnectionsExpireAndReleasePool() throws {
        let pool = MCPHTTPChannels()
        var channels: [EmbeddedChannel] = []
        for index in 0..<16 {
            let channel = try channel()
            XCTAssertTrue(pool.insert(channel))
            if index % 3 == 1 { try channel.writeInbound(ByteBuffer(string: "POST / HTTP/1.1\r\nHost:")) }
            if index % 3 == 2 {
                try channel.writeInbound(ByteBuffer(string: "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 20\r\n\r\na"))
                channel.embeddedEventLoop.advanceTime(by: .seconds(1))
                try channel.writeInbound(ByteBuffer(string: "b"))
            }
            channels.append(channel)
        }
        let extra = try channel()
        XCTAssertFalse(pool.insert(extra))
        for channel in channels {
            channel.embeddedEventLoop.advanceTime(by: .seconds(2))
            XCTAssertFalse(channel.isActive)
            do { _ = try channel.finish(acceptAlreadyClosed: true) }
            catch { XCTAssertEqual(error as? HTTPParserError, .invalidEOFState) }
        }
        XCTAssertTrue(pool.insert(extra))
        _ = try extra.finish()
    }

    func testCompletedRequestMayWaitForApprovalOrStreamAndKeepAliveRearms() throws {
        let channel = try channel()
        try channel.writeInbound(ByteBuffer(string: "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"))
        channel.embeddedEventLoop.advanceTime(by: .seconds(30))
        XCTAssertTrue(channel.isActive)
        try channel.writeOutbound(HTTPServerResponsePart.head(.init(version: .http1_1, status: .ok)))
        channel.embeddedEventLoop.advanceTime(by: .seconds(30))
        XCTAssertTrue(channel.isActive)
        try channel.writeOutbound(HTTPServerResponsePart.end(nil))
        channel.embeddedEventLoop.advanceTime(by: .seconds(2))
        XCTAssertFalse(channel.isActive)
        _ = try channel.finish(acceptAlreadyClosed: true)
    }
}
