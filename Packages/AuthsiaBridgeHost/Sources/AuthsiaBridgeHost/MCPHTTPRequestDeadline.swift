#if os(macOS)
import NIOCore
import NIOHTTP1

/// Bounds silent sockets, incomplete headers and slow bodies. The deadline is
/// absolute, not renewed by trickled bytes. Completed requests may await native
/// approval or stream responses; keep-alive gets a new deadline after response end.
final class MCPHTTPRequestDeadline: ChannelDuplexHandler, @unchecked Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundIn = HTTPServerResponsePart
    private let timeout: TimeAmount
    private var deadline: Scheduled<Void>?
    private var receiving = true

    init(timeout: TimeAmount = .seconds(15)) { self.timeout = timeout }
    func handlerAdded(context: ChannelHandlerContext) { arm(context) }
    func handlerRemoved(context: ChannelHandlerContext) { deadline?.cancel(); deadline = nil }
    func channelInactive(context: ChannelHandlerContext) {
        deadline?.cancel(); deadline = nil
        context.fireChannelInactive()
    }
    private func arm(_ context: ChannelHandlerContext) {
        guard deadline == nil else { return }
        let channel = context.channel
        deadline = context.eventLoop.scheduleTask(in: timeout) { channel.close(promise: nil) }
    }
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        // Pipelining while an earlier response is pending is not supported.
        guard receiving else { context.close(promise: nil); return }
        if case .end = unwrapInboundIn(data) {
            receiving = false
            deadline?.cancel(); deadline = nil
        }
        context.fireChannelRead(data)
    }
    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        if case .end = unwrapOutboundIn(data) {
            receiving = true
            arm(context)
        }
        context.write(data, promise: promise)
    }
}
#endif
