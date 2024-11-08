import Foundation
import Hummingbird
import JWTKit

public struct MySessionPayload: Codable, Sendable {
    var test: String
}

public struct MySessionToken: JWTPayload {
    public typealias Content = MySessionPayload

    public var payload: MySessionPayload

    public func verify(using algorithm: some JWTKit.JWTAlgorithm) async throws {}
}

public protocol SessionMiddlewareContext<Content>: RequestContext where Content: JWTPayload {
    associatedtype Content

    var session: Content? { get set }
}

public struct SessionMiddleware<Context: SessionMiddlewareContext>: RouterMiddleware {

    let cookieName: String
    let keyCollection = JWTKeyCollection()
    let tokenType: any JWTPayload.Type

    public init(
        cookieName: String = "HBSESSION",
        secret: String,
        tokenType: any JWTPayload.Type
    ) async  {
        self.cookieName = cookieName
        self.tokenType = tokenType
        await keyCollection.add(hmac: HMACKey(stringLiteral: secret), digestAlgorithm: .sha256)
    }

    public func handle(
        _ request: Request,
        context: Context,
        next: (Request, Context) async throws -> Response
    ) async throws -> Response {
        var context = context

        if let cookie = request.cookies[cookieName] {
            let payload = try await keyCollection.verify(cookie.value, as: Context.Content.self)
            context.session = payload
        }

        var response = try await next(request, context)

        if let session = context.session {
            let cookieValue = try await keyCollection.sign(session)
            response.setCookie(.init(name: cookieName, value: cookieValue))
        }

        return response
    }
}
