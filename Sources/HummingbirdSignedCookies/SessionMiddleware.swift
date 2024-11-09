import Foundation
import Hummingbird
import JWTKit

public protocol SessionMiddlewareContext<Content>: RequestContext where Content: Codable & Sendable {
    associatedtype Content

    var session: Content? { get set }
}

public struct SessionMiddleware<Context: SessionMiddlewareContext>: RouterMiddleware {

    struct SessionToken: JWTPayload {
        let data: Context.Content

        public func verify(using algorithm: some JWTKit.JWTAlgorithm) async throws {}
    }

    let cookieName: String
    let keyCollection = JWTKeyCollection()

    public init(
        cookieName: String = "HBSESSION",
        secret: String
    ) async  {
        self.cookieName = cookieName
        await keyCollection.add(hmac: HMACKey(stringLiteral: secret), digestAlgorithm: .sha256)
    }

    public func handle(
        _ request: Request,
        context: Context,
        next: (Request, Context) async throws -> Response
    ) async throws -> Response {
        var context = context

        if let cookie = request.cookies[cookieName] {
            let payload = try await keyCollection.verify(cookie.value, as: SessionToken.self)
            context.session = payload.data
        }

        var response = try await next(request, context)

        if let session = context.session {
            let tokenPayload = SessionToken(data: session)
            let cookieValue = try await keyCollection.sign(tokenPayload)
            response.setCookie(.init(name: cookieName, value: cookieValue))
        } else {
            response.setCookie(.init(name: cookieName, value: "", expires: Date()))
        }

        return response
    }
}
