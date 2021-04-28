//
//  Copyright © 2020 Anbion. All rights reserved.
//

import Foundation
import JWTKit

public struct AuthHeaderClaims: JWTPayload {
    public var iss: UserId
    public var iat: IssuedAtClaim
    public var exp: ExpirationClaim
    public var nonce: Data
    
    public init(iss: UserId, iat: Date, exp: Date, nonce: Data) {
        self.iss = iss
        self.iat = IssuedAtClaim(value: iat)
        self.exp = ExpirationClaim(value: exp)
        self.nonce = nonce
    }
    
    public func verify() throws {
        try exp.verifyNotExpired(currentDate: Date().addingTimeInterval(-AuthManager.jwtValidationLeeway))
        try iat.verifyIssuedInPast(currentDate: Date().addingTimeInterval(AuthManager.jwtValidationLeeway))
    }
    
    public func verify(using signer: JWTSigner) throws {
        try verify()
    }
}
