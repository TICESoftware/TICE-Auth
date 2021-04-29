//
//  Copyright © 2021 Anbion. All rights reserved.
//

import Foundation
import JWTKit

protocol Claims: JWTPayload {
    var iat: IssuedAtClaim { get }
    var exp: ExpirationClaim { get }
}

extension Claims {
    public func verify(using signer: JWTSigner) throws {
        try exp.verifyNotExpired(currentDate: Date().addingTimeInterval(-AuthManager.jwtValidationLeeway))
        try iat.verifyIssuedInPast(currentDate: Date().addingTimeInterval(AuthManager.jwtValidationLeeway))
    }
}
