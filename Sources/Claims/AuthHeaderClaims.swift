//
//  Copyright © 2020 Anbion. All rights reserved.
//

import Foundation
import JWTKit

struct AuthHeaderClaims: Claims {
    let iss: UserId
    let iat: IssuedAtClaim
    let exp: ExpirationClaim
    let nonce: Data
    
    init(iss: UserId, iat: Date, exp: Date, nonce: Data) {
        self.iss = iss
        self.iat = IssuedAtClaim(value: iat)
        self.exp = ExpirationClaim(value: exp)
        self.nonce = nonce
    }
}
